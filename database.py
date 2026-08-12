"""
CyberSagacity Rule Aggregator - Database Layer
SQLite database for storing security rules from all major scanning tools.
"""

import sqlite3
import os
import json
import threading
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "RULE_AGGREGATOR_DB",
    os.path.join(os.path.dirname(__file__), "rules.db"),
)

# Holds the active transaction connection for the current thread, so nested
# get_db()/upsert_* calls reuse one connection and commit once per sync.
_tx = threading.local()


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    # Inside an outer transaction(): yield its connection without committing.
    conn = getattr(_tx, "conn", None)
    if conn is not None:
        yield conn
        return

    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def transaction():
    """Run a block in a single transaction on one connection.

    All get_db()/upsert_* calls made inside commit once when the block exits
    (or roll back atomically if it raises). Safe across threads (gunicorn
    workers, scheduler).
    """
    conn = get_connection()
    _tx.conn = conn
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _tx.conn = None
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS vendors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                source_type TEXT NOT NULL,  -- 'github', 'api', 'web_scrape'
                source_url TEXT NOT NULL,
                description TEXT,
                logo_url TEXT,
                last_synced_at TIMESTAMP,
                last_commit_sha TEXT,
                rule_count INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,           -- vendor-specific rule ID
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,                   -- critical, high, medium, low, info
                category TEXT,                   -- e.g., 'injection', 'xss', 'crypto'
                language TEXT,                   -- programming language targeted
                cwe_ids TEXT,                    -- JSON array of CWE IDs
                owasp_ids TEXT,                  -- JSON array of OWASP categories
                tags TEXT,                       -- JSON array of tags
                source_file TEXT,                -- path within repo or URL
                rule_content TEXT,               -- the actual rule definition
                rule_format TEXT,                -- yaml, json, xml, rego, python, java
                metadata TEXT,                   -- JSON blob for vendor-specific metadata
                first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id),
                UNIQUE(vendor_id, rule_id)
            );

            CREATE TABLE IF NOT EXISTS sync_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id INTEGER NOT NULL,
                started_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                status TEXT NOT NULL,            -- 'running', 'success', 'failed'
                rules_added INTEGER DEFAULT 0,
                rules_updated INTEGER DEFAULT 0,
                rules_removed INTEGER DEFAULT 0,
                error_message TEXT,
                FOREIGN KEY (vendor_id) REFERENCES vendors(id)
            );

            CREATE TABLE IF NOT EXISTS rule_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                change_type TEXT NOT NULL,       -- 'added', 'updated', 'removed'
                old_content TEXT,
                new_content TEXT,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sync_id INTEGER,
                FOREIGN KEY (rule_id) REFERENCES rules(id),
                FOREIGN KEY (sync_id) REFERENCES sync_history(id)
            );

            CREATE INDEX IF NOT EXISTS idx_rules_vendor ON rules(vendor_id);
            CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
            CREATE INDEX IF NOT EXISTS idx_rules_language ON rules(language);
            CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
            CREATE INDEX IF NOT EXISTS idx_rules_active ON rules(is_active);
            CREATE INDEX IF NOT EXISTS idx_sync_vendor ON sync_history(vendor_id);
            CREATE INDEX IF NOT EXISTS idx_changes_rule ON rule_changes(rule_id);

            CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING fts5(
                rule_id, title, description, tags, category,
                content='rules', content_rowid='id'
            );
        """)

        # Insert/update triggers for FTS
        conn.executescript("""
            CREATE TRIGGER IF NOT EXISTS rules_ai AFTER INSERT ON rules BEGIN
                INSERT INTO rules_fts(rowid, rule_id, title, description, tags, category)
                VALUES (new.id, new.rule_id, new.title, new.description, new.tags, new.category);
            END;

            CREATE TRIGGER IF NOT EXISTS rules_ad AFTER DELETE ON rules BEGIN
                INSERT INTO rules_fts(rules_fts, rowid, rule_id, title, description, tags, category)
                VALUES ('delete', old.id, old.rule_id, old.title, old.description, old.tags, old.category);
            END;

            CREATE TRIGGER IF NOT EXISTS rules_au AFTER UPDATE ON rules BEGIN
                INSERT INTO rules_fts(rules_fts, rowid, rule_id, title, description, tags, category)
                VALUES ('delete', old.id, old.rule_id, old.title, old.description, old.tags, old.category);
                INSERT INTO rules_fts(rowid, rule_id, title, description, tags, category)
                VALUES (new.id, new.rule_id, new.title, new.description, new.tags, new.category);
            END;
        """)


def upsert_vendor(name, display_name, source_type, source_url, description="", logo_url=""):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO vendors (name, display_name, source_type, source_url, description, logo_url)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                display_name=excluded.display_name,
                source_type=excluded.source_type,
                source_url=excluded.source_url,
                description=excluded.description,
                logo_url=excluded.logo_url,
                updated_at=CURRENT_TIMESTAMP
        """, (name, display_name, source_type, source_url, description, logo_url))
        return conn.execute("SELECT * FROM vendors WHERE name=?", (name,)).fetchone()


# Columns considered when deciding whether a rule "changed". rule_content alone
# missed metadata-only edits (severity/title changes with identical content).
_MUTABLE_FIELDS = (
    "title", "description", "severity", "category", "language",
    "cwe_ids", "owasp_ids", "tags", "source_file", "rule_content",
    "rule_format", "metadata",
)


def _json_default(obj):
    """Fallback for json.dumps — handles datetime and other non-serializable
    objects that YAML parsers (PyYAML) produce from .snyk/.yaml rule files."""
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    return str(obj)


def _json_dumps(obj, **kw):
    return json.dumps(obj, default=_json_default, **kw)


def _record_change(conn, rule_id, change_type, old_content, new_content, sync_id):
    conn.execute(
        "INSERT INTO rule_changes (rule_id, change_type, old_content, new_content, sync_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (rule_id, change_type, old_content, new_content, sync_id),
    )


def upsert_rule(vendor_id, rule_id, title, description="", severity="medium",
                category="", language="", cwe_ids=None, owasp_ids=None,
                tags=None, source_file="", rule_content="", rule_format="",
                metadata=None, sync_id=None):
    # sort_keys for stable comparisons across runs (dict ordering differs
    # between metadata sources).
    cwe_json = _json_dumps(cwe_ids or [], sort_keys=True)
    owasp_json = _json_dumps(owasp_ids or [], sort_keys=True)
    tags_json = _json_dumps(tags or [], sort_keys=True)
    meta_json = _json_dumps(metadata or {}, sort_keys=True)

    new_values = (title, description, severity, category, language,
                  cwe_json, owasp_json, tags_json, source_file,
                  rule_content, rule_format, meta_json)

    with get_db() as conn:
        existing = conn.execute(
            f"SELECT id, is_active, {', '.join(_MUTABLE_FIELDS)} FROM rules "
            "WHERE vendor_id=? AND rule_id=?",
            (vendor_id, rule_id)
        ).fetchone()

        if existing:
            if tuple(existing[f] for f in _MUTABLE_FIELDS) != new_values:
                conn.execute("""
                    UPDATE rules SET
                        title=?, description=?, severity=?, category=?, language=?,
                        cwe_ids=?, owasp_ids=?, tags=?, source_file=?,
                        rule_content=?, rule_format=?, metadata=?,
                        is_active=1,
                        last_updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                """, new_values + (existing["id"],))
                _record_change(
                    conn, existing["id"], "updated",
                    existing["rule_content"], rule_content, sync_id,
                )
                return ("updated", existing["id"])
            if not existing["is_active"]:
                # Re-appeared with identical content after a removal: revive.
                conn.execute(
                    "UPDATE rules SET is_active=1, last_updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (existing["id"],),
                )
                _record_change(
                    conn, existing["id"], "added",
                    existing["rule_content"], rule_content, sync_id,
                )
                return ("added", existing["id"])
            return ("unchanged", existing["id"])
        else:
            cursor = conn.execute("""
                INSERT INTO rules (vendor_id, rule_id, title, description, severity,
                    category, language, cwe_ids, owasp_ids, tags, source_file,
                    rule_content, rule_format, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (vendor_id, rule_id, title, description, severity, category,
                  language, cwe_json, owasp_json, tags_json, source_file,
                  rule_content, rule_format, meta_json))
            _record_change(conn, cursor.lastrowid, "added", None, rule_content, sync_id)
            return ("added", cursor.lastrowid)


def deactivate_missing_rules(vendor_id, seen_rule_ids, sync_id=None):
    """Deactivate active rules for a vendor that were not seen in the last sync.

    Records a 'removed' entry in rule_changes for each. Returns the count
    removed. Rules stay in the table (is_active=0) to preserve history and the
    rule_changes FK; all queries already filter on is_active=1.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, rule_id, rule_content FROM rules "
            "WHERE vendor_id=? AND is_active=1",
            (vendor_id,),
        ).fetchall()

        removed = 0
        for row in rows:
            if row["rule_id"] in seen_rule_ids:
                continue
            conn.execute(
                "UPDATE rules SET is_active=0, last_updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (row["id"],),
            )
            _record_change(conn, row["id"], "removed", row["rule_content"], None, sync_id)
            removed += 1
        return removed


def start_sync(vendor_id):
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO sync_history (vendor_id, started_at, status)
            VALUES (?, ?, 'running')
        """, (vendor_id, datetime.utcnow().isoformat()))
        return cursor.lastrowid


def complete_sync(sync_id, status, rules_added=0, rules_updated=0,
                  rules_removed=0, error_message=None):
    with get_db() as conn:
        conn.execute("""
            UPDATE sync_history SET
                completed_at=?, status=?, rules_added=?, rules_updated=?,
                rules_removed=?, error_message=?
            WHERE id=?
        """, (datetime.utcnow().isoformat(), status, rules_added,
              rules_updated, rules_removed, error_message, sync_id))


def update_vendor_stats(vendor_id):
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) as c FROM rules WHERE vendor_id=? AND is_active=1",
            (vendor_id,)
        ).fetchone()["c"]
        conn.execute("""
            UPDATE vendors SET rule_count=?, last_synced_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (count, vendor_id))


# Summary columns for list/search responses. rule_content and metadata are
# large and unnecessary for listings — the detail endpoint returns them.
_RULE_SUMMARY_COLUMNS = (
    "r.id", "r.vendor_id", "r.rule_id", "r.title", "r.description",
    "r.severity", "r.category", "r.language", "r.cwe_ids", "r.owasp_ids",
    "r.tags", "r.source_file", "r.rule_format", "r.first_seen_at",
    "r.last_updated_at", "r.is_active",
    "v.name as vendor_name", "v.display_name as vendor_display_name",
)

# Upper bound for per_page regardless of caller (CLI included).
MAX_PER_PAGE = 200


def search_rules(query="", vendor=None, severity=None, language=None,
                 category=None, page=1, per_page=50):
    # Defensive clamps so no caller can produce a negative offset or a
    # division-by-zero in the page math below.
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), MAX_PER_PAGE))

    def build(use_fts):
        conditions = ["r.is_active=1"]
        params = []
        if query:
            if use_fts:
                conditions.append(
                    "r.id IN (SELECT rowid FROM rules_fts WHERE rules_fts MATCH ?)"
                )
                params.append(query)
            else:
                # Substring fallback for queries FTS5 rejects as malformed.
                escaped = query.replace("%", "\\%").replace("_", "\\_")
                like = f"%{escaped}%"
                conditions.append(
                    "(r.title LIKE ? ESCAPE '\\' OR r.description LIKE ? ESCAPE '\\' "
                    "OR r.rule_id LIKE ? ESCAPE '\\')"
                )
                params.extend([like, like, like])
        if vendor:
            conditions.append("v.name=?")
            params.append(vendor)
        if severity:
            conditions.append("r.severity=?")
            params.append(severity)
        if language:
            conditions.append("r.language=?")
            params.append(language)
        if category:
            conditions.append("r.category=?")
            params.append(category)
        return " AND ".join(conditions), params

    def run(use_fts):
        where, params = build(use_fts)
        offset = (page - 1) * per_page
        count = conn.execute(
            f"SELECT COUNT(*) as c FROM rules r JOIN vendors v ON r.vendor_id=v.id "
            f"WHERE {where}",
            params,
        ).fetchone()["c"]
        rows = conn.execute(f"""
            SELECT {', '.join(_RULE_SUMMARY_COLUMNS)}
            FROM rules r
            JOIN vendors v ON r.vendor_id=v.id
            WHERE {where}
            ORDER BY r.last_updated_at DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset]).fetchall()
        return count, rows

    with get_db() as conn:
        try:
            count, rows = run(use_fts=True)
        except sqlite3.OperationalError:
            # Malformed FTS query (e.g. a lone quote) — retry as a substring
            # search so the API returns results instead of a 500.
            count, rows = run(use_fts=False)

        return {
            "rules": [dict(r) for r in rows],
            "total": count,
            "page": page,
            "per_page": per_page,
            "pages": (count + per_page - 1) // per_page,
        }


def get_dashboard_stats():
    with get_db() as conn:
        vendors = [dict(r) for r in conn.execute("""
            SELECT v.*,
                (SELECT COUNT(*) FROM rules r WHERE r.vendor_id=v.id AND r.is_active=1) as active_rules,
                (SELECT MAX(completed_at) FROM sync_history sh WHERE sh.vendor_id=v.id AND sh.status='success') as last_successful_sync
            FROM vendors v ORDER BY v.display_name
        """).fetchall()]

        total_rules = conn.execute("SELECT COUNT(*) as c FROM rules WHERE is_active=1").fetchone()["c"]

        severity_dist = [dict(r) for r in conn.execute("""
            SELECT severity, COUNT(*) as count FROM rules
            WHERE is_active=1 GROUP BY severity ORDER BY count DESC
        """).fetchall()]

        language_dist = [dict(r) for r in conn.execute("""
            SELECT language, COUNT(*) as count FROM rules
            WHERE is_active=1 AND language != '' GROUP BY language
            ORDER BY count DESC LIMIT 20
        """).fetchall()]

        category_dist = [dict(r) for r in conn.execute("""
            SELECT category, COUNT(*) as count FROM rules
            WHERE is_active=1 AND category != '' GROUP BY category
            ORDER BY count DESC LIMIT 20
        """).fetchall()]

        recent_syncs = [dict(r) for r in conn.execute("""
            SELECT sh.*, v.display_name as vendor_name
            FROM sync_history sh
            JOIN vendors v ON sh.vendor_id=v.id
            ORDER BY sh.started_at DESC LIMIT 20
        """).fetchall()]

        recent_changes = [dict(r) for r in conn.execute("""
            SELECT rc.*, r.rule_id, r.title, v.display_name as vendor_name
            FROM rule_changes rc
            JOIN rules r ON rc.rule_id=r.id
            JOIN vendors v ON r.vendor_id=v.id
            ORDER BY rc.changed_at DESC LIMIT 50
        """).fetchall()]

        return {
            "vendors": vendors,
            "total_rules": total_rules,
            "total_vendors": len(vendors),
            "severity_distribution": severity_dist,
            "language_distribution": language_dist,
            "category_distribution": category_dist,
            "recent_syncs": recent_syncs,
            "recent_changes": recent_changes,
        }


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
