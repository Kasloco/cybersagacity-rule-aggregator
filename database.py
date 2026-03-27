"""
CyberSagacity Rule Aggregator - Database Layer
SQLite database for storing security rules from all major scanning tools.
"""

import sqlite3
import os
import json
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "RULE_AGGREGATOR_DB",
    os.path.join(os.path.dirname(__file__), "rules.db"),
)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
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


def upsert_rule(vendor_id, rule_id, title, description="", severity="medium",
                category="", language="", cwe_ids=None, owasp_ids=None,
                tags=None, source_file="", rule_content="", rule_format="",
                metadata=None):
    cwe_json = json.dumps(cwe_ids or [])
    owasp_json = json.dumps(owasp_ids or [])
    tags_json = json.dumps(tags or [])
    meta_json = json.dumps(metadata or {})

    with get_db() as conn:
        existing = conn.execute(
            "SELECT id, rule_content FROM rules WHERE vendor_id=? AND rule_id=?",
            (vendor_id, rule_id)
        ).fetchone()

        if existing:
            if existing["rule_content"] != rule_content:
                conn.execute("""
                    UPDATE rules SET
                        title=?, description=?, severity=?, category=?, language=?,
                        cwe_ids=?, owasp_ids=?, tags=?, source_file=?,
                        rule_content=?, rule_format=?, metadata=?,
                        last_updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                """, (title, description, severity, category, language,
                      cwe_json, owasp_json, tags_json, source_file,
                      rule_content, rule_format, meta_json, existing["id"]))
                return ("updated", existing["id"])
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
            return ("added", cursor.lastrowid)


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


def search_rules(query="", vendor=None, severity=None, language=None,
                 category=None, page=1, per_page=50):
    with get_db() as conn:
        conditions = ["r.is_active=1"]
        params = []

        if query:
            conditions.append("r.id IN (SELECT rowid FROM rules_fts WHERE rules_fts MATCH ?)")
            params.append(query)
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

        where = " AND ".join(conditions)
        offset = (page - 1) * per_page

        count = conn.execute(
            f"SELECT COUNT(*) as c FROM rules r JOIN vendors v ON r.vendor_id=v.id WHERE {where}",
            params
        ).fetchone()["c"]

        rows = conn.execute(f"""
            SELECT r.*, v.name as vendor_name, v.display_name as vendor_display_name
            FROM rules r
            JOIN vendors v ON r.vendor_id=v.id
            WHERE {where}
            ORDER BY r.last_updated_at DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset]).fetchall()

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
