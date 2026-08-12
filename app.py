"""
CyberSagacity Rule Aggregator - Web Dashboard
Flask application serving the rule intelligence dashboard.
"""

import json
from flask import Flask, render_template, request, jsonify, abort
from flask_cors import CORS

from database import (
    init_db, get_dashboard_stats, search_rules, get_db, MAX_PER_PAGE,
)

app = Flask(__name__)
CORS(app)


@app.template_filter('commafy')
def commafy_filter(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return str(value)


@app.before_request
def ensure_db():
    init_db()


def _parse_pagination():
    """Parse and validate page/per_page query params, returning 400 on bad input."""
    page = request.args.get("page", "1")
    per_page = request.args.get("per_page", "50")
    try:
        page = int(page)
        per_page = int(per_page)
    except ValueError:
        abort(400, description="page and per_page must be integers")
    if page < 1:
        abort(400, description="page must be >= 1")
    if per_page < 1:
        abort(400, description="per_page must be >= 1")
    if per_page > MAX_PER_PAGE:
        abort(400, description=f"per_page must be <= {MAX_PER_PAGE}")
    return page, per_page


@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/api/stats")
def api_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/rules")
def api_rules():
    page, per_page = _parse_pagination()
    results = search_rules(
        query=request.args.get("q", ""),
        vendor=request.args.get("vendor"),
        severity=request.args.get("severity"),
        language=request.args.get("language"),
        category=request.args.get("category"),
        page=page,
        per_page=per_page,
    )
    return jsonify(results)


@app.route("/api/rules/<vendor>/<rule_id>")
def api_rule_detail(vendor, rule_id):
    with get_db() as conn:
        row = conn.execute("""
            SELECT r.*, v.name as vendor_name, v.display_name as vendor_display_name
            FROM rules r JOIN vendors v ON r.vendor_id=v.id
            WHERE v.name=? AND r.rule_id=?
        """, (vendor, rule_id)).fetchone()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(dict(row))


@app.route("/api/vendors")
def api_vendors():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT v.*,
                (SELECT COUNT(*) FROM rules r WHERE r.vendor_id=v.id AND r.is_active=1) as active_rules
            FROM vendors v ORDER BY v.display_name
        """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/sync-history")
def api_sync_history():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT sh.*, v.display_name as vendor_name
            FROM sync_history sh
            JOIN vendors v ON sh.vendor_id=v.id
            ORDER BY sh.started_at DESC LIMIT 100
        """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/languages")
def api_languages():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT language, COUNT(*) as count FROM rules
            WHERE is_active=1 AND language != ''
            GROUP BY language ORDER BY count DESC
        """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/categories")
def api_categories():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT category, COUNT(*) as count FROM rules
            WHERE is_active=1 AND category != ''
            GROUP BY category ORDER BY count DESC
        """).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=8080)
