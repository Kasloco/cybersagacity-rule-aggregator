"""Collector for Semgrep rules — fetches directly from the Semgrep Registry API.

Uses two API endpoints:
  1. /api/registry/rules  — metadata for ALL ~5,800 rules (public + Pro listings)
  2. /c/r/all (JSON)      — full rule definitions for ~3,000 public rules

No authentication needed for public rules. Pro rules are listed in metadata
but their content requires a Semgrep Team/Enterprise API token.
"""

import json
import logging
import os
import time

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# Canonical language normalization
LANGUAGE_NORMALIZE = {
    "py": "python",
    "js": "javascript",
    "ts": "typescript",
    "kt": "kotlin",
    "C#": "csharp",
    "cpp": "c++",
    "c": "c",
}

# Security-relevant categories extracted from rule ID paths
SECURITY_CATEGORIES = {
    "security", "audit", "xss", "sqli", "xxe", "ssrf", "csrf", "injection",
    "crypto", "deserialization", "hardcoded", "path-traversal", "pathtraversal",
    "command-injection", "open-redirect", "secrets", "tls", "cors", "cookies",
    "session", "nosqli", "eval", "redos", "insecure-transport", "traversal",
    "insecure-communication", "insecure-crypto", "dos", "rmi", "ldap",
    "xpath", "xpath-injection", "xml", "webview", "best-practice",
    "best_practices", "correctness", "performance", "maintainability",
    "compatibility", "portability",
}

REGISTRY_METADATA_URL = "https://semgrep.dev/api/registry/rules"
REGISTRY_CONTENT_URL = "https://semgrep.dev/c/r/all"
REQUEST_TIMEOUT = 120  # seconds — these are large responses


class SemgrepCollector(BaseCollector):
    name = "semgrep"
    display_name = "Semgrep"
    source_type = "api"
    source_url = "https://semgrep.dev/r"
    description = (
        "Official Semgrep Registry — 5,800+ static analysis rules for 35+ "
        "languages covering OWASP Top 10, injection, crypto, secrets, "
        "hardcoded credentials, XSS, XXE, SSRF, and more."
    )
    logo_url = "https://avatars.githubusercontent.com/u/78890965"

    def sync(self, force=False):
        """Override sync — fetch from Semgrep API, no git clone needed."""
        self.register_vendor()
        from database import start_sync, complete_sync, update_vendor_stats
        self.sync_id = start_sync(self.vendor["id"])
        logger.info(f"[{self.name}] Starting Semgrep Registry API sync...")

        try:
            self.collect_rules()
            update_vendor_stats(self.vendor["id"])
            complete_sync(
                self.sync_id, "success",
                self.stats["added"], self.stats["updated"], self.stats["removed"],
            )
            logger.info(
                f"[{self.name}] Sync complete: "
                f"+{self.stats['added']} ~{self.stats['updated']} "
                f"-{self.stats['removed']} ={self.stats['unchanged']}"
            )
        except Exception as e:
            logger.error(f"[{self.name}] Sync failed: {e}", exc_info=True)
            complete_sync(self.sync_id, "failed", error_message=str(e))
            raise

        return self.stats

    def _fetch_json(self, url, accept="application/json"):
        """Fetch JSON from a URL with retries."""
        headers = {
            "Accept": accept,
            "User-Agent": "CyberSagacity-RuleAggregator/1.0",
        }
        for attempt in range(3):
            try:
                logger.info(f"[semgrep] Fetching {url} (attempt {attempt + 1})...")
                resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException as e:
                logger.warning(f"[semgrep] Request failed: {e}")
                if attempt < 2:
                    time.sleep(5 * (attempt + 1))
                else:
                    raise

    def _extract_categories(self, rule_path):
        """Extract security categories from a dotted rule path."""
        parts = rule_path.split(".")
        categories = [p for p in parts if p in SECURITY_CATEGORIES]
        primary = categories[0] if categories else ""
        if not primary and len(parts) >= 2:
            primary = parts[1]
        return primary, categories

    def _normalize_languages(self, languages):
        """Normalize language names to canonical form."""
        normalized = []
        for lang in languages:
            lang = lang.strip()
            if lang:
                normalized.append(LANGUAGE_NORMALIZE.get(lang, lang))
        return normalized

    def collect_rules(self):
        # --- Phase 1: Fetch full rule content for public rules ---
        logger.info("[semgrep] Phase 1: Fetching full public rule content from /c/r/all...")
        content_data = self._fetch_json(REGISTRY_CONTENT_URL)
        full_rules = content_data.get("rules", [])
        missed_count = content_data.get("missed", 0)
        logger.info(
            f"[semgrep] Got {len(full_rules)} public rules "
            f"({missed_count} Pro rules require auth)"
        )

        # Index full rules by their ID for quick lookup
        full_rule_index = {}
        for rule in full_rules:
            if isinstance(rule, dict) and "id" in rule:
                full_rule_index[rule["id"]] = rule

        # --- Phase 2: Fetch metadata for ALL rules (public + Pro) ---
        logger.info("[semgrep] Phase 2: Fetching registry metadata for all rules...")
        metadata_list = self._fetch_json(REGISTRY_METADATA_URL)
        logger.info(f"[semgrep] Got metadata for {len(metadata_list)} rules")

        count = 0
        for entry in metadata_list:
            rule_path = entry.get("path", "")
            if not rule_path:
                continue

            visibility = entry.get("visibility", "public")
            meta = entry.get("meta", {})
            rule_meta = meta.get("rule", {})

            # Try to get full rule content from Phase 1
            full_rule = full_rule_index.get(rule_path)

            # Determine severity
            if full_rule:
                severity_raw = full_rule.get("severity", "WARNING")
            else:
                severity_raw = "INFO"  # Pro rules without content default to info
            severity = SEVERITY_MAP.get(severity_raw, "medium")

            # Determine languages
            if full_rule:
                languages = full_rule.get("languages", [])
            else:
                # Try to infer from path (first segment is often the language)
                first_seg = rule_path.split(".")[0] if rule_path else ""
                languages = [first_seg] if first_seg else []

            normalized_langs = self._normalize_languages(languages)
            primary_language = normalized_langs[0] if normalized_langs else ""

            # Extract categories
            category, categories = self._extract_categories(rule_path)

            # Build title
            if full_rule:
                message = full_rule.get("message", "")
                title = message[:200] if message else rule_path.split(".")[-1]
            else:
                title = rule_path.split(".")[-1]
            title = title.replace("-", " ").replace("_", " ")
            if len(title) > 500:
                title = title[:500]

            # Build description
            if full_rule and full_rule.get("message"):
                description = full_rule["message"]
            else:
                description = f"Semgrep rule: {rule_path}"

            # Tags
            tags = list(set(categories + normalized_langs))
            tags.append(severity_raw.lower())
            if visibility == "team_tier":
                tags.append("pro")

            # CWE and OWASP from full rule metadata
            cwe_ids = []
            owasp_ids = []
            rule_metadata = {}
            if full_rule:
                rule_metadata = full_rule.get("metadata", {})
                cwe = rule_metadata.get("cwe", [])
                if isinstance(cwe, str):
                    cwe_ids = [cwe]
                elif isinstance(cwe, list):
                    cwe_ids = cwe

                owasp = rule_metadata.get("owasp", [])
                if isinstance(owasp, str):
                    owasp_ids = [owasp]
                elif isinstance(owasp, list):
                    owasp_ids = owasp

            # Rule URL
            url = rule_meta.get("url", f"https://semgrep.dev/r/{rule_path}")

            # Source file / GitHub link
            source_uri = entry.get("source_uri", "")

            self.upsert(
                rule_id=rule_path,
                title=title[:500],
                description=description[:2000] if description else "",
                severity=severity,
                category=category,
                language=primary_language,
                cwe_ids=cwe_ids,
                owasp_ids=owasp_ids,
                tags=tags,
                source_file=source_uri or url,
                rule_content=json.dumps(full_rule, indent=2)[:50000] if full_rule else "",
                rule_format="yaml",
                metadata={
                    "url": url,
                    "source_uri": source_uri,
                    "visibility": visibility,
                    "all_languages": normalized_langs,
                    "all_categories": categories,
                    "semgrep_metadata": rule_metadata if full_rule else {},
                    "last_change_at": entry.get("last_change_at", ""),
                    "author": meta.get("author", ""),
                },
            )
            count += 1

        logger.info(f"[semgrep] Processed {count} total rules from Semgrep Registry API")
