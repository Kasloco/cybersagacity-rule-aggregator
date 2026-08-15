"""Collector for Veracode Dynamic Analysis (DAST) findings.

Veracode DAST tests running web applications for vulnerabilities. The
finding categories and CWE mappings are publicly documented at:
  https://docs.veracode.com/r/c_review_cwe  (shared with SAST)
  https://docs.veracode.com/r/c_was_findings

This collector scrapes the Veracode DAST documentation pages to extract
the vulnerability categories, CWE mappings, and severity information.
"""

import logging
import re
import html as html_mod

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

VERACODE_DAST_URL = "https://docs.veracode.com/r/c_was_findings"
VERACODE_CWE_URL = "https://docs.veracode.com/r/c_review_cwe"
REQUEST_TIMEOUT = 60

# DAST-specific finding categories from Veracode docs
DAST_CATEGORIES = {
    "API Abuse": "api",
    "Authentication Issues": "auth",
    "Authorization Issues": "auth",
    "Code Injection": "injection",
    "Cross-Site Scripting (XSS)": "xss",
    "Cryptographic Issues": "crypto",
    "Information Leakage": "information-disclosure",
    "Input Validation": "input-validation",
    "Path Traversal": "path-traversal",
    "Session Management": "auth",
    "SQL Injection": "sqli",
    "XML External Entity": "xxe",
    "Open Redirect": "redirect",
    "Security Misconfiguration": "misconfiguration",
    "Insecure Deserialization": "deserialization",
    "Server-Side Request Forgery": "ssrf",
}


class VeracodeDASTCollector(BaseCollector):
    name = "veracode_dast"
    display_name = "Veracode Dynamic Analysis (DAST)"
    source_type = "web_scrape"
    source_url = VERACODE_DAST_URL
    description = (
        "Veracode Dynamic Analysis (DAST) — tests running web applications "
        "for vulnerabilities including XSS, SQL injection, path traversal, "
        "authentication flaws, and cryptographic issues. Maps findings to "
        "CWE standard with Veracode severity scoring."
    )
    logo_url = "https://www.veracode.com/sites/default/files/favicon.ico"

    def collect_rules(self):
        logger.info(f"[veracode_dast] Fetching DAST findings from {VERACODE_DAST_URL}...")

        # Try the DAST findings page first
        count = 0
        try:
            count = self._scrape_page(VERACODE_DAST_URL, "DAST")
        except Exception as e:
            logger.warning(f"[veracode_dast] DAST page failed: {e}")

        # Also scrape the shared CWE reference page for DAST-specific entries
        if count == 0:
            logger.info(f"[veracode_dast] Falling back to CWE reference page...")
            try:
                count = self._scrape_page(VERACODE_CWE_URL, "DAST")
            except Exception as e:
                logger.warning(f"[veracode_dast] CWE page failed: {e}")

        # If both fail, use the curated DAST categories
        if count == 0:
            logger.info(f"[veracode_dast] Using curated DAST categories as fallback")
            count = self._use_curated()

        logger.info(f"[veracode_dast] Collected {count} DAST rules.")
        return self.stats

    def _scrape_page(self, url, finding_type):
        """Scrape a Veracode docs page for vulnerability listings."""
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        # Convert HTML tables to pipe-separated rows
        text = html
        text = re.sub(r"<br\s*/?>", "\n", text)
        text = re.sub(r"</?t[hd]>\s*", "|", text)
        text = re.sub(r"<thead>|<tbody>|</?table>|</?tr>\s*", "\n", text)
        text = re.sub(r"<[^>]+>", "", text)

        count = 0
        current_category = ""
        seen_cwes = set()

        for line in text.splitlines():
            stripped = line.strip()
            hm = re.match(r"^#{2,3}\s+(.*)$", stripped)
            if hm:
                current_category = hm.group(1).strip()
                continue
            if not stripped or "CWE ID" in stripped:
                continue
            if re.match(r"^[\s|:-]+$", stripped):
                continue
            if "|" in stripped:
                cells = [c.strip() for c in stripped.split("|")]
                cells = [c for c in cells if c != ""]
                if len(cells) < 4:
                    continue

                cwe_raw = cells[0]
                name = cells[1]
                sev_raw = cells[2]
                static = cells[3]
                dynamic = cells[4] if len(cells) > 4 else ""

                # Only include DAST-supported findings
                if dynamic != "X" and finding_type == "DAST":
                    continue

                m = re.match(r"(?:CWE-)?(\d+)", cwe_raw)
                if not m:
                    continue
                cwe_id = int(m.group(1))
                if cwe_id in seen_cwes:
                    continue
                seen_cwes.add(cwe_id)

                try:
                    sev_num = int(sev_raw)
                except ValueError:
                    sev_num = 3

                severity_map = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info", 0: "info"}
                severity = severity_map.get(sev_num, "medium")

                category = DAST_CATEGORIES.get(current_category, "security")
                title = f"CWE-{cwe_id}: {name}"
                rule_id = f"VERACODE-DAST-CWE-{cwe_id}"

                self.upsert(
                    rule_id=rule_id,
                    title=title[:500],
                    description=(
                        f"Veracode DAST finding mapped to {title}. "
                        f"Category: {current_category}. "
                        f"Dynamic support: yes."
                    ),
                    severity=severity,
                    category=category,
                    language="",
                    cwe_ids=[f"CWE-{cwe_id}"],
                    owasp_ids=[],
                    tags=["dast", "dynamic", current_category.lower().replace(" ", "-")],
                    source_file=url,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Veracode",
                        "scan_type": "DAST",
                        "cwe_id": cwe_id,
                        "cwe_name": name,
                        "veracode_severity": sev_num,
                        "category": current_category,
                    },
                )
                count += 1

        return count

    def _use_curated(self):
        """Fallback: use the curated DAST categories list."""
        count = 0
        for i, (cat_name, cat_key) in enumerate(DAST_CATEGORIES.items()):
            rule_id = f"VERACODE-DAST-CAT-{i+1}"
            self.upsert(
                rule_id=rule_id,
                title=f"Veracode DAST: {cat_name}",
                description=(
                    f"Veracode Dynamic Analysis category: {cat_name}. "
                    f"Detects {cat_name.lower()} vulnerabilities in running "
                    f"web applications via dynamic testing."
                ),
                severity="medium",
                category=cat_key,
                language="",
                cwe_ids=[],
                owasp_ids=[],
                tags=["dast", "dynamic", cat_key],
                source_file=VERACODE_DAST_URL,
                rule_content="",
                rule_format="html",
                metadata={
                    "vendor": "Veracode",
                    "scan_type": "DAST",
                    "category": cat_name,
                },
            )
            count += 1
        return count