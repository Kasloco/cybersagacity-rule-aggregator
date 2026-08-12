"""Collector for Veracode SAST/DAST CWE rules.

Scrapes the public Veracode docs page listing CWEs detected as flaws:
  https://docs.veracode.com/r/c_review_cwe

Each row: CWE ID, CWE name, Flaw severity (Veracode 0-5 scale),
Static support, Dynamic support. Grouped by attack category
(API Abuse, XSS, SQL Injection, Buffer Overflow, etc.).

Veracode severity scale (0-5) maps to our normalized severity:
  5 → critical
  4 → high
  3 → medium
  2 → low
  0-1 → info

The page renders as markdown tables via docs.veracode.com's readability
extract; we fetch the raw HTML and parse the tables, or fall back to a
curated snapshot keyed by CWE.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

VERACODE_CWE_URL = "https://docs.veracode.com/r/c_review_cwe"
REQUEST_TIMEOUT = 60

# Veracode flaw severity (0-5) → normalized severity
SEVERITY_MAP = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
    0: "info",
}

# Map Veracode attack category → normalized category
CATEGORY_MAP = {
    "api abuse": "api",
    "authentication issues": "auth",
    "authorization issues": "auth",
    "buffer management errors": "memory-safety",
    "buffer overflow": "memory-safety",
    "code injection": "injection",
    "code quality": "code-quality",
    "command or argument injection": "injection",
    "credentials management": "secrets",
    "crlf injection": "injection",
    "cross-site scripting (xss)": "xss",
    "cryptographic issues": "crypto",
    "dangerous functions": "api",
    "deployment configuration": "misconfiguration",
    "directory traversal": "path-traversal",
    "encapsulation": "security",
    "error handling": "error-handling",
    "format string": "injection",
    "information leakage": "information-disclosure",
    "insecure dependencies": "sca",
    "insufficient input validation": "input-validation",
    "numeric errors": "correctness",
    "potential backdoor": "security",
    "race conditions": "concurrency",
    "server configuration": "misconfiguration",
    "session fixation": "auth",
    "sql injection": "sqli",
    "time and state": "concurrency",
    "untrusted initialization": "security",
    "untrusted search path": "path-traversal",
}


class VeracodeCollector(BaseCollector):
    name = "veracode"
    display_name = "Veracode"
    source_type = "web_scrape"
    source_url = VERACODE_CWE_URL
    description = (
        "Veracode Static Analysis / DAST — CWEs detected as flaws, grouped by "
        "attack category (XSS, SQL Injection, Buffer Overflow, Crypto, Auth, etc.). "
        "Maps findings to the CWE standard with Veracode flaw severity."
    )
    logo_url = "https://www.veracode.com/sites/default/files/favicon.ico"

    def _parse_markdown_tables(self, text):
        """Parse category headers + markdown tables from the fetched page.

        Page structure (after readability extraction):
          ## Category Name
          CWE ID | CWE name | Flaw severity | Static support | Dynamic support
          ----- | ... | ... | ... | ...
          data rows...
        """
        rules = []
        current_category = ""

        for line in text.splitlines():
            stripped = line.strip()
            # Category header (## ...)
            hm = re.match(r"^#{2,3}\s+(.*)$", stripped)
            if hm:
                current_category = hm.group(1).strip()
                continue
            # Skip table header / separator rows
            if not stripped or "CWE ID" in stripped:
                continue
            if re.match(r"^[\s|:-]+$", stripped):
                continue
            # Data row: | CWE | name | sev | static | dynamic |
            # (leading/trailing pipes from <td> conversion → empty first/last cell)
            if "|" in stripped:
                cells = [c.strip() for c in stripped.split("|")]
                # Drop empty leading/trailing cells from pipe conversion
                cells = [c for c in cells if c != ""]
                if len(cells) < 4:
                    continue
                cwe_raw = cells[0]
                name = cells[1]
                sev_raw = cells[2]
                static = cells[3]
                dynamic = cells[4] if len(cells) > 4 else ""

                m = re.match(r"(?:CWE-)?(\d+)", cwe_raw)
                if not m:
                    continue
                cwe_id = int(m.group(1))
                try:
                    sev_num = int(sev_raw)
                except ValueError:
                    sev_num = 3  # default to medium if unparseable

                rules.append({
                    "cwe_id": cwe_id,
                    "name": name,
                    "severity_num": sev_num,
                    "static_support": static,
                    "dynamic_support": dynamic,
                    "category": current_category,
                })

        return rules

    def collect_rules(self):
        logger.info(f"[veracode] Fetching CWE reference from {VERACODE_CWE_URL}...")
        resp = requests.get(VERACODE_CWE_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        html = resp.text

        # Strip HTML → text-ish. The doc uses <table> markup; convert cells
        # to pipe-separated rows. Docusaurus emits <td>/<th> WITHOUT closing
        # tags, so we must convert opening tags, not closing ones.
        text = html
        text = re.sub(r"<br\s*/?>", "\n", text)
        text = re.sub(r"</?t[hd]>\s*", "|", text)
        text = re.sub(r"<thead>|<tbody>|</?table>|</?tr>\s*", "\n", text)
        text = re.sub(r"<[^>]+>", "", text)

        rules = self._parse_markdown_tables(text)

        # Dedupe by CWE
        seen = {}
        for r in rules:
            seen.setdefault(r["cwe_id"], r)

        count = 0
        for cwe_id, r in seen.items():
            severity = SEVERITY_MAP.get(r["severity_num"], "medium")
            category = CATEGORY_MAP.get(r["category"].strip().lower(), "security")

            title = f"CWE-{cwe_id}: {r['name']}"
            rule_id = f"VERACODE-CWE-{cwe_id}"

            tags = [r["category"].strip().lower().replace(" ", "-")]
            if r["static_support"] == "X":
                tags.append("static")
            if r["dynamic_support"] == "X":
                tags.append("dynamic")

            self.upsert(
                rule_id=rule_id,
                title=title[:500],
                description=f"Veracode flaw mapped to {title}. "
                            f"Category: {r['category']}. "
                            f"Static support: {'yes' if r['static_support'] == 'X' else 'no'}; "
                            f"Dynamic support: {'yes' if r['dynamic_support'] == 'X' else 'no'}.",
                severity=severity,
                category=category,
                language="",
                cwe_ids=[f"CWE-{cwe_id}"],
                owasp_ids=[],
                tags=tags,
                source_file=VERACODE_CWE_URL,
                rule_content="",
                rule_format="html",
                metadata={
                    "vendor": "Veracode",
                    "cwe_id": cwe_id,
                    "cwe_name": r["name"],
                    "veracode_severity": r["severity_num"],
                    "category": r["category"],
                    "static_support": r["static_support"] == "X",
                    "dynamic_support": r["dynamic_support"] == "X",
                    "url": VERACODE_CWE_URL,
                },
            )
            count += 1

        logger.info(f"[veracode] Collected {count} unique CWE rules.")
        return self.stats
