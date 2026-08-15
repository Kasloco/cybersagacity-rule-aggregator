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
        try:
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
        except Exception as e:
            logger.warning(f"[veracode] Scrape failed: {e}, using curated list")
            rules = []

        # If scraping found too few rules, use the curated fallback
        if len(rules) < 10:
            logger.info(f"[veracode] Scrape found {len(rules)} rules, using curated fallback")
            rules = self._get_curated_rules()

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

    def _get_curated_rules(self):
        """Return a curated list of Veracode CWE rules as fallback."""
        # Veracode's published CWE reference — these are the CWEs that
        # Veracode SAST detects, grouped by attack category.
        curated = [
            # API Abuse
            ("API Abuse", 22, "Improper Privilege Management", 4, "X", ""),
            ("API Abuse", 200, "Information Exposure", 3, "X", ""),
            ("API Abuse", 352, "CSRF", 4, "X", ""),
            # Authentication Issues
            ("Authentication Issues", 287, "Improper Authentication", 5, "X", ""),
            ("Authentication Issues", 384, "Session Fixation", 4, "X", ""),
            ("Authentication Issues", 613, "Insufficient Session Expiration", 3, "X", ""),
            ("Authentication Issues", 798, "Use of Hardcoded Credentials", 5, "X", ""),
            # Authorization Issues
            ("Authorization Issues", 284, "Improper Access Control", 5, "X", ""),
            ("Authorization Issues", 639, "IDOR", 5, "X", ""),
            ("Authorization Issues", 862, "Missing Authorization", 4, "X", ""),
            # Buffer Management
            ("Buffer Management Errors", 120, "Buffer Overflow", 5, "X", ""),
            ("Buffer Management Errors", 121, "Stack-based Buffer Overflow", 5, "X", ""),
            ("Buffer Management Errors", 122, "Heap-based Buffer Overflow", 5, "X", ""),
            ("Buffer Management Errors", 787, "Out-of-bounds Write", 5, "X", ""),
            ("Buffer Management Errors", 125, "Out-of-bounds Read", 4, "X", ""),
            # Code Injection
            ("Code Injection", 77, "Command Injection", 5, "X", ""),
            ("Code Injection", 94, "Code Injection", 5, "X", ""),
            ("Code Injection", 95, "Code Evaluation", 5, "X", ""),
            # Code Quality
            ("Code Quality", 561, "Dead Code", 2, "X", ""),
            ("Code Quality", 398, "Resource Leak", 3, "X", ""),
            # Credentials Management
            ("Credentials Management", 256, "Plaintext Storage of Password", 4, "X", ""),
            ("Credentials Management", 259, "Hardcoded Password", 4, "X", ""),
            ("Credentials Management", 798, "Use of Hardcoded Credentials", 5, "X", ""),
            # CRLF Injection
            ("CRLF Injection", 93, "CRLF Injection", 3, "X", ""),
            # Cross-site Scripting
            ("Cross-site Scripting (XSS)", 79, "XSS", 4, "X", ""),
            # Cryptographic Issues
            ("Cryptographic Issues", 327, "Use of Broken Crypto", 4, "X", ""),
            ("Cryptographic Issues", 328, "Weak Hash", 3, "X", ""),
            ("Cryptographic Issues", 330, "Insufficient Randomness", 3, "X", ""),
            ("Cryptographic Issues", 295, "Improper Certificate Validation", 4, "X", ""),
            # Dangerous Functions
            ("Dangerous Functions", 676, "Potentially Dangerous Function", 3, "X", ""),
            # Directory Traversal
            ("Directory Traversal", 22, "Path Traversal", 4, "X", ""),
            # Error Handling
            ("Error Handling", 209, "Information Exposure via Error", 2, "X", ""),
            ("Error Handling", 390, "Missing Error Handling", 2, "X", ""),
            # Format String
            ("Format String", 134, "Format String Vulnerability", 4, "X", ""),
            # Information Leakage
            ("Information Leakage", 200, "Information Exposure", 3, "X", ""),
            ("Information Leakage", 209, "Error Message Info Exposure", 2, "X", ""),
            # Insecure Dependencies
            ("Insecure Dependencies", 1104, "Outdated Dependency", 3, "X", ""),
            # Input Validation
            ("Insufficient Input Validation", 20, "Improper Input Validation", 3, "X", ""),
            # Numeric Errors
            ("Numeric Errors", 190, "Integer Overflow", 4, "X", ""),
            ("Numeric Errors", 191, "Integer Underflow", 3, "X", ""),
            # Race Conditions
            ("Race Conditions", 362, "Race Condition", 4, "X", ""),
            ("Race Conditions", 367, "TOCTOU", 4, "X", ""),
            # SQL Injection
            ("SQL Injection", 89, "SQL Injection", 5, "X", ""),
            ("SQL Injection", 943, "NoSQL Injection", 5, "X", ""),
            # Untrusted Initialization
            ("Untrusted Initialization", 672, "Untrusted Init", 3, "X", ""),
            # Untrusted Search Path
            ("Untrusted Search Path", 426, "Untrusted Search Path", 3, "X", ""),
            # Server Configuration
            ("Server Configuration", 16, "Security Misconfiguration", 3, "X", ""),
            ("Server Configuration", 693, "Missing Protection Mechanism", 3, "X", ""),
            # Session Fixation
            ("Session Fixation", 384, "Session Fixation", 4, "X", ""),
            # Time and State
            ("Time and State", 833, "Deadlock", 2, "X", ""),
            # Encapsulation
            ("Encapsulation", 1061, "Insufficient Encapsulation", 2, "X", ""),
            # Potential Backdoor
            ("Potential Backdoor", 507, "Backdoor", 5, "X", ""),
        ]

        rules = []
        for category, cwe_id, name, sev_num, static, dynamic in curated:
            rules.append({
                "cwe_id": cwe_id,
                "name": name,
                "severity_num": sev_num,
                "static_support": static,
                "dynamic_support": dynamic,
                "category": category,
            })
        return rules
