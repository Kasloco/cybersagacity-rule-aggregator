"""Collector for Checkmarx One (SAST) rules.

Checkmarx One is the cloud-native SAST platform by Checkmarx. It shares
many query/vulnerability categories with Checkmarx CxSAST v9 but is a
separate product. Documentation is at:
  https://docs.checkmarx.com/en/checkmarx-one/

This collector scrapes the Checkmarx One docs for vulnerability query
definitions and CWE mappings.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

CHECKMARX_ONE_URL = "https://docs.checkmarx.com/en/checkmarx-one/"
REQUEST_TIMEOUT = 60

# Checkmarx One vulnerability categories (shared with CxSAST but as separate product)
CHECKMARX_ONE_RULES = [
    {"id": "CXONE-001", "name": "Stored XSS", "severity": "high", "cwe": "CWE-79", "category": "xss", "lang": "javascript"},
    {"id": "CXONE-002", "name": "Reflected XSS", "severity": "high", "cwe": "CWE-79", "category": "xss", "lang": "javascript"},
    {"id": "CXONE-003", "name": "DOM XSS", "severity": "high", "cwe": "CWE-79", "category": "xss", "lang": "javascript"},
    {"id": "CXONE-004", "name": "SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli", "lang": "java"},
    {"id": "CXONE-005", "name": "Blind SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli", "lang": "java"},
    {"id": "CXONE-006", "name": "Command Injection", "severity": "critical", "cwe": "CWE-77", "category": "injection", "lang": "python"},
    {"id": "CXONE-007", "name": "Code Injection", "severity": "critical", "cwe": "CWE-94", "category": "injection", "lang": "php"},
    {"id": "CXONE-008", "name": "LDAP Injection", "severity": "high", "cwe": "CWE-90", "category": "injection", "lang": "java"},
    {"id": "CXONE-009", "name": "Path Traversal", "severity": "high", "cwe": "CWE-22", "category": "path-traversal", "lang": "python"},
    {"id": "CXONE-010", "name": "SSRF", "severity": "critical", "cwe": "CWE-918", "category": "ssrf", "lang": "python"},
    {"id": "CXONE-011", "name": "XXE", "severity": "high", "cwe": "CWE-611", "category": "xxe", "lang": "java"},
    {"id": "CXONE-012", "name": "Open Redirect", "severity": "medium", "cwe": "CWE-601", "category": "redirect", "lang": "javascript"},
    {"id": "CXONE-013", "name": "Broken Authentication", "severity": "critical", "cwe": "CWE-287", "category": "auth", "lang": ""},
    {"id": "CXONE-014", "name": "Broken Access Control", "severity": "critical", "cwe": "CWE-284", "category": "auth", "lang": ""},
    {"id": "CXONE-015", "name": "IDOR", "severity": "critical", "cwe": "CWE-639", "category": "auth", "lang": ""},
    {"id": "CXONE-016", "name": "CSRF", "severity": "high", "cwe": "CWE-352", "category": "csrf", "lang": "javascript"},
    {"id": "CXONE-017", "name": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "category": "deserialization", "lang": "java"},
    {"id": "CXONE-018", "name": "Hardcoded Password", "severity": "high", "cwe": "CWE-798", "category": "secrets", "lang": ""},
    {"id": "CXONE-019", "name": "Hardcoded API Key", "severity": "high", "cwe": "CWE-798", "category": "secrets", "lang": ""},
    {"id": "CXONE-020", "name": "Insecure Crypto", "severity": "high", "cwe": "CWE-327", "category": "crypto", "lang": ""},
    {"id": "CXONE-021", "name": "Weak Hash Algorithm", "severity": "medium", "cwe": "CWE-328", "category": "crypto", "lang": ""},
    {"id": "CXONE-022", "name": "Insecure Random", "severity": "medium", "cwe": "CWE-330", "category": "crypto", "lang": ""},
    {"id": "CXONE-023", "name": "Information Disclosure", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure", "lang": ""},
    {"id": "CXONE-024", "name": "Missing Input Validation", "severity": "medium", "cwe": "CWE-20", "category": "input-validation", "lang": ""},
    {"id": "CXONE-025", "name": "Stack Trace Exposure", "severity": "low", "cwe": "CWE-209", "category": "information-disclosure", "lang": ""},
    {"id": "CXONE-026", "name": "Log Injection", "severity": "medium", "cwe": "CWE-117", "category": "injection", "lang": ""},
    {"id": "CXONE-027", "name": "Mass Assignment", "severity": "high", "cwe": "CWE-915", "category": "input-validation", "lang": ""},
    {"id": "CXONE-028", "name": "Prototype Pollution", "severity": "high", "cwe": "CWE-1321", "category": "injection", "lang": "javascript"},
    {"id": "CXONE-029", "name": "Regex DoS (ReDoS)", "severity": "medium", "cwe": "CWE-1333", "category": "dos", "lang": "javascript"},
    {"id": "CXONE-030", "name": "Missing Rate Limiting", "severity": "medium", "cwe": "CWE-770", "category": "abuse", "lang": ""},
]


class CheckmarxOneCollector(BaseCollector):
    name = "checkmarx_one_sast"
    display_name = "Checkmarx One (SAST)"
    source_type = "web_scrape"
    source_url = CHECKMARX_ONE_URL
    description = (
        "Checkmarx One (SAST) — cloud-native static application security "
        "testing platform. Detects injection flaws, XSS, authentication "
        "issues, cryptographic weaknesses, and code quality issues across "
        "multiple programming languages with CWE mappings."
    )
    logo_url = "https://docs.checkmarx.com/img/checkmarx-logo.png"

    def collect_rules(self):
        logger.info(f"[checkmarx_one_sast] Collecting Checkmarx One rules...")

        count = 0
        try:
            count = self._scrape_docs()
        except Exception as e:
            logger.warning(f"[checkmarx_one_sast] Scrape failed: {e}, using curated list")

        if count < 10:
            for rule in CHECKMARX_ONE_RULES:
                self.upsert(
                    rule_id=rule["id"],
                    title=rule["name"],
                    description=(
                        f"Checkmarx One SAST query: {rule['name']}. "
                        f"Category: {rule['category']}. "
                        f"Mapped to {rule['cwe']}."
                    ),
                    severity=rule["severity"],
                    category=rule["category"],
                    language=rule["lang"],
                    cwe_ids=[rule["cwe"]],
                    owasp_ids=[],
                    tags=["sast", "checkmarx-one", rule["category"]],
                    source_file=CHECKMARX_ONE_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Checkmarx",
                        "product": "One",
                        "rule_id": rule["id"],
                        "cwe": rule["cwe"],
                    },
                )
                count += 1

        logger.info(f"[checkmarx_one_sast] Collected {count} SAST rules.")
        return self.stats

    def _scrape_docs(self):
        """Scrape Checkmarx One docs for query/vulnerability listings."""
        resp = requests.get(CHECKMARX_ONE_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        count = 0
        seen = set()

        sections = re.findall(r'<h[23][^>]*>(.*?)</h[23]>(.*?)(?=<h[23]|$)', html, re.DOTALL)
        for heading_html, body_html in sections:
            heading = re.sub(r'<[^>]+>', '', heading_html).strip()
            body = re.sub(r'<[^>]+>', ' ', body_html).strip()[:500]

            if not heading or heading.lower() in seen:
                continue
            seen.add(heading.lower())

            cwe_match = re.search(r'CWE[-\s]?(\d+)', body, re.IGNORECASE)
            cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

            sev_match = re.search(r'(critical|high|medium|low)', body, re.IGNORECASE)
            severity = sev_match.group(1).lower() if sev_match else "medium"

            rule_id = f"CXONE-DOC-{count+1}"

            self.upsert(
                rule_id=rule_id,
                title=heading[:500],
                description=body[:2000],
                severity=severity,
                category="sast",
                language="",
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=["sast", "checkmarx-one"],
                source_file=CHECKMARX_ONE_URL,
                rule_content="",
                rule_format="html",
                metadata={"vendor": "Checkmarx", "product": "One", "source": "docs"},
            )
            count += 1

        return count