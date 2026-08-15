"""Collector for StackHawk DAST scan rules.

StackHawk is a dynamic application security testing (DAST) tool. Their
scan rules and vulnerability detection definitions are documented at:
  https://docs.stackhawk.com/

This collector scrapes the StackHawk docs for scan rule definitions,
CWE mappings, and severity information.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

STACKHAWK_URL = "https://docs.stackhawk.com/hawkscan/"
REQUEST_TIMEOUT = 60

# Curated StackHawk scan rules based on HawkScan documentation
STACKHAWK_RULES = [
    {"id": "SH-AUTH-001", "name": "Broken Authentication", "severity": "critical", "cwe": "CWE-287", "category": "auth"},
    {"id": "SH-AUTH-002", "name": "Session Management Failure", "severity": "high", "cwe": "CWE-384", "category": "auth"},
    {"id": "SH-AUTH-003", "name": "Weak Password Policy", "severity": "medium", "cwe": "CWE-521", "category": "auth"},
    {"id": "SH-XSS-001", "name": "Reflected XSS", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "SH-XSS-002", "name": "Stored XSS", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "SH-XSS-003", "name": "DOM-based XSS", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "SH-SQLI-001", "name": "SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli"},
    {"id": "SH-SQLI-002", "name": "Blind SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli"},
    {"id": "SH-INJ-001", "name": "Command Injection", "severity": "critical", "cwe": "CWE-77", "category": "injection"},
    {"id": "SH-INJ-002", "name": "LDAP Injection", "severity": "high", "cwe": "CWE-90", "category": "injection"},
    {"id": "SH-INJ-003", "name": "Expression Language Injection", "severity": "high", "cwe": "CWE-917", "category": "injection"},
    {"id": "SH-PATH-001", "name": "Path Traversal", "severity": "high", "cwe": "CWE-22", "category": "path-traversal"},
    {"id": "SH-SSRF-001", "name": "Server-Side Request Forgery", "severity": "critical", "cwe": "CWE-918", "category": "ssrf"},
    {"id": "SH-XXE-001", "name": "XML External Entity", "severity": "high", "cwe": "CWE-611", "category": "xxe"},
    {"id": "SH-REDIRECT-001", "name": "Open Redirect", "severity": "medium", "cwe": "CWE-601", "category": "redirect"},
    {"id": "SH-CSRF-001", "name": "Cross-Site Request Forgery", "severity": "high", "cwe": "CWE-352", "category": "csrf"},
    {"id": "SH-CRYPTO-001", "name": "Weak Cryptographic Algorithm", "severity": "high", "cwe": "CWE-327", "category": "crypto"},
    {"id": "SH-CRYPTO-002", "name": "Insecure TLS Configuration", "severity": "high", "cwe": "CWE-326", "category": "crypto"},
    {"id": "SH-CONFIG-001", "name": "Security Misconfiguration", "severity": "high", "cwe": "CWE-16", "category": "misconfiguration"},
    {"id": "SH-CONFIG-002", "name": "Missing Security Headers", "severity": "medium", "cwe": "CWE-693", "category": "misconfiguration"},
    {"id": "SH-CONFIG-003", "name": "CORS Misconfiguration", "severity": "medium", "cwe": "CWE-942", "category": "misconfiguration"},
    {"id": "SH-INFO-001", "name": "Information Disclosure", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure"},
    {"id": "SH-INFO-002", "name": "Verbose Error Messages", "severity": "low", "cwe": "CWE-209", "category": "information-disclosure"},
    {"id": "SH-INFO-003", "name": "Directory Listing Enabled", "severity": "medium", "cwe": "CWE-548", "category": "information-disclosure"},
    {"id": "SH-DESERIAL-001", "name": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "category": "deserialization"},
    {"id": "SH-RATE-001", "name": "Missing Rate Limiting", "severity": "medium", "cwe": "CWE-770", "category": "abuse"},
    {"id": "SH-ACCESS-001", "name": "Broken Access Control", "severity": "critical", "cwe": "CWE-284", "category": "auth"},
    {"id": "SH-ACCESS-002", "name": "IDOR (Insecure Direct Object Reference)", "severity": "critical", "cwe": "CWE-639", "category": "auth"},
    {"id": "SH-ACCESS-003", "name": "Forced Browsing", "severity": "medium", "cwe": "CWE-425", "category": "auth"},
    {"id": "SH-COOKIE-001", "name": "Missing HttpOnly Cookie Flag", "severity": "medium", "cwe": "CWE-1004", "category": "misconfiguration"},
    {"id": "SH-COOKIE-002", "name": "Missing Secure Cookie Flag", "severity": "medium", "cwe": "CWE-614", "category": "misconfiguration"},
    {"id": "SH-COOKIE-003", "name": "Overly Broad Cookie Domain", "severity": "low", "cwe": "CWE-565", "category": "misconfiguration"},
]


class StackHawkCollector(BaseCollector):
    name = "stackhawk"
    display_name = "StackHawk"
    source_type = "web_scrape"
    source_url = STACKHAWK_URL
    description = (
        "StackHawk HawkScan — dynamic application security testing (DAST) "
        "tool. Scans running web applications for OWASP Top 10 vulnerabilities "
        "including XSS, SQL injection, SSRF, CSRF, authentication flaws, "
        "misconfigurations, and insecure deserialization."
    )
    logo_url = "https://docs.stackhawk.com/img/stackhawk-logo.svg"

    def collect_rules(self):
        logger.info(f"[stackhawk] Collecting StackHawk scan rules...")

        count = 0
        try:
            count = self._scrape_docs()
        except Exception as e:
            logger.warning(f"[stackhawk] Scrape failed: {e}, using curated list")

        if count < 10:
            for rule in STACKHAWK_RULES:
                self.upsert(
                    rule_id=rule["id"],
                    title=rule["name"],
                    description=(
                        f"StackHawk HawkScan detection: {rule['name']}. "
                        f"Category: {rule['category']}. "
                        f"Mapped to {rule['cwe']}."
                    ),
                    severity=rule["severity"],
                    category=rule["category"],
                    language="",
                    cwe_ids=[rule["cwe"]],
                    owasp_ids=[],
                    tags=["dast", "stackhawk", rule["category"]],
                    source_file=STACKHAWK_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "StackHawk",
                        "rule_id": rule["id"],
                        "cwe": rule["cwe"],
                    },
                )
                count += 1

        logger.info(f"[stackhawk] Collected {count} scan rules.")
        return self.stats

    def _scrape_docs(self):
        """Scrape StackHawk docs for scan rule listings."""
        resp = requests.get(STACKHAWK_URL, timeout=REQUEST_TIMEOUT, headers={
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

            rule_id = f"SH-DOC-{count+1}"

            self.upsert(
                rule_id=rule_id,
                title=heading[:500],
                description=body[:2000],
                severity=severity,
                category="dast",
                language="",
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=["dast", "stackhawk"],
                source_file=STACKHAWK_URL,
                rule_content="",
                rule_format="html",
                metadata={"vendor": "StackHawk", "source": "docs"},
            )
            count += 1

        return count