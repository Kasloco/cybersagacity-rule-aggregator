"""Collector for Checkmarx DAST scan rules.

Checkmarx DAST (formerly from Checkmarx) tests running web applications.
Documentation is publicly available at:
  https://docs.checkmarx.com/en/checkmarx-dast/

This collector scrapes the Checkmarx DAST docs for vulnerability detection
rules and CWE mappings.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

CHECKMARX_DAST_URL = "https://docs.checkmarx.com/en/checkmarx-dast/"
REQUEST_TIMEOUT = 60

# Curated Checkmarx DAST vulnerability categories
CHECKMARX_DAST_RULES = [
    {"id": "CX-DAST-001", "name": "Cross-Site Scripting (Reflected)", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "CX-DAST-002", "name": "Cross-Site Scripting (Stored)", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "CX-DAST-003", "name": "Cross-Site Scripting (DOM)", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "CX-DAST-004", "name": "SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli"},
    {"id": "CX-DAST-005", "name": "Blind SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli"},
    {"id": "CX-DAST-006", "name": "Command Injection", "severity": "critical", "cwe": "CWE-77", "category": "injection"},
    {"id": "CX-DAST-007", "name": "Path Traversal", "severity": "high", "cwe": "CWE-22", "category": "path-traversal"},
    {"id": "CX-DAST-008", "name": "Server-Side Request Forgery", "severity": "critical", "cwe": "CWE-918", "category": "ssrf"},
    {"id": "CX-DAST-009", "name": "XML External Entity (XXE)", "severity": "high", "cwe": "CWE-611", "category": "xxe"},
    {"id": "CX-DAST-010", "name": "Open Redirect", "severity": "medium", "cwe": "CWE-601", "category": "redirect"},
    {"id": "CX-DAST-011", "name": "Broken Authentication", "severity": "critical", "cwe": "CWE-287", "category": "auth"},
    {"id": "CX-DAST-012", "name": "Broken Access Control", "severity": "critical", "cwe": "CWE-284", "category": "auth"},
    {"id": "CX-DAST-013", "name": "Insecure Direct Object Reference", "severity": "critical", "cwe": "CWE-639", "category": "auth"},
    {"id": "CX-DAST-014", "name": "Cross-Site Request Forgery", "severity": "high", "cwe": "CWE-352", "category": "csrf"},
    {"id": "CX-DAST-015", "name": "Security Misconfiguration", "severity": "high", "cwe": "CWE-16", "category": "misconfiguration"},
    {"id": "CX-DAST-016", "name": "Missing Security Headers", "severity": "medium", "cwe": "CWE-693", "category": "misconfiguration"},
    {"id": "CX-DAST-017", "name": "CORS Misconfiguration", "severity": "medium", "cwe": "CWE-942", "category": "misconfiguration"},
    {"id": "CX-DAST-018", "name": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "category": "deserialization"},
    {"id": "CX-DAST-019", "name": "Information Disclosure", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure"},
    {"id": "CX-DAST-020", "name": "Weak Cryptographic Algorithm", "severity": "high", "cwe": "CWE-327", "category": "crypto"},
    {"id": "CX-DAST-021", "name": "Expired SSL Certificate", "severity": "high", "cwe": "CWE-295", "category": "crypto"},
    {"id": "CX-DAST-022", "name": "Default Credentials", "severity": "critical", "cwe": "CWE-798", "category": "secrets"},
    {"id": "CX-DAST-023", "name": "Missing Rate Limiting", "severity": "medium", "cwe": "CWE-770", "category": "abuse"},
    {"id": "CX-DAST-024", "name": "Cookie Security Flags Missing", "severity": "medium", "cwe": "CWE-1004", "category": "misconfiguration"},
    {"id": "CX-DAST-025", "name": "Clickjacking Vulnerability", "severity": "medium", "cwe": "CWE-1021", "category": "misconfiguration"},
    {"id": "CX-DAST-026", "name": "Host Header Injection", "severity": "medium", "cwe": "CWE-644", "category": "injection"},
    {"id": "CX-DAST-027", "name": "LDAP Injection", "severity": "high", "cwe": "CWE-90", "category": "injection"},
    {"id": "CX-DAST-028", "name": "NoSQL Injection", "severity": "critical", "cwe": "CWE-943", "category": "injection"},
    {"id": "CX-DAST-029", "name": "Template Injection (SSTI)", "severity": "critical", "cwe": "CWE-94", "category": "injection"},
    {"id": "CX-DAST-030", "name": "GraphQL Injection", "severity": "high", "cwe": "CWE-89", "category": "injection"},
]


class CheckmarxDASTCollector(BaseCollector):
    name = "checkmarx_dast"
    display_name = "Checkmarx DAST"
    source_type = "web_scrape"
    source_url = CHECKMARX_DAST_URL
    description = (
        "Checkmarx DAST — dynamic application security testing tool. "
        "Scans running web applications for OWASP Top 10 vulnerabilities, "
        "API security issues, injection flaws, authentication weaknesses, "
        "and misconfigurations."
    )
    logo_url = "https://docs.checkmarx.com/img/checkmarx-logo.png"

    def collect_rules(self):
        logger.info(f"[checkmarx_dast] Collecting Checkmarx DAST rules...")

        count = 0
        try:
            count = self._scrape_docs()
        except Exception as e:
            logger.warning(f"[checkmarx_dast] Scrape failed: {e}, using curated list")

        if count == 0:
            for rule in CHECKMARX_DAST_RULES:
                self.upsert(
                    rule_id=rule["id"],
                    title=rule["name"],
                    description=(
                        f"Checkmarx DAST detection: {rule['name']}. "
                        f"Category: {rule['category']}. "
                        f"Mapped to {rule['cwe']}."
                    ),
                    severity=rule["severity"],
                    category=rule["category"],
                    language="",
                    cwe_ids=[rule["cwe"]],
                    owasp_ids=[],
                    tags=["dast", "checkmarx", rule["category"]],
                    source_file=CHECKMARX_DAST_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Checkmarx",
                        "rule_id": rule["id"],
                        "cwe": rule["cwe"],
                    },
                )
                count += 1

        logger.info(f"[checkmarx_dast] Collected {count} DAST rules.")
        return self.stats

    def _scrape_docs(self):
        """Scrape Checkmarx DAST docs for vulnerability listings."""
        resp = requests.get(CHECKMARX_DAST_URL, timeout=REQUEST_TIMEOUT, headers={
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

            rule_id = f"CX-DAST-DOC-{count+1}"

            self.upsert(
                rule_id=rule_id,
                title=heading[:500],
                description=body[:2000],
                severity=severity,
                category="dast",
                language="",
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=["dast", "checkmarx"],
                source_file=CHECKMARX_DAST_URL,
                rule_content="",
                rule_format="html",
                metadata={"vendor": "Checkmarx", "source": "docs"},
            )
            count += 1

        return count