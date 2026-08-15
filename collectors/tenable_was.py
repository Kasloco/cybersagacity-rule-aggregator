"""Collector for Tenable Web App Scanning (WAS) rules.

Tenable WAS is a dynamic web application scanner. Plugin/checker
documentation is publicly available at:
  https://www.tenable.com/plugins/was

This collector scrapes the Tenable WAS plugin listings for vulnerability
detection rules with CVE and CWE mappings.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

TENABLE_WAS_URL = "https://www.tenable.com/plugins/was"
TENABLE_DOCS_URL = "https://docs.tenable.com/web-app-scanning/WAS.htm"
REQUEST_TIMEOUT = 60

# Curated Tenable WAS detection rules
TENABLE_WAS_RULES = [
    {"id": "TENABLE-WAS-001", "name": "Cross-Site Scripting (XSS)", "severity": "high", "cwe": "CWE-79", "category": "xss"},
    {"id": "TENABLE-WAS-002", "name": "SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli"},
    {"id": "TENABLE-WAS-003", "name": "Blind SQL Injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli"},
    {"id": "TENABLE-WAS-004", "name": "Command Injection", "severity": "critical", "cwe": "CWE-77", "category": "injection"},
    {"id": "TENABLE-WAS-005", "name": "Path Traversal", "severity": "high", "cwe": "CWE-22", "category": "path-traversal"},
    {"id": "TENABLE-WAS-006", "name": "Open Redirect", "severity": "medium", "cwe": "CWE-601", "category": "redirect"},
    {"id": "TENABLE-WAS-007", "name": "Server-Side Request Forgery", "severity": "critical", "cwe": "CWE-918", "category": "ssrf"},
    {"id": "TENABLE-WAS-008", "name": "XML External Entity (XXE)", "severity": "high", "cwe": "CWE-611", "category": "xxe"},
    {"id": "TENABLE-WAS-009", "name": "Insecure Deserialization", "severity": "critical", "cwe": "CWE-502", "category": "deserialization"},
    {"id": "TENABLE-WAS-010", "name": "Broken Authentication", "severity": "critical", "cwe": "CWE-287", "category": "auth"},
    {"id": "TENABLE-WAS-011", "name": "Session Fixation", "severity": "high", "cwe": "CWE-384", "category": "auth"},
    {"id": "TENABLE-WAS-012", "name": "Broken Access Control", "severity": "critical", "cwe": "CWE-284", "category": "auth"},
    {"id": "TENABLE-WAS-013", "name": "Insecure Direct Object Reference", "severity": "critical", "cwe": "CWE-639", "category": "auth"},
    {"id": "TENABLE-WAS-014", "name": "Cross-Site Request Forgery", "severity": "high", "cwe": "CWE-352", "category": "csrf"},
    {"id": "TENABLE-WAS-015", "name": "Security Misconfiguration", "severity": "high", "cwe": "CWE-16", "category": "misconfiguration"},
    {"id": "TENABLE-WAS-016", "name": "Missing Security Headers", "severity": "medium", "cwe": "CWE-693", "category": "misconfiguration"},
    {"id": "TENABLE-WAS-017", "name": "CORS Misconfiguration", "severity": "medium", "cwe": "CWE-942", "category": "misconfiguration"},
    {"id": "TENABLE-WAS-018", "name": "SSL/TLS Weak Cipher Suite", "severity": "high", "cwe": "CWE-326", "category": "crypto"},
    {"id": "TENABLE-WAS-019", "name": "Expired or Invalid SSL Certificate", "severity": "high", "cwe": "CWE-295", "category": "crypto"},
    {"id": "TENABLE-WAS-020", "name": "Information Disclosure", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure"},
    {"id": "TENABLE-WAS-021", "name": "Directory Listing Enabled", "severity": "medium", "cwe": "CWE-548", "category": "information-disclosure"},
    {"id": "TENABLE-WAS-022", "name": "Default Credentials Detected", "severity": "critical", "cwe": "CWE-798", "category": "secrets"},
    {"id": "TENABLE-WAS-023", "name": "Weak Password Policy", "severity": "medium", "cwe": "CWE-521", "category": "auth"},
    {"id": "TENABLE-WAS-024", "name": "Missing Rate Limiting", "severity": "medium", "cwe": "CWE-770", "category": "abuse"},
    {"id": "TENABLE-WAS-025", "name": "Cookie Security Flags Missing", "severity": "medium", "cwe": "CWE-1004", "category": "misconfiguration"},
    {"id": "TENABLE-WAS-026", "name": "HTTP Methods Enabled", "severity": "low", "cwe": "CWE-650", "category": "misconfiguration"},
    {"id": "TENABLE-WAS-027", "name": "Clickjacking Protection Missing", "severity": "medium", "cwe": "CWE-1021", "category": "misconfiguration"},
    {"id": "TENABLE-WAS-028", "name": "Host Header Injection", "severity": "medium", "cwe": "CWE-644", "category": "injection"},
    {"id": "TENABLE-WAS-029", "name": "Email Header Injection", "severity": "medium", "cwe": "CWE-93", "category": "injection"},
    {"id": "TENABLE-WAS-030", "name": "LDAP Injection", "severity": "high", "cwe": "CWE-90", "category": "injection"},
    {"id": "TENABLE-WAS-031", "name": "NoSQL Injection", "severity": "critical", "cwe": "CWE-943", "category": "injection"},
    {"id": "TENABLE-WAS-032", "name": "Template Injection (SSTI)", "severity": "critical", "cwe": "CWE-94", "category": "injection"},
    {"id": "TENABLE-WAS-033", "name": "GraphQL Introspection Enabled", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure"},
    {"id": "TENABLE-WAS-034", "name": "API BOLA/IDOR", "severity": "critical", "cwe": "CWE-639", "category": "auth"},
    {"id": "TENABLE-WAS-035", "name": "API Broken Authentication", "severity": "critical", "cwe": "CWE-287", "category": "auth"},
]


class TenableWASCollector(BaseCollector):
    name = "tenable_was"
    display_name = "Tenable Web App Scanning"
    source_type = "web_scrape"
    source_url = TENABLE_WAS_URL
    description = (
        "Tenable Web App Scanning (WAS) — dynamic web application scanner. "
        "Detects OWASP Top 10 vulnerabilities, API security issues, "
        "misconfigurations, and cryptographic weaknesses in running web "
        "applications."
    )
    logo_url = "https://www.tenable.com/sites/all/themes/tenable/favicon.ico"

    def collect_rules(self):
        logger.info(f"[tenable_was] Collecting Tenable WAS scan rules...")

        count = 0
        try:
            count = self._scrape_plugins()
        except Exception as e:
            logger.warning(f"[tenable_was] Scrape failed: {e}, using curated list")

        if count < 10:
            for rule in TENABLE_WAS_RULES:
                self.upsert(
                    rule_id=rule["id"],
                    title=rule["name"],
                    description=(
                        f"Tenable WAS detection: {rule['name']}. "
                        f"Category: {rule['category']}. "
                        f"Mapped to {rule['cwe']}."
                    ),
                    severity=rule["severity"],
                    category=rule["category"],
                    language="",
                    cwe_ids=[rule["cwe"]],
                    owasp_ids=[],
                    tags=["dast", "tenable", "was", rule["category"]],
                    source_file=TENABLE_WAS_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Tenable",
                        "rule_id": rule["id"],
                        "cwe": rule["cwe"],
                    },
                )
                count += 1

        logger.info(f"[tenable_was] Collected {count} scan rules.")
        return self.stats

    def _scrape_plugins(self):
        """Scrape Tenable WAS plugin listings."""
        resp = requests.get(TENABLE_WAS_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        count = 0
        seen = set()

        # Look for plugin entries
        plugins = re.findall(r'<a[^>]*href="([^"]*plugin[^"]*)"[^>]*>(.*?)</a>', html, re.DOTALL | re.IGNORECASE)
        for url, name_html in plugins:
            name = re.sub(r'<[^>]+>', '', name_html).strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())

            cwe_match = re.search(r'CWE[-\s]?(\d+)', name, re.IGNORECASE)
            cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

            self.upsert(
                rule_id=f"TENABLE-WAS-PLUG-{count+1}",
                title=name[:500],
                description=f"Tenable WAS plugin: {name}",
                severity="medium",
                category="dast",
                language="",
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=["dast", "tenable"],
                source_file=url if url.startswith("http") else f"https://www.tenable.com{url}",
                rule_content="",
                rule_format="html",
                metadata={"vendor": "Tenable", "source": "plugins"},
            )
            count += 1

        return count