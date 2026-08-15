"""Collector for Wallarm API Security rules.

Wallarm is an API security platform that detects API-specific threats.
Their public docs list API security rules and attack classifications:
  https://docs.wallarm.com/api-security/

This collector scrapes the Wallarm docs for API security rule definitions
including attack types, CWE mappings, and severity.
"""

import logging
import re
import html as html_mod

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

WALLARM_DOCS_URL = "https://docs.wallarm.com/api-security/"
WALLARM_ATTACKS_URL = "https://docs.wallarm.com/api-security/attacks/"
REQUEST_TIMEOUT = 60

# Wallarm API attack types with CWE mappings
WALLARM_ATTACKS = [
    {"id": "API-1", "name": "API Broken Object Level Authorization (BOLA)", "cwe": "CWE-639", "severity": "critical", "category": "auth"},
    {"id": "API-2", "name": "API Broken User Authentication", "cwe": "CWE-287", "severity": "critical", "category": "auth"},
    {"id": "API-3", "name": "API Excessive Data Exposure", "cwe": "CWE-200", "severity": "high", "category": "information-disclosure"},
    {"id": "API-4", "name": "API Lack of Rate Limiting", "cwe": "CWE-770", "severity": "medium", "category": "abuse"},
    {"id": "API-5", "name": "API Broken Function Level Authorization (BFLA)", "cwe": "CWE-285", "severity": "critical", "category": "auth"},
    {"id": "API-6", "name": "API Mass Assignment", "cwe": "CWE-915", "severity": "high", "category": "input-validation"},
    {"id": "API-7", "name": "API Security Misconfiguration", "cwe": "CWE-16", "severity": "high", "category": "misconfiguration"},
    {"id": "API-8", "name": "API Injection Flaws", "cwe": "CWE-74", "severity": "critical", "category": "injection"},
    {"id": "API-9", "name": "API Improper Asset Management", "cwe": "CWE-1059", "severity": "medium", "category": "misconfiguration"},
    {"id": "API-10", "name": "API Insufficient Logging and Monitoring", "cwe": "CWE-778", "severity": "low", "category": "logging"},
    # Wallarm-specific detections
    {"id": "WALLARM-1", "name": "API Schema Validation Failure", "cwe": "CWE-20", "severity": "high", "category": "input-validation"},
    {"id": "WALLARM-2", "name": "API SSRF", "cwe": "CWE-918", "severity": "critical", "category": "ssrf"},
    {"id": "WALLARM-3", "name": "API Path Traversal", "cwe": "CWE-22", "severity": "high", "category": "path-traversal"},
    {"id": "WALLARM-4", "name": "API XSS", "cwe": "CWE-79", "severity": "high", "category": "xss"},
    {"id": "WALLARM-5", "name": "API SQL Injection", "cwe": "CWE-89", "severity": "critical", "category": "sqli"},
    {"id": "WALLARM-6", "name": "API NoSQL Injection", "cwe": "CWE-943", "severity": "critical", "category": "injection"},
    {"id": "WALLARM-7", "name": "API Command Injection", "cwe": "CWE-77", "severity": "critical", "category": "injection"},
    {"id": "WALLARM-8", "name": "API Open Redirect", "cwe": "CWE-601", "severity": "medium", "category": "redirect"},
    {"id": "WALLARM-9", "name": "API GraphQL Injection", "cwe": "CWE-89", "severity": "high", "category": "injection"},
    {"id": "WALLARM-10", "name": "API Broken Authentication Token", "cwe": "CWE-287", "severity": "high", "category": "auth"},
    {"id": "WALLARM-11", "name": "API JWT Tampering", "cwe": "CWE-347", "severity": "high", "category": "auth"},
    {"id": "WALLARM-12", "name": "API Overexposed Data Structure", "cwe": "CWE-200", "severity": "medium", "category": "information-disclosure"},
    {"id": "WALLARM-13", "name": "API BOLA via IDOR", "cwe": "CWE-639", "severity": "critical", "category": "auth"},
    {"id": "WALLARM-14", "name": "API Forceful Browsing", "cwe": "CWE-425", "severity": "medium", "category": "auth"},
    {"id": "WALLARM-15", "name": "API Replay Attack", "cwe": "CWE-294", "severity": "high", "category": "auth"},
]


class WallarmAPICollector(BaseCollector):
    name = "wallarm_api"
    display_name = "Wallarm API Security"
    source_type = "web_scrape"
    source_url = WALLARM_DOCS_URL
    description = (
        "Wallarm API Security platform — detects API-specific threats "
        "including BOLA, BFLA, injection, SSRF, GraphQL attacks, JWT "
        "tampering, and OWASP API Top 10 vulnerabilities."
    )
    logo_url = "https://docs.wallarm.com/images/wallarm-logo.svg"

    def collect_rules(self):
        logger.info(f"[wallarm_api] Collecting API security rules...")

        # Try scraping the docs page first
        count = 0
        try:
            count = self._scrape_docs()
        except Exception as e:
            logger.warning(f"[wallarm_api] Scrape failed: {e}, using curated list")

        # Fallback to curated list
        if count < 10:
            for attack in WALLARM_ATTACKS:
                self.upsert(
                    rule_id=attack["id"],
                    title=attack["name"],
                    description=(
                        f"Wallarm API Security detection: {attack['name']}. "
                        f"Category: {attack['category']}. "
                        f"Mapped to {attack['cwe']}."
                    ),
                    severity=attack["severity"],
                    category=attack["category"],
                    language="",
                    cwe_ids=[attack["cwe"]],
                    owasp_ids=[],
                    tags=["api-security", "wallarm", attack["category"]],
                    source_file=WALLARM_DOCS_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Wallarm",
                        "attack_id": attack["id"],
                        "cwe": attack["cwe"],
                    },
                )
                count += 1

        logger.info(f"[wallarm_api] Collected {count} API security rules.")
        return self.stats

    def _scrape_docs(self):
        """Scrape Wallarm docs for attack listings."""
        resp = requests.get(WALLARM_ATTACKS_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        # Look for attack type listings in the docs
        # Wallarm docs typically list attacks in heading + description format
        count = 0
        seen = set()

        # Find attack headings and descriptions
        sections = re.findall(r'<h[23][^>]*>(.*?)</h[23]>(.*?)(?=<h[23]|$)', html, re.DOTALL)
        for heading_html, body_html in sections:
            heading = re.sub(r'<[^>]+>', '', heading_html).strip()
            body = re.sub(r'<[^>]+>', ' ', body_html).strip()[:500]

            if not heading or heading.lower() in seen:
                continue
            seen.add(heading.lower())

            # Try to find a CWE reference
            cwe_match = re.search(r'CWE[-\s]?(\d+)', body, re.IGNORECASE)
            cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

            # Try to find severity
            sev_match = re.search(r'(critical|high|medium|low|info)', body, re.IGNORECASE)
            severity = sev_match.group(1).lower() if sev_match else "medium"

            rule_id = f"WALLARM-DOC-{count+1}"

            self.upsert(
                rule_id=rule_id,
                title=heading[:500],
                description=body[:2000],
                severity=severity,
                category="api-security",
                language="",
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=["api-security", "wallarm"],
                source_file=WALLARM_ATTACKS_URL,
                rule_content="",
                rule_format="html",
                metadata={"vendor": "Wallarm", "source": "docs"},
            )
            count += 1

        return count