"""Collector for JFrog Xray security advisories.

JFrog Xray is a security analysis tool for artifacts/packages. JFrog
maintains a public security advisories database at:
  https://jfrog.com/security/

This collector scrapes the JFrog security advisories for vulnerability
listings with CVE mappings, severity, and affected package information.
"""

import logging
import re
import json
import time

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

JFROG_SECURITY_URL = "https://jfrog.com/security/"
JFROG_API_URL = "https://api.nexmode.net/v1/vulnerabilities"  # fallback
REQUEST_TIMEOUT = 60

# Curated JFrog Xray vulnerability categories
JFROG_CHECKS = [
    {"id": "JFROG-XRAY-001", "name": "Dependency confusion attack", "severity": "high", "cwe": "CWE-494", "category": "sca"},
    {"id": "JFROG-XRAY-002", "name": "Known vulnerability in dependency", "severity": "high", "cwe": "CWE-1035", "category": "sca"},
    {"id": "JFROG-XRAY-003", "name": "Malicious package detected", "severity": "critical", "cwe": "CWE-506", "category": "sca"},
    {"id": "JFROG-XRAY-004", "name": "Outdated package with known CVE", "severity": "high", "cwe": "CWE-1104", "category": "sca"},
    {"id": "JFROG-XRAY-005", "name": "Transitive dependency vulnerability", "severity": "medium", "cwe": "CWE-1035", "category": "sca"},
    {"id": "JFROG-XRAY-006", "name": "License compliance violation", "severity": "medium", "cwe": "CWE-1023", "category": "compliance"},
    {"id": "JFROG-XRAY-007", "name": "Container image vulnerability", "severity": "high", "cwe": "CWE-1035", "category": "container-security"},
    {"id": "JFROG-XRAY-008", "name": "Infrastructure as Code misconfiguration", "severity": "medium", "cwe": "CWE-16", "category": "misconfiguration"},
    {"id": "JFROG-XRAY-009", "name": "Secret detection in artifacts", "severity": "high", "cwe": "CWE-798", "category": "secrets"},
    {"id": "JFROG-XRAY-010", "name": "SBOM completeness check", "severity": "low", "cwe": "CWE-1059", "category": "compliance"},
    {"id": "JFROG-XRAY-011", "name": "Vulnerable build tool", "severity": "high", "cwe": "CWE-1035", "category": "sca"},
    {"id": "JFROG-XRAY-012", "name": "Cryptographic weakness in dependency", "severity": "high", "cwe": "CWE-327", "category": "crypto"},
    {"id": "JFROG-XRAY-013", "name": "Insecure deserialization in library", "severity": "critical", "cwe": "CWE-502", "category": "deserialization"},
    {"id": "JFROG-XRAY-014", "name": "Remote code execution in dependency", "severity": "critical", "cwe": "CWE-94", "category": "injection"},
    {"id": "JFROG-XRAY-015", "name": "Path traversal in package", "severity": "high", "cwe": "CWE-22", "category": "path-traversal"},
    {"id": "JFROG-XRAY-016", "name": "Prototype pollution in JS library", "severity": "high", "cwe": "CWE-1321", "category": "injection"},
    {"id": "JFROG-XRAY-017", "name": "ReDoS in regex dependency", "severity": "medium", "cwe": "CWE-1333", "category": "dos"},
    {"id": "JFROG-XRAY-018", "name": "Improper input validation in library", "severity": "medium", "cwe": "CWE-20", "category": "input-validation"},
    {"id": "JFROG-XRAY-019", "name": "Information exposure in package", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure"},
    {"id": "JFROG-XRAY-020", "name": "Insecure transit protocol in dependency", "severity": "medium", "cwe": "CWE-319", "category": "crypto"},
]


class JFrogXrayCollector(BaseCollector):
    name = "jfrog_xray"
    display_name = "JFrog Xray"
    source_type = "web_scrape"
    source_url = JFROG_SECURITY_URL
    description = (
        "JFrog Xray — security analysis for software artifacts and packages. "
        "Detects known vulnerabilities, malicious packages, license compliance "
        "issues, secrets in artifacts, container vulnerabilities, and IaC "
        "misconfigurations across the software supply chain."
    )
    logo_url = "https://jfrog.com/wp-content/themes/jfrog/img/logo.svg"

    def collect_rules(self):
        logger.info(f"[jfrog_xray] Collecting JFrog Xray security checks...")

        count = 0
        try:
            count = self._scrape_advisories()
        except Exception as e:
            logger.warning(f"[jfrog_xray] Scrape failed: {e}, using curated list")

        if count == 0:
            for check in JFROG_CHECKS:
                self.upsert(
                    rule_id=check["id"],
                    title=check["name"],
                    description=(
                        f"JFrog Xray security check: {check['name']}. "
                        f"Category: {check['category']}. "
                        f"Mapped to {check['cwe']}."
                    ),
                    severity=check["severity"],
                    category=check["category"],
                    language="",
                    cwe_ids=[check["cwe"]],
                    owasp_ids=[],
                    tags=["jfrog", "xray", "sca", check["category"]],
                    source_file=JFROG_SECURITY_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "JFrog",
                        "check_id": check["id"],
                        "cwe": check["cwe"],
                    },
                )
                count += 1

        logger.info(f"[jfrog_xray] Collected {count} security checks.")
        return self.stats

    def _scrape_advisories(self):
        """Scrape JFrog security advisories page."""
        resp = requests.get(JFROG_SECURITY_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        count = 0
        seen = set()

        # Look for advisory entries on the page
        # JFrog lists advisories with CVE IDs and descriptions
        advisories = re.findall(
            r'(CVE-\d{4}-\d+).*?(?:<[^>]+>)*\s*([^<]{10,200})',
            html, re.IGNORECASE
        )

        for cve_id, desc_text in advisories:
            if cve_id in seen:
                continue
            seen.add(cve_id)

            desc = re.sub(r'<[^>]+>', '', desc_text).strip()[:500]
            if not desc:
                desc = f"JFrog security advisory: {cve_id}"

            sev_match = re.search(r'(critical|high|medium|low)', desc, re.IGNORECASE)
            severity = sev_match.group(1).lower() if sev_match else "medium"

            self.upsert(
                rule_id=f"JFROG-{cve_id}",
                title=f"{cve_id}: {desc[:100]}",
                description=desc[:2000],
                severity=severity,
                category="sca",
                language="",
                cwe_ids=[],
                owasp_ids=[],
                tags=["jfrog", "xray", "sca"],
                source_file=f"{JFROG_SECURITY_URL}",
                rule_content="",
                rule_format="html",
                metadata={"vendor": "JFrog", "cve": cve_id},
            )
            count += 1

        return count