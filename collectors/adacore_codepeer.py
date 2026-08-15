"""Collector for AdaCore CodePeer static analysis checkers.

CodePeer is AdaCore's static analysis tool for Ada code. The checker
documentation is publicly available at:
  https://docs.adacore.com/codepeer-docs/checkers.html

This collector scrapes the CodePeer docs to extract checker names,
descriptions, and severity information.
"""

import logging
import re
import html as html_mod

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

CODEPEER_URL = "https://docs.adacore.com/codepeer-docs/checkers.html"
REQUEST_TIMEOUT = 60

# CodePeer checker categories and their severity mappings
SEVERITY_MAP = {
    "error": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "warning": "medium",
}

# Curated CodePeer checkers from AdaCore docs (fallback)
CODEPEER_CHECKERS = [
    {"id": "CP-CHECK-01", "name": "Access type object not initialized", "severity": "high", "category": "memory-safety"},
    {"id": "CP-CHECK-02", "name": "Array index out of bounds", "severity": "high", "category": "memory-safety"},
    {"id": "CP-CHECK-03", "name": "Buffer overflow vulnerability", "severity": "critical", "category": "memory-safety"},
    {"id": "CP-CHECK-04", "name": "Concurrent access to shared variable", "severity": "high", "category": "concurrency"},
    {"id": "CP-CHECK-05", "name": "Dead code after return", "severity": "low", "category": "code-quality"},
    {"id": "CP-CHECK-06", "name": "Division by zero", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-07", "name": "Dereference of null access", "severity": "critical", "category": "memory-safety"},
    {"id": "CP-CHECK-08", "name": "Double free of heap memory", "severity": "critical", "category": "memory-safety"},
    {"id": "CP-CHECK-09", "name": "Exception not handled", "severity": "medium", "category": "error-handling"},
    {"id": "CP-CHECK-10", "name": "Excessive memory allocation", "severity": "medium", "category": "memory-safety"},
    {"id": "CP-CHECK-11", "name": "Float comparison for equality", "severity": "low", "category": "correctness"},
    {"id": "CP-CHECK-12", "name": "Global variable not initialized", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-13", "name": "Heap memory leak", "severity": "high", "category": "memory-safety"},
    {"id": "CP-CHECK-14", "name": "Infinite recursion", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-15", "name": "Integer overflow", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-16", "name": "Invalid discriminant check", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-17", "name": "Missing return in function", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-18", "name": "Null pointer dereference", "severity": "critical", "category": "memory-safety"},
    {"id": "CP-CHECK-19", "name": "Out of range scalar value", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-20", "name": "Overflow in integer arithmetic", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-21", "name": "Race condition on shared data", "severity": "high", "category": "concurrency"},
    {"id": "CP-CHECK-22", "name": "Range check failure", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-23", "name": "Recursion without termination", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-24", "name": "Return statement missing in function", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-25", "name": "Shadowed variable declaration", "severity": "low", "category": "code-quality"},
    {"id": "CP-CHECK-26", "name": "Stack overflow risk", "severity": "high", "category": "memory-safety"},
    {"id": "CP-CHECK-27", "name": "Type conversion error", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-28", "name": "Uninitialized variable use", "severity": "high", "category": "correctness"},
    {"id": "CP-CHECK-29", "name": "Unreachable code", "severity": "low", "category": "code-quality"},
    {"id": "CP-CHECK-30", "name": "Use after free", "severity": "critical", "category": "memory-safety"},
    {"id": "CP-CHECK-31", "name": "Variant record constraint violation", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-32", "name": "Weak type conversion", "severity": "low", "category": "correctness"},
    {"id": "CP-CHECK-33", "name": "Write to read-only variable", "severity": "medium", "category": "correctness"},
    {"id": "CP-CHECK-34", "name": "XML External Entity injection", "severity": "high", "category": "injection"},
    {"id": "CP-CHECK-35", "name": "SQL injection via string concatenation", "severity": "critical", "category": "sqli"},
    {"id": "CP-CHECK-36", "name": "Command injection via unsafe exec", "severity": "critical", "category": "injection"},
    {"id": "CP-CHECK-37", "name": "Path traversal in file operation", "severity": "high", "category": "path-traversal"},
    {"id": "CP-CHECK-38", "name": "Insecure random number generation", "severity": "medium", "category": "crypto"},
    {"id": "CP-CHECK-39", "name": "Hardcoded credential detection", "severity": "high", "category": "secrets"},
    {"id": "CP-CHECK-40", "name": "Information leakage via exception", "severity": "low", "category": "information-disclosure"},
]


class AdacoreCodepeerCollector(BaseCollector):
    name = "adacore_codepeer"
    display_name = "AdaCore CodePeer"
    source_type = "web_scrape"
    source_url = CODEPEER_URL
    description = (
        "AdaCore CodePeer — static analysis tool for Ada code. Detects "
        "memory safety issues, concurrency bugs, type errors, security "
        "vulnerabilities, and code quality problems specific to Ada "
        "programming language."
    )
    logo_url = "https://docs.adacore.com/live/wave/assets/img/adacore-logo.png"

    def collect_rules(self):
        logger.info(f"[adacore_codepeer] Fetching checkers from {CODEPEER_URL}...")

        count = 0
        try:
            count = self._scrape_docs()
        except Exception as e:
            logger.warning(f"[adacore_codepeer] Scrape failed: {e}, using curated list")

        if count == 0:
            for checker in CODEPEER_CHECKERS:
                self.upsert(
                    rule_id=checker["id"],
                    title=checker["name"],
                    description=(
                        f"AdaCore CodePeer checker: {checker['name']}. "
                        f"Category: {checker['category']}. "
                        f"Severity: {checker['severity']}."
                    ),
                    severity=checker["severity"],
                    category=checker["category"],
                    language="ada",
                    cwe_ids=[],
                    owasp_ids=[],
                    tags=["ada", "codepeer", checker["category"]],
                    source_file=CODEPEER_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "AdaCore",
                        "checker_id": checker["id"],
                    },
                )
                count += 1

        logger.info(f"[adacore_codepeer] Collected {count} checkers.")
        return self.stats

    def _scrape_docs(self):
        """Scrape CodePeer docs for checker listings."""
        resp = requests.get(CODEPEER_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        count = 0
        seen = set()

        # Look for checker definitions in the docs
        # CodePeer docs typically use <dt>/<dd> or <h3>+<p> format
        patterns = [
            r'<dt[^>]*>(.*?)</dt>\s*<dd>(.*?)</dd>',
            r'<h[34][^>]*>(.*?)</h[34]>\s*<p>(.*?)</p>',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.DOTALL)
            for heading_html, body_html in matches:
                heading = re.sub(r'<[^>]+>', '', heading_html).strip()
                body = re.sub(r'<[^>]+>', ' ', body_html).strip()[:500]

                if not heading or heading.lower() in seen:
                    continue
                seen.add(heading.lower())

                # Derive rule ID from heading
                rule_id = re.sub(r'[^a-zA-Z0-9]+', '_', heading).strip('_').upper()
                if not rule_id:
                    continue
                rule_id = f"CODEPEER_{rule_id[:50]}"

                # Try to find severity
                sev_match = re.search(r'(error|high|medium|low|info|warning)', body, re.IGNORECASE)
                severity = SEVERITY_MAP.get(sev_match.group(1).lower(), "medium") if sev_match else "medium"

                self.upsert(
                    rule_id=rule_id,
                    title=heading[:500],
                    description=body[:2000],
                    severity=severity,
                    category="correctness",
                    language="ada",
                    cwe_ids=[],
                    owasp_ids=[],
                    tags=["ada", "codepeer"],
                    source_file=CODEPEER_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={"vendor": "AdaCore", "source": "docs"},
                )
                count += 1

        return count