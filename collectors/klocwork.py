"""Collector for Perforce Klocwork static analysis checkers.

Klocwork is a commercial static analysis tool by Perforce (formerly Klocwork).
Checker documentation is publicly available at:
  https://docs.perforce.com/klocwork/

This collector scrapes the Klocwork docs for checker definitions, which
include checker names, severity, CWE mappings, and descriptions.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

KLOCWORK_URL = "https://docs.perforce.com/klocwork/en-US/Content/Reference/CheckerReference/C_CheckerReference.htm"
KLOCWORK_JAVA_URL = "https://docs.perforce.com/klocwork/en-US/Content/Reference/CheckerReference/J_CheckerReference.htm"
REQUEST_TIMEOUT = 60

# Curated Klocwork checkers (subset from public docs)
KLOCWORK_CHECKERS = [
    # C/C++ checkers
    {"id": "KW-ABV-GENERAL", "name": "Array bounds violation", "severity": "critical", "cwe": "CWE-787", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-ABV-STACK", "name": "Stack-based buffer overflow", "severity": "critical", "cwe": "CWE-121", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-ABV-HEAP", "name": "Heap-based buffer overflow", "severity": "critical", "cwe": "CWE-122", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-ABV-UNKNOWN", "name": "Unknown size buffer overflow", "severity": "high", "cwe": "CWE-787", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-NPD", "name": "Null pointer dereference", "severity": "critical", "cwe": "CWE-476", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-UFM", "name": "Use after free", "severity": "critical", "cwe": "CWE-416", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-MLK", "name": "Memory leak", "severity": "high", "cwe": "CWE-401", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-DFREE", "name": "Double free", "severity": "critical", "cwe": "CWE-415", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-MM-UNKNOWN", "name": "Mismatched memory management", "severity": "high", "cwe": "CWE-762", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-UNINIT", "name": "Uninitialized variable", "severity": "high", "cwe": "CWE-457", "category": "correctness", "lang": "c,c++"},
    {"id": "KW-OVERRUN", "name": "Buffer overrun", "severity": "critical", "cwe": "CWE-787", "category": "memory-safety", "lang": "c,c++"},
    {"id": "KW-RACE", "name": "Race condition", "severity": "high", "cwe": "CWE-362", "category": "concurrency", "lang": "c,c++"},
    {"id": "KW-DEADCODE", "name": "Dead code", "severity": "low", "cwe": "CWE-561", "category": "code-quality", "lang": "c,c++"},
    {"id": "KW-DIVZERO", "name": "Division by zero", "severity": "high", "cwe": "CWE-369", "category": "correctness", "lang": "c,c++"},
    {"id": "KW-INTOVER", "name": "Integer overflow", "severity": "high", "cwe": "CWE-190", "category": "correctness", "lang": "c,c++"},
    {"id": "KW-TOCTOU", "name": "TOCTOU race condition", "severity": "high", "cwe": "CWE-367", "category": "concurrency", "lang": "c,c++"},
    {"id": "KW-SQL-INJ", "name": "SQL injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli", "lang": "c,c++"},
    {"id": "KW-CMD-INJ", "name": "Command injection", "severity": "critical", "cwe": "CWE-77", "category": "injection", "lang": "c,c++"},
    {"id": "KW-XSS", "name": "Cross-site scripting", "severity": "high", "cwe": "CWE-79", "category": "xss", "lang": "c,c++"},
    {"id": "KW-PATH-TRAVERSAL", "name": "Path traversal", "severity": "high", "cwe": "CWE-22", "category": "path-traversal", "lang": "c,c++"},
    {"id": "KW-HARDCODED-PASS", "name": "Hardcoded password", "severity": "high", "cwe": "CWE-798", "category": "secrets", "lang": "c,c++"},
    {"id": "KW-INSECURE-RANDOM", "name": "Insecure random number", "severity": "medium", "cwe": "CWE-330", "category": "crypto", "lang": "c,c++"},
    {"id": "KW-INSECURE-CRYPTO", "name": "Insecure cryptographic algorithm", "severity": "high", "cwe": "CWE-327", "category": "crypto", "lang": "c,c++"},
    {"id": "KW-INFO-LEAK", "name": "Information leakage", "severity": "medium", "cwe": "CWE-200", "category": "information-disclosure", "lang": "c,c++"},
    # Java checkers
    {"id": "KW-JAVA-NPD", "name": "Java null pointer dereference", "severity": "critical", "cwe": "CWE-476", "category": "memory-safety", "lang": "java"},
    {"id": "KW-JAVA-MLK", "name": "Java memory leak", "severity": "high", "cwe": "CWE-401", "category": "memory-safety", "lang": "java"},
    {"id": "KW-JAVA-RACE", "name": "Java race condition", "severity": "high", "cwe": "CWE-362", "category": "concurrency", "lang": "java"},
    {"id": "KW-JAVA-SQL-INJ", "name": "Java SQL injection", "severity": "critical", "cwe": "CWE-89", "category": "sqli", "lang": "java"},
    {"id": "KW-JAVA-XSS", "name": "Java XSS", "severity": "high", "cwe": "CWE-79", "category": "xss", "lang": "java"},
    {"id": "KW-JAVA-DEADLOCK", "name": "Java potential deadlock", "severity": "high", "cwe": "CWE-833", "category": "concurrency", "lang": "java"},
    {"id": "KW-JAVA-UNINIT", "name": "Java uninitialized field", "severity": "medium", "cwe": "CWE-457", "category": "correctness", "lang": "java"},
    {"id": "KW-JAVA-EMPTYSYNC", "name": "Java empty synchronized block", "severity": "medium", "cwe": "CWE-585", "category": "concurrency", "lang": "java"},
    {"id": "KW-JAVA-IGNEX", "name": "Java ignored exception", "severity": "low", "cwe": "CWE-390", "category": "error-handling", "lang": "java"},
    {"id": "KW-JAVA-HARDCODED", "name": "Java hardcoded credential", "severity": "high", "cwe": "CWE-798", "category": "secrets", "lang": "java"},
]


class KlocworkCollector(BaseCollector):
    name = "klocwork"
    display_name = "Perforce Klocwork"
    source_type = "web_scrape"
    source_url = KLOCWORK_URL
    description = (
        "Perforce Klocwork — commercial static analysis for C, C++, Java, "
        "and C#. Detects security vulnerabilities, memory safety issues, "
        "concurrency bugs, and code quality problems with CWE mappings."
    )
    logo_url = "https://docs.perforce.com/s/en_US/images/logo"

    def collect_rules(self):
        logger.info(f"[klocwork] Collecting Klocwork checker definitions...")

        count = 0
        try:
            count = self._scrape_docs(KLOCWORK_URL, "c,c++")
        except Exception as e:
            logger.warning(f"[klocwork] C/C++ docs scrape failed: {e}")

        try:
            count += self._scrape_docs(KLOCWORK_JAVA_URL, "java")
        except Exception as e:
            logger.warning(f"[klocwork] Java docs scrape failed: {e}")

        if count == 0:
            for checker in KLOCWORK_CHECKERS:
                self.upsert(
                    rule_id=checker["id"],
                    title=checker["name"],
                    description=(
                        f"Perforce Klocwork checker: {checker['name']}. "
                        f"Category: {checker['category']}. "
                        f"Mapped to {checker['cwe']}. "
                        f"Language: {checker['lang']}."
                    ),
                    severity=checker["severity"],
                    category=checker["category"],
                    language=checker["lang"],
                    cwe_ids=[checker["cwe"]],
                    owasp_ids=[],
                    tags=[checker["lang"].split(",")[0], "klocwork", checker["category"]],
                    source_file=KLOCWORK_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Perforce",
                        "checker_id": checker["id"],
                        "cwe": checker["cwe"],
                    },
                )
                count += 1

        logger.info(f"[klocwork] Collected {count} checkers.")
        return self.stats

    def _scrape_docs(self, url, language):
        """Scrape Klocwork docs for checker listings."""
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        count = 0
        seen = set()

        # Look for checker entries in the docs
        sections = re.findall(r'<h[23][^>]*>(.*?)</h[23]>(.*?)(?=<h[23]|$)', html, re.DOTALL)
        for heading_html, body_html in sections:
            heading = re.sub(r'<[^>]+>', '', heading_html).strip()
            body = re.sub(r'<[^>]+>', ' ', body_html).strip()[:500]

            if not heading or heading.lower() in seen:
                continue
            seen.add(heading.lower())

            cwe_match = re.search(r'CWE[-\s]?(\d+)', body, re.IGNORECASE)
            cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

            sev_match = re.search(r'(critical|high|medium|low|error|warning)', body, re.IGNORECASE)
            severity = sev_match.group(1).lower() if sev_match else "medium"
            if severity == "error":
                severity = "high"
            if severity == "warning":
                severity = "medium"

            rule_id = f"KW-{re.sub(r'[^A-Z0-9]+', '_', heading.upper())[:30]}"

            self.upsert(
                rule_id=rule_id,
                title=heading[:500],
                description=body[:2000],
                severity=severity,
                category="correctness",
                language=language,
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=[language.split(",")[0], "klocwork"],
                source_file=url,
                rule_content="",
                rule_format="html",
                metadata={"vendor": "Perforce", "source": "docs"},
            )
            count += 1

        return count