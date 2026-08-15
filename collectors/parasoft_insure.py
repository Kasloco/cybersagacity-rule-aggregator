"""Collector for Parasoft Insure++ static analysis rules.

Parasoft Insure++ is a memory and runtime error detection tool for C/C++.
Documentation is publicly available at:
  https://docs.parasoft.com/display/INSURE

This collector scrapes the Parasoft docs for error/checker definitions.
"""

import logging
import re

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

PARASOFT_URL = "https://docs.parasoft.com/display/INSURE/Insure+Error+Messages"
REQUEST_TIMEOUT = 60

# Curated Parasoft Insure++ error categories
INSURE_ERRORS = [
    {"id": "INSURE-FREE", "name": "Freeing invalid pointer", "severity": "critical", "cwe": "CWE-416", "category": "memory-safety"},
    {"id": "INSURE-LEAK", "name": "Memory leak detected", "severity": "high", "cwe": "CWE-401", "category": "memory-safety"},
    {"id": "INSURE-BOUNDS", "name": "Array bounds violation", "severity": "critical", "cwe": "CWE-787", "category": "memory-safety"},
    {"id": "INSURE-NULL", "name": "Null pointer dereference", "severity": "critical", "cwe": "CWE-476", "category": "memory-safety"},
    {"id": "INSURE-UNINIT", "name": "Use of uninitialized memory", "severity": "high", "cwe": "CWE-457", "category": "correctness"},
    {"id": "INSURE-OVERFLOW", "name": "Buffer overflow", "severity": "critical", "cwe": "CWE-120", "category": "memory-safety"},
    {"id": "INSURE-USE_AFTER_FREE", "name": "Use after free", "severity": "critical", "cwe": "CWE-416", "category": "memory-safety"},
    {"id": "INSURE-DOUBLE_FREE", "name": "Double free", "severity": "critical", "cwe": "CWE-415", "category": "memory-safety"},
    {"id": "INSURE-MISMATCH", "name": "Mismatched malloc/free", "severity": "high", "cwe": "CWE-762", "category": "memory-safety"},
    {"id": "INSURE-RACE", "name": "Data race condition", "severity": "high", "cwe": "CWE-362", "category": "concurrency"},
    {"id": "INSURE-DEADLOCK", "name": "Potential deadlock", "severity": "high", "cwe": "CWE-833", "category": "concurrency"},
    {"id": "INSURE-STACK", "name": "Stack overflow detected", "severity": "high", "cwe": "CWE-674", "category": "memory-safety"},
    {"id": "INSURE-REDZONE", "name": "Red zone access violation", "severity": "critical", "cwe": "CWE-787", "category": "memory-safety"},
    {"id": "INSURE-WILD", "name": "Wild pointer dereference", "severity": "critical", "cwe": "CWE-476", "category": "memory-safety"},
    {"id": "INSURE-RETURN", "name": "Return of stack address", "severity": "high", "cwe": "CWE-562", "category": "memory-safety"},
    {"id": "INSURE-COPY", "name": "Invalid memory copy", "severity": "high", "cwe": "CWE-787", "category": "memory-safety"},
    {"id": "INSURE-CMP", "name": "Invalid pointer comparison", "severity": "medium", "cwe": "CWE-1022", "category": "correctness"},
    {"id": "INSURE-PARAM", "name": "Invalid function parameter", "severity": "medium", "cwe": "CWE-20", "category": "input-validation"},
    {"id": "INSURE-CAST", "name": "Unsafe type cast", "severity": "medium", "cwe": "CWE-704", "category": "correctness"},
    {"id": "INSURE-FORMAT", "name": "Format string vulnerability", "severity": "high", "cwe": "CWE-134", "category": "injection"},
    {"id": "INSURE-INT_OVERFLOW", "name": "Integer overflow", "severity": "high", "cwe": "CWE-190", "category": "correctness"},
    {"id": "INSURE-DIV_ZERO", "name": "Division by zero", "severity": "high", "cwe": "CWE-369", "category": "correctness"},
    {"id": "INSURE-INDEX", "name": "Out of bounds array index", "severity": "critical", "cwe": "CWE-787", "category": "memory-safety"},
    {"id": "INSURE-STR", "name": "Unsafe string operation", "severity": "high", "cwe": "CWE-120", "category": "memory-safety"},
    {"id": "INSURE-PEER", "name": "Peer pointer mismatch", "severity": "medium", "cwe": "CWE-468", "category": "correctness"},
]


class ParasoftInsureCollector(BaseCollector):
    name = "parasoft_insure"
    display_name = "Parasoft Insure++"
    source_type = "web_scrape"
    source_url = PARASOFT_URL
    description = (
        "Parasoft Insure++ — runtime memory error detection tool for C/C++. "
        "Detects memory leaks, buffer overflows, null pointer dereferences, "
        "use-after-free, double free, data races, and other memory safety "
        "issues through runtime instrumentation."
    )
    logo_url = "https://docs.parasoft.com/s/en_US/images/logo"

    def collect_rules(self):
        logger.info(f"[parasoft_insure] Collecting Insure++ error definitions...")

        count = 0
        try:
            count = self._scrape_docs()
        except Exception as e:
            logger.warning(f"[parasoft_insure] Scrape failed: {e}, using curated list")

        if count == 0:
            for err in INSURE_ERRORS:
                self.upsert(
                    rule_id=err["id"],
                    title=err["name"],
                    description=(
                        f"Parasoft Insure++ detection: {err['name']}. "
                        f"Category: {err['category']}. "
                        f"Mapped to {err['cwe']}."
                    ),
                    severity=err["severity"],
                    category=err["category"],
                    language="c,c++",
                    cwe_ids=[err["cwe"]],
                    owasp_ids=[],
                    tags=["c", "c++", "insure", err["category"]],
                    source_file=PARASOFT_URL,
                    rule_content="",
                    rule_format="html",
                    metadata={
                        "vendor": "Parasoft",
                        "error_id": err["id"],
                        "cwe": err["cwe"],
                    },
                )
                count += 1

        logger.info(f"[parasoft_insure] Collected {count} error definitions.")
        return self.stats

    def _scrape_docs(self):
        """Scrape Parasoft docs for error messages."""
        resp = requests.get(PARASOFT_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "CyberSagacity-RuleAggregator/1.0"
        })
        resp.raise_for_status()
        html = resp.text

        count = 0
        seen = set()

        # Look for error definitions in headings + descriptions
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

            rule_id = f"INSURE-{re.sub(r'[^A-Z0-9]+', '_', heading.upper())[:30]}"

            self.upsert(
                rule_id=rule_id,
                title=heading[:500],
                description=body[:2000],
                severity=severity,
                category="memory-safety",
                language="c,c++",
                cwe_ids=[cwe_id] if cwe_id else [],
                owasp_ids=[],
                tags=["c", "c++", "insure"],
                source_file=PARASOFT_URL,
                rule_content="",
                rule_format="html",
                metadata={"vendor": "Parasoft", "source": "docs"},
            )
            count += 1

        return count