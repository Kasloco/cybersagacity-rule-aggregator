"""Collector for Google ErrorProne bug pattern rules.

ErrorProne is Google's Java bug pattern analyzer that runs at compile time.
Rules are defined as Java classes annotated with @BugPattern, specifying:
  - name: the rule name
  - summary: short description
  - severity: ERROR, WARNING, SUGGESTION
  - category: first-party, third-party, etc.
  - link: URL to detailed explanation
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "suggestion": "low",
    "info": "info",
}


class ErrorProneCollector(BaseCollector):
    name = "errorprone"
    display_name = "ErrorProne"
    source_type = "github"
    source_url = "https://github.com/google/error-prone.git"
    description = (
        "Google ErrorProne is a compile-time Java bug pattern analyzer. "
        "It catches common programming mistakes and security-relevant patterns "
        "during compilation. Rules are Java classes annotated with @BugPattern "
        "specifying name, summary, severity, and category."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1342004"

    def collect_rules(self):
        count = 0

        # Bug patterns are in core/src/main/java/com/google/errorprone/bugpatterns/
        bp_dir = os.path.join(
            self.clone_dir,
            "core", "src", "main", "java", "com", "google", "errorprone", "bugpatterns",
        )
        if not os.path.isdir(bp_dir):
            logger.warning("[errorprone] bugpatterns directory not found")
            return

        for root, dirs, files in os.walk(bp_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                fpath = os.path.join(root, fname)
                count += self._parse_bug_pattern(fpath)

        logger.info(f"[errorprone] Processed {count} rules")

    def _parse_bug_pattern(self, fpath):
        """Parse a Java file with @BugPattern annotation."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        # Find @BugPattern annotation
        # Pattern: @BugPattern(
        #     name = "RuleName",
        #     summary = "Short description",
        #     severity = Severity.ERROR,
        #     ...
        # )
        bp_match = re.search(r'@BugPattern\s*\((.*?)\)', content, re.DOTALL)
        if not bp_match:
            return 0

        annotation = bp_match.group(1)

        # Extract fields
        name_m = re.search(r'name\s*=\s*"([^"]+)"', annotation)
        summary_m = re.search(r'summary\s*=\s*"([^"]+)"', annotation)
        severity_m = re.search(r'severity\s*=\s*(?:Severity\.)?(\w+)', annotation)
        category_m = re.search(r'category\s*=\s*(?:Category\.)?(\w+)', annotation)

        if not name_m:
            return 0

        rule_name = name_m.group(1)
        rule_id = f"errorprone-{rule_name}"
        title = summary_m.group(1) if summary_m else rule_name
        severity = SEVERITY_MAP.get(
            severity_m.group(1).lower() if severity_m else "",
            "info",
        )

        # Extract CWE from link or description
        cwe_ids = ""
        cwe_m = re.search(r'cwe[-_]?(\d+)', content, re.IGNORECASE)
        if cwe_m:
            cwe_ids = f"CWE-{cwe_m.group(1)}"

        # Get class name for additional context
        class_m = re.search(r'class\s+(\w+)', content)
        class_name = class_m.group(1) if class_m else os.path.basename(fpath).replace(".java", "")

        self.upsert(
            rule_id,
            title,
            severity=severity,
            cwe_ids=cwe_ids,
            description=f"ErrorProne bug pattern: {rule_name}. {title}",
            metadata={
                "class": class_name,
                "category": category_m.group(1) if category_m else "",
            },
        )
        return 1