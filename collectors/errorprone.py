"""Collector for Google ErrorProne bug pattern rules.

ErrorProne is Google's Java bug pattern analyzer that runs at compile time.
Rules are defined as Java classes annotated with @BugPattern, specifying:
  - name: the rule name (if absent, defaults to the class name)
  - summary: short description
  - severity: ERROR, WARNING, SUGGESTION
  - category: first-party, third-party, etc.
  - link: URL to detailed explanation

The @BugPattern annotation may use:
  - `severity = ERROR` (static import of SeverityLevel.ERROR)
  - `severity = SeverityLevel.ERROR` (fully qualified)
  - No `name` field (defaults to the class name)
  - `altNames` for alternative names
  - `summary` with multi-line string concatenation
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
        # This directory contains all ~648 bug pattern classes.
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
        """Parse a Java file with @BugPattern annotation.

        The @BugPattern annotation may or may not include a `name` field.
        When absent, the rule name defaults to the Java class name.
        Severity is typically a statically imported enum constant (e.g. just
        `ERROR` rather than `Severity.ERROR`).
        """
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        # Find @BugPattern annotation — it may span multiple lines.
        # The annotation body ends at the first closing paren at the
        # annotation's nesting level.
        bp_match = re.search(r'@BugPattern\s*\((.*?)\)', content, re.DOTALL)
        if not bp_match:
            return 0

        annotation = bp_match.group(1)

        # Extract the rule name. Many bug patterns do NOT specify name=
        # and instead rely on the class name as the canonical rule name.
        name_m = re.search(r'name\s*=\s*"([^"]+)"', annotation)

        # Get the class name — used as the rule name when name= is absent.
        class_m = re.search(r'class\s+(\w+)', content)
        class_name = class_m.group(1) if class_m else os.path.basename(fpath).replace(".java", "")

        rule_name = name_m.group(1) if name_m else class_name
        rule_id = f"errorprone-{rule_name}"

        # Extract summary (may use string concatenation across lines).
        summary_m = re.search(r'summary\s*=\s*"([^"]+)"', annotation)
        title = summary_m.group(1) if summary_m else rule_name

        # Extract severity. ErrorProne uses SeverityLevel enum constants
        # that are typically statically imported, so the annotation just
        # says `severity = ERROR` (not `severity = SeverityLevel.ERROR`).
        # We match both forms and also handle the qualified form.
        severity_m = re.search(
            r'severity\s*=\s*(?:SeverityLevel\.)?(\w+)', annotation
        )
        if severity_m:
            sev_val = severity_m.group(1)
            # Filter out false matches like "BugPattern" from qualified refs
            severity = SEVERITY_MAP.get(sev_val.lower(), "info")
        else:
            severity = "info"

        # Extract category (optional)
        category_m = re.search(
            r'category\s*=\s*(?:Category\.)?(\w+)', annotation
        )

        # Extract altNames (optional)
        alt_names_m = re.search(r'altNames\s*=\s*"([^"]+)"', annotation)

        # Extract CWE from file content
        cwe_ids = ""
        cwe_m = re.search(r'cwe[-_]?(?:id\s*[:=]\s*)?(\d+)', content, re.IGNORECASE)
        if cwe_m:
            cwe_ids = f"CWE-{cwe_m.group(1)}"

        # Build relative path for source_file
        rel_path = os.path.relpath(fpath, self.clone_dir)

        # Determine subcategory from directory structure
        bp_dir = os.path.join(
            self.clone_dir,
            "core", "src", "main", "java", "com", "google", "errorprone", "bugpatterns",
        )
        rel_to_bp = os.path.relpath(fpath, bp_dir) if os.path.isdir(bp_dir) else os.path.basename(fpath)
        subdir = os.path.dirname(rel_to_bp)
        category = category_m.group(1) if category_m else ""
        if subdir and subdir != ".":
            category = category or subdir.replace(os.sep, ".")

        metadata = {
            "class": class_name,
            "category": category,
        }
        if alt_names_m:
            metadata["altNames"] = alt_names_m.group(1)

        self.upsert(
            rule_id,
            title,
            severity=severity,
            cwe_ids=cwe_ids if cwe_ids else None,
            category=category,
            language="java",
            description=f"ErrorProne bug pattern: {rule_name}. {title}",
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="java",
            tags=["errorprone", "java", "sast", "bugpattern"],
            metadata=metadata,
        )
        return 1