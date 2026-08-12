"""Collector for Psalm PHP static analysis rules by Vimeo.

Psalm defines issue types as PHP classes in ``src/Psalm/Issue/*.php``. Each
class extends ``CodeIssue`` (or a subclass like ``ClassIssue``,
``PropertyIssue``, ``MethodIssue``, etc.) and defines two constants:

  - ``ERROR_LEVEL`` — integer 1-9 where lower is more severe (1=critical, 2=high,
    3-4=medium, 5-7=low, 8-9=info). Negative values are suppressed by default.
  - ``SHORTCODE`` — unique numeric ID used in documentation URLs (psalm.dev/NNN)

Each issue also has a documentation page in ``docs/running_psalm/issues/<Name>.md``
containing a human-readable description starting with "Emitted when ...".

The collector:
  1. Walks ``src/Psalm/Issue/`` for PHP files with class definitions
  2. Extracts the class name (used as the rule ID), ERROR_LEVEL, SHORTCODE
  3. Determines the parent issue class (category)
  4. Reads the corresponding doc page for a description
  5. Upserts each issue with all preserved metadata
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Map Psalm ERROR_LEVEL to our five-tier severity system.
# Psalm levels 1-9, lower = more severe.
# Level 1: Error, must fix
# Level 2: Error, should fix
# Level 3-4: Warning
# Level 5-7: Info/suggestion
# Level 8-9: Very minor
# Negative: suppressed by default
ERROR_LEVEL_TO_SEVERITY = {
    1: "critical",
    2: "high",
    3: "high",
    4: "medium",
    5: "medium",
    6: "low",
    7: "low",
    8: "info",
    9: "info",
}

# Map parent issue class to category
PARENT_CATEGORY_MAP = {
    "CodeIssue": "code_issue",
    "ClassIssue": "class_issue",
    "PropertyIssue": "property_issue",
    "MethodIssue": "method_issue",
    "FunctionIssue": "function_issue",
    "ArgumentIssue": "argument_issue",
    "ClassConstantIssue": "class_constant_issue",
    "VariableIssue": "variable_issue",
}

# Regex patterns for PHP class parsing
RE_CLASS_DEF = re.compile(
    r'(?:final\s+)?(?:class|trait)\s+(\w+)\s+extends\s+(\w+)(?:\s+implements\s+([\w, ]+))?\s*\{',
    re.MULTILINE,
)
RE_ERROR_LEVEL = re.compile(r'public\s+const\s+ERROR_LEVEL\s*=\s*(-?\d+)')
RE_SHORTCODE = re.compile(r'public\s+const\s+SHORTCODE\s*=\s*(\d+)')
RE_ABSTRACT_CLASS = re.compile(r'abstract\s+class\s+(\w+)')


class PsalmCollector(BaseCollector):
    name = "psalm"
    display_name = "Psalm (Vimeo)"
    source_type = "github"
    source_url = "https://github.com/vimeo/psalm.git"
    description = (
        "PHP static analysis tool by Vimeo. 300+ issue types covering type "
        "safety, taint analysis, code quality, and security. Each issue has "
        "an error level (1-9) and shortcode for documentation references."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1785255"

    def collect_rules(self):
        count = 0
        issue_dir = os.path.join(self.clone_dir, "src/Psalm/Issue")
        docs_dir = os.path.join(self.clone_dir, "docs/running_psalm/issues")

        if not os.path.isdir(issue_dir):
            logger.warning(f"[psalm] Issue directory not found: {issue_dir}")
            return

        # Collect abstract base classes to skip them as non-issues
        abstract_classes = set()

        # First pass: identify abstract classes and traits
        for fname in os.listdir(issue_dir):
            if not fname.endswith(".php"):
                continue
            fpath = os.path.join(issue_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            if RE_ABSTRACT_CLASS.search(content):
                cls_match = re.search(r'abstract\s+class\s+(\w+)', content)
                if cls_match:
                    abstract_classes.add(cls_match.group(1))

        # Second pass: parse actual issue classes
        for fname in sorted(os.listdir(issue_dir)):
            if not fname.endswith(".php"):
                continue

            fpath = os.path.join(issue_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            # Find class definition
            class_match = RE_CLASS_DEF.search(content)
            if not class_match:
                continue

            class_name = class_match.group(1)
            parent_class = class_match.group(2)

            # Skip abstract base classes and traits
            if class_name in abstract_classes:
                continue
            if "trait" in content[:content.index("class") + 20] if "class" in content else False:
                continue

            # Extract ERROR_LEVEL and SHORTCODE
            el_match = RE_ERROR_LEVEL.search(content)
            sc_match = RE_SHORTCODE.search(content)

            error_level = int(el_match.group(1)) if el_match else -1
            shortcode = int(sc_match.group(1)) if sc_match else 0

            # Map error level to severity
            if error_level < 0:
                severity = "info"
            elif error_level in ERROR_LEVEL_TO_SEVERITY:
                severity = ERROR_LEVEL_TO_SEVERITY[error_level]
            else:
                severity = "medium"

            # Determine category from parent class
            category = PARENT_CATEGORY_MAP.get(parent_class, "code_issue")

            # Read description from doc page
            description = self._read_issue_doc(docs_dir, class_name)

            # Build rule_id — use class name as the canonical ID
            rule_id = class_name

            # Build metadata preserving vendor-native fields
            metadata = {
                "class_name": class_name,
                "parent_class": parent_class,
                "error_level": error_level,
                "shortcode": shortcode,
                "doc_url": f"https://psalm.dev/{shortcode:03d}" if shortcode else "",
            }

            self.upsert(
                rule_id=rule_id,
                title=class_name,
                description=description,
                severity=severity,
                category=category,
                language="php",
                cwe_ids=[],
                tags=["psalm", "php", "sast", category],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="php",
                metadata=metadata,
            )
            count += 1

        logger.info(f"[psalm] Processed {count} issue types")

    def _read_issue_doc(self, docs_dir, issue_name):
        """Read the description from the issue's markdown doc page."""
        doc_path = os.path.join(docs_dir, f"{issue_name}.md")
        if not os.path.exists(doc_path):
            return ""

        try:
            with open(doc_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return ""

        # The first paragraph after the heading is the description
        # Format: "# IssueName\n\nDescription text\n\n```php"
        lines = content.split("\n")
        description_lines = []
        in_description = False

        for line in lines:
            if line.startswith("# "):
                in_description = True
                continue
            if in_description:
                if line.strip() == "" and description_lines:
                    break
                if line.startswith("```"):
                    break
                if line.strip():
                    description_lines.append(line.strip())

        return " ".join(description_lines)[:2000]