"""Collector for detekt (Kotlin static analysis) rules."""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# detekt rule-set modules and their rule-set IDs.
# Each module lives at detekt-rules-<name>/ and contains rules under
# src/main/kotlin/dev/detekt/rules/<package>/.
RULE_MODULES = [
    "detekt-rules-complexity",
    "detekt-rules-coroutines",
    "detekt-rules-empty-blocks",
    "detekt-rules-exceptions",
    "detekt-rules-naming",
    "detekt-rules-performance",
    "detekt-rules-potential-bugs",
    "detekt-rules-style",
    "detekt-rules-comments",
    "detekt-rules-libraries",
    "detekt-rules-ruleauthors",
    "detekt-rules-ktlint-wrapper",
]

# Kotlin source root inside each module
KOTLIN_SRC = "src/main/kotlin"


class DetektCollector(BaseCollector):
    name = "detekt"
    display_name = "detekt"
    source_type = "github"
    source_url = "https://github.com/detekt/detekt.git"
    description = (
        "Static code analysis tool for Kotlin. Detects code smells, "
        "complexity issues, naming violations, potential bugs, performance "
        "problems, empty code blocks, exception handling issues, and "
        "enforces style conventions across Kotlin projects."
    )
    logo_url = "https://avatars.githubusercontent.com/u/38919421"

    def collect_rules(self):
        count = 0

        for module in RULE_MODULES:
            src_dir = os.path.join(self.clone_dir, module, KOTLIN_SRC)
            if not os.path.isdir(src_dir):
                continue

            # Determine the rule-set ID from the module name
            rule_set_id = module.replace("detekt-rules-", "").replace("-wrapper", "")

            for root, dirs, files in os.walk(src_dir):
                dirs[:] = [
                    d for d in dirs
                    if not d.startswith(".") and d != "internal"
                ]
                for fname in sorted(files):
                    if not fname.endswith(".kt"):
                        continue
                    # Skip Provider files and internal utility files
                    if fname.endswith("Provider.kt") or fname.startswith("_"):
                        continue
                    # Skip files that are not rule definitions (utils, helpers)
                    if fname in ("EmptyRule.kt", "EmptyCodeProvider.kt"):
                        continue

                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, self.clone_dir)

                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read()
                    except Exception:
                        continue

                    rule = self._parse_rule_file(
                        content, fname, rel_path, rule_set_id
                    )
                    if rule:
                        self.upsert(
                            rule_id=rule["id"],
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            category=rule_set_id,
                            language="kotlin",
                            cwe_ids=[],
                            tags=rule["tags"],
                            source_file=rel_path,
                            rule_content=content[:50000],
                            rule_format="kotlin",
                            metadata=rule["metadata"],
                        )
                        count += 1

        logger.info(f"[detekt] Processed {count} rules")

    def _parse_rule_file(self, content, filename, rel_path, rule_set_id):
        """Extract rule metadata from a detekt Kotlin rule file.

        detekt rules follow these patterns:

        1.  **Rule** subclass — passes description via constructor:
            ``class FooRule(config: Config) : Rule(config, "description")``

        2.  **EmptyRule** subclass — passes description via constructor:
            ``class FooBlock(config: Config) : EmptyRule(
                  config, description = "...", findingMessage = "..."
              )``

        3.  Rule name = class name (the ``ruleName`` property defaults to
            ``javaClass.simpleName``).

        4.  ``@ActiveByDefault(since = "1.0.0")`` marks rules enabled by
            default.

        5.  Severity is not defined per-rule in source — it's configurable.
            We default to "info" and set "warning" for potential bugs and
            "error" for empty-block rules.
        """
        # -- Class name (rule name) --
        class_match = re.search(r'class\s+(\w+)\s*\(', content)
        if not class_match:
            return None
        class_name = class_match.group(1)

        # -- Description --
        # Try constructor parameter: Rule(config, "description")
        # or Rule(config, description = "...")
        description = self._extract_description(content, class_name)

        # If no description found, try KDoc comment
        if not description:
            description = self._extract_kdoc(content)

        if not description:
            description = class_name

        # -- @ActiveByDefault --
        active_by_default = None
        active_match = re.search(
            r'@ActiveByDefault\s*\(\s*since\s*=\s*"([^"]+)"\s*\)', content
        )
        if active_match:
            active_by_default = active_match.group(1)

        # -- @Configuration annotations (config options) --
        config_options = re.findall(
            r'@Configuration\s*\(\s*"([^"]+)"\s*\)', content
        )

        # -- Severity (heuristic based on rule set) --
        severity = self._map_severity(rule_set_id)

        # -- Rule ID --
        rule_id = f"detekt:{class_name}"

        # -- Tags --
        tags = ["detekt", "kotlin", "sast", rule_set_id]
        if active_by_default:
            tags.append("active-by-default")

        # -- KDoc (full documentation) --
        kdoc = self._extract_full_kdoc(content)

        metadata = {
            "rule_name": class_name,
            "rule_set_id": rule_set_id,
            "active_by_default": active_by_default,
            "config_options": config_options,
            "source_file": rel_path,
        }
        if kdoc:
            metadata["kdoc"] = kdoc[:1000]

        return {
            "id": rule_id,
            "title": f"{class_name}: {description}"[:500],
            "description": (kdoc or description)[:2000],
            "severity": severity,
            "tags": tags,
            "metadata": metadata,
        }

    @staticmethod
    def _extract_description(content, class_name):
        """Extract the description string from the rule's constructor call."""
        # Pattern 1: Rule(config, "description")
        # This is the most common pattern in detekt
        patterns = [
            # Rule(config, "description")
            rf'class\s+{re.escape(class_name)}\s*\([^)]*\)\s*:\s*\w+\s*\(\s*\w+\s*,\s*"((?:[^"\\]|\\.)*)"',
            # Rule(\n    config,\n    "description"\n)
            rf'class\s+{re.escape(class_name)}\s*\([^)]*\)\s*:\s*\w+\s*\(\s*\w+\s*,\s*\n\s*"((?:[^"\\]|\\.)*)"',
            # description = "..."
            r'description\s*=\s*\n?\s*"((?:[^"\\]|\\.)*)"',
            # EmptyRule(config, description = "...", findingMessage = "...")
            rf'class\s+{re.escape(class_name)}\s*\([^)]*\)\s*:\s*\w+\s*\(\s*\w+\s*,\s*\n?\s*description\s*=\s*\n?\s*"((?:[^"\\]|\\.)*)"',
        ]
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1).strip()
        return None

    @staticmethod
    def _extract_kdoc(content):
        """Extract the first KDoc comment block from the file."""
        # KDoc starts with /** and ends with */
        match = re.search(r'/\*\*\s*\n((?:\s*\*.*\n)*)\s*\*/', content)
        if match:
            lines = match.group(1)
            # Clean up: remove leading * and whitespace
            cleaned = re.sub(r'^\s*\*\s?', '', lines, flags=re.MULTILINE)
            cleaned = cleaned.strip()
            if cleaned:
                # Take first non-empty line as description
                first_line = cleaned.split('\n')[0].strip()
                return first_line if first_line else cleaned
        return None

    @staticmethod
    def _extract_full_kdoc(content):
        """Extract the full KDoc comment block including examples."""
        match = re.search(r'/\*\*\s*\n((?:\s*\*.*\n)*)\s*\*/', content)
        if match:
            lines = match.group(1)
            cleaned = re.sub(r'^\s*\*\s?', '', lines, flags=re.MULTILINE)
            cleaned = cleaned.strip()
            return cleaned if cleaned else None
        return None

    @staticmethod
    def _map_severity(rule_set_id):
        """Map a detekt rule-set ID to a severity level."""
        # Potential bugs and exceptions are more severe
        high_sets = {"potential-bugs", "exceptions"}
        medium_sets = {"complexity", "coroutines", "performance"}
        if rule_set_id in high_sets:
            return "high"
        if rule_set_id in medium_sets:
            return "medium"
        return "info"