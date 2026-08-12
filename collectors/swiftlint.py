"""Collector for SwiftLint rules (Realm).

SwiftLint is a Swift linter enforcing Swift style and conventions.
Rules are defined in Swift files with RuleDescription structs.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class SwiftLintCollector(BaseCollector):
    name = "swiftlint"
    display_name = "SwiftLint"
    source_type = "github"
    source_url = "https://github.com/realm/SwiftLint.git"
    description = (
        "SwiftLint enforces Swift style and conventions. "
        "300+ rules covering idiomatic Swift, style, lint, performance, "
        "and code quality with configurable severity levels."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1191502"

    def collect_rules(self):
        count = 0

        # SwiftLint rules are in Source/SwiftLintBuiltInRules/Rules/ (newer)
        # or Source/SwiftLintFramework/Rules/ (older)
        for rules_subdir in [
            "Source/SwiftLintBuiltInRules/Rules",
            "Source/SwiftLintFramework/Rules",
        ]:
            rules_dir = os.path.join(self.clone_dir, rules_subdir)
            if os.path.isdir(rules_dir):
                count += self._walk_rules(rules_dir)

        logger.info(f"[swiftlint] Processed {count} rules")

    def _walk_rules(self, rules_dir):
        count = 0
        for root, dirs, files in os.walk(rules_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".swift"):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_rule_file(fpath, rel_path)
        return count

    def _parse_rule_file(self, fpath, rel_path):
        """Parse a Swift rule file for RuleDescription fields."""
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract identifier, name, description from RuleDescription
        id_match = re.search(r'identifier:\s*"([^"]+)"', content)
        name_match = re.search(r'name:\s*"([^"]+)"', content)
        desc_match = re.search(r'description:\s*"([^"]+)"', content)

        if not id_match:
            return 0

        rule_id = id_match.group(1)
        name = name_match.group(1) if name_match else rule_id
        description = desc_match.group(1) if desc_match else ""

        # Extract severity from SeverityConfiguration
        severity = "medium"
        sev_match = re.search(
            r'SeverityConfiguration[^.]*\(\.(\w+)\)', content
        )
        if sev_match:
            sev_raw = sev_match.group(1).lower()
            if sev_raw == "error":
                severity = "high"
            elif sev_raw == "warning":
                severity = "medium"

        # Extract kind/category
        kind_match = re.search(r'kind:\s*\.(\w+)', content)
        category = kind_match.group(1) if kind_match else "lint"

        # Extract deprecated/replaced info
        deprecated = "deprecated" in content.lower()

        tags = ["swiftlint", "swift", "sast", category]
        if deprecated:
            tags.append("deprecated")

        self.upsert(
            rule_id=f"swiftlint:{rule_id}",
            title=name[:500],
            description=description,
            severity=severity,
            category=category,
            language="swift",
            cwe_ids=[],
            tags=tags,
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="swift",
            metadata={
                "swiftlint_id": rule_id,
                "kind": category,
                "deprecated": deprecated,
            },
        )
        return 1