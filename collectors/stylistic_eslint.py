"""Collector for @stylistic/eslint-plugin rules.

Collects all formatting/stylistic rules from the ESLint Stylistic
project (~96 rules). Each rule lives in its own subdirectory under
packages/eslint-plugin/rules/<rule-name>/<rule-name>.ts and uses a
createRule({ name, meta: { type, docs: { description } } }) pattern.

Source: https://eslint.style/rules
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "problem": "high",
    "suggestion": "medium",
    "layout": "low",
}


class StylisticESLintCollector(BaseCollector):
    name = "stylistic-eslint"
    display_name = "ESLint @stylistic"
    source_type = "github"
    source_url = "https://github.com/eslint-stylistic/eslint-stylistic.git"
    description = (
        "@stylistic/eslint-plugin: ~96 formatting and stylistic rules "
        "for JavaScript, TypeScript, and JSX. Includes spacing, "
        "indentation, line breaks, brackets, quotes, semicolons, and "
        "operators. These rules were moved out of ESLint core into "
        "this plugin as part of the formatting rules deprecation."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6019716"

    def collect_rules(self):
        count = 0
        rules_dir = os.path.join(
            self.clone_dir, "packages", "eslint-plugin", "rules"
        )
        if not os.path.isdir(rules_dir):
            logger.warning("[stylistic-eslint] rules directory not found")
            return

        for entry in sorted(os.listdir(rules_dir)):
            entry_path = os.path.join(rules_dir, entry)
            if not os.path.isdir(entry_path):
                continue

            # Each rule is a directory with <rule-name>.ts inside
            rule_file = os.path.join(entry_path, f"{entry}.ts")
            if not os.path.exists(rule_file):
                # Some rules may have index.ts instead
                rule_file = os.path.join(entry_path, "index.ts")
                if not os.path.exists(rule_file):
                    continue

            rule_name = entry

            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            meta = self._parse_rule_meta(content, rule_name)
            description = (
                meta.get("description")
                or f"@stylistic rule: {rule_name}"
            )
            rule_type = meta.get("type") or "layout"
            severity = SEVERITY_MAP.get(rule_type, "low")

            tags = ["stylistic", "eslint", "formatting", "sast"]
            if meta.get("deprecated"):
                tags.append("deprecated")

            metadata = {
                "rule_type": rule_type,
                "fixable": meta.get("fixable", False),
                "source": "@stylistic/eslint-plugin",
            }

            self.upsert(
                rule_id=f"stylistic/{rule_name}",
                title=description[:500],
                description=description,
                severity=severity,
                category="javascript-formatting",
                language="javascript",
                tags=tags,
                source_file=os.path.relpath(rule_file, self.clone_dir),
                rule_content=content[:50000],
                rule_format="typescript",
                metadata=metadata,
            )
            count += 1

        logger.info(f"[stylistic-eslint] Processed {count} rules")

    def _parse_rule_meta(self, content, rule_name):
        """Extract metadata from a @stylistic rule file."""
        meta = {}

        # Extract description from docs: { description: '...' }
        desc_m = re.search(
            r"description\s*:\s*['\"`]([^'\"`]+)['\"`]", content
        )
        if desc_m:
            meta["description"] = desc_m.group(1)

        # Extract type (problem, suggestion, layout)
        type_m = re.search(r"type\s*:\s*['\"](\w+)['\"]", content)
        if type_m:
            meta["type"] = type_m.group(1)

        # Extract fixable flag
        if re.search(r"fixable\s*:\s*['\"]\w+['\"]", content):
            meta["fixable"] = True

        # Extract deprecated flag
        if re.search(r"deprecated\s*:\s*true", content):
            meta["deprecated"] = True

        return meta