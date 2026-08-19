"""Collector for @typescript-eslint/eslint-plugin rules.

Collects all rules from the typescript-eslint monorepo (134+ rules).
Rules live in packages/eslint-plugin/src/rules/*.ts and use a
createRule({ name, meta: { type, docs: { description } } }) pattern.

Source: https://typescript-eslint.io/rules/
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


class TypeScriptESLintCollector(BaseCollector):
    name = "typescript-eslint"
    display_name = "TypeScript-ESLint"
    source_type = "github"
    source_url = "https://github.com/typescript-eslint/typescript-eslint.git"
    description = (
        "@typescript-eslint/eslint-plugin: 134+ rules for TypeScript "
        "linting including type-aware rules (no-floating-promises, "
        "no-misused-promises, no-unsafe-*), best practices, and "
        "TypeScript-specific patterns (no-explicit-any, prefer-readonly, "
        "consistent-type-definitions, naming-convention, etc)."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6019716"

    def collect_rules(self):
        count = 0
        rules_dir = os.path.join(
            self.clone_dir, "packages", "eslint-plugin", "src", "rules"
        )
        if not os.path.isdir(rules_dir):
            logger.warning("[typescript-eslint] rules directory not found")
            return

        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith(".ts"):
                continue

            fpath = os.path.join(rules_dir, fname)
            if os.path.isdir(fpath):
                continue

            rule_name = fname.replace(".ts", "")
            if rule_name == "index":
                continue

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            meta = self._parse_rule_meta(content, rule_name)
            description = (
                meta.get("description")
                or f"TypeScript-ESLint rule: {rule_name}"
            )
            rule_type = meta.get("type") or "suggestion"
            severity = SEVERITY_MAP.get(rule_type, "medium")

            tags = ["typescript-eslint", "typescript", "eslint", "sast"]
            if meta.get("recommended"):
                tags.append("recommended")
            if meta.get("deprecated"):
                tags.append("deprecated")

            metadata = {
                "rule_type": rule_type,
                "recommended": meta.get("recommended", False),
                "fixable": meta.get("fixable", False),
                "has_suggestions": meta.get("has_suggestions", False),
                "source": "typescript-eslint",
            }
            if meta.get("replaced_by"):
                metadata["replacedBy"] = meta["replaced_by"]

            self.upsert(
                rule_id=f"typescript-eslint/{rule_name}",
                title=description[:500],
                description=description,
                severity=severity,
                category="typescript-linting",
                language="typescript",
                tags=tags,
                source_file=os.path.relpath(fpath, self.clone_dir),
                rule_content=content[:50000],
                rule_format="typescript",
                metadata=metadata,
            )
            count += 1

        logger.info(f"[typescript-eslint] Processed {count} rules")

    def _parse_rule_meta(self, content, rule_name):
        """Extract metadata from a TypeScript-ESLint rule file."""
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

        # Extract recommended flag
        rec_m = re.search(r"recommended\s*:\s*['\"](\w+)['\"]", content)
        if rec_m:
            meta["recommended"] = rec_m.group(1) in ("recommended", "strict", "stylistic", "true")
        elif re.search(r"recommended\s*:\s*true", content):
            meta["recommended"] = True

        # Extract fixable flag
        if re.search(r"fixable\s*:\s*['\"]\w+['\"]", content):
            meta["fixable"] = True

        # Extract hasSuggestions flag
        if re.search(r"hasSuggestions\s*:\s*true", content):
            meta["has_suggestions"] = True

        # Extract deprecated flag
        if re.search(r"deprecated\s*:\s*true", content):
            meta["deprecated"] = True

        # Extract replacedBy
        replaced_m = re.search(
            r"replacedBy\s*:\s*\[([^\]]*)\]", content, re.DOTALL
        )
        if replaced_m:
            replaced_names = re.findall(
                r"['\"]([^'\"]+)['\"]", replaced_m.group(1)
            )
            if replaced_names:
                meta["replaced_by"] = replaced_names

        return meta