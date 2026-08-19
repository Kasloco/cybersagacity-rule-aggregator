"""Collector for eslint-react (ESLint React) rules.

Collects all rules from the eslint-react project (~92 rules across
multiple sub-plugins: react-x, react-dom, react-jsx, react-web-api,
react-rsc, react-naming-convention, react-debug).

Each rule lives in a subdirectory under
plugins/eslint-plugin-*/src/rules/<rule-name>/<rule-name>.ts and
exports RULE_NAME and uses createRule({ meta: { type, docs: { description } } }).

Source: https://eslint-react.xyz/docs/rules
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

# Maps sub-plugin directory names to their rule_id prefix segment
SUB_PLUGIN_MAP = {
    "eslint-plugin-react-x": "react",
    "eslint-plugin-react-dom": "react-dom",
    "eslint-plugin-react-jsx": "react-jsx",
    "eslint-plugin-react-web-api": "react-web-api",
    "eslint-plugin-react-rsc": "react-rsc",
    "eslint-plugin-react-naming-convention": "react-naming-convention",
    "eslint-plugin-react-debug": "react-debug",
}


class ESLintReactCollector(BaseCollector):
    name = "eslint-react"
    display_name = "ESLint React"
    source_type = "github"
    source_url = "https://github.com/rel1cx/eslint-react.git"
    description = (
        "ESLint React (eslint-react.xyz): ~92 rules for React "
        "development including hooks rules, component patterns, "
        "DOM safety, RSC compatibility, naming conventions, JSX "
        "best practices, and web API leak detection. Covers "
        "react-x, react-dom, react-jsx, react-web-api, react-rsc, "
        "react-naming-convention, and react-debug sub-plugins."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6019716"

    def collect_rules(self):
        count = 0
        plugins_dir = os.path.join(self.clone_dir, "plugins")
        if not os.path.isdir(plugins_dir):
            logger.warning("[eslint-react] plugins directory not found")
            return

        for sub_dir_name in sorted(os.listdir(plugins_dir)):
            sub_plugin = SUB_PLUGIN_MAP.get(sub_dir_name)
            if not sub_plugin:
                continue

            rules_dir = os.path.join(
                plugins_dir, sub_dir_name, "src", "rules"
            )
            if not os.path.isdir(rules_dir):
                continue

            count += self._collect_from_subplugin(
                rules_dir, sub_plugin, self.clone_dir
            )

        logger.info(f"[eslint-react] Processed {count} rules")

    def _collect_from_subplugin(self, rules_dir, sub_plugin, clone_dir):
        """Collect rules from a single sub-plugin's rules directory."""
        count = 0

        for entry in sorted(os.listdir(rules_dir)):
            entry_path = os.path.join(rules_dir, entry)
            if not os.path.isdir(entry_path):
                continue

            # Each rule is a directory with <rule-name>.ts inside
            rule_file = os.path.join(entry_path, f"{entry}.ts")
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
                or f"ESLint React rule: {rule_name}"
            )
            rule_type = meta.get("type") or "suggestion"
            severity = SEVERITY_MAP.get(rule_type, "medium")

            tags = ["eslint-react", "react", "eslint", "sast", sub_plugin]
            if meta.get("deprecated"):
                tags.append("deprecated")

            metadata = {
                "rule_type": rule_type,
                "fixable": meta.get("fixable", False),
                "has_suggestions": meta.get("has_suggestions", False),
                "sub_plugin": sub_plugin,
                "source": "eslint-react",
            }

            rule_id = f"eslint-react/{sub_plugin}/{rule_name}"

            self.upsert(
                rule_id=rule_id,
                title=description[:500],
                description=description,
                severity=severity,
                category="react-linting",
                language="javascript",
                tags=tags,
                source_file=os.path.relpath(rule_file, clone_dir),
                rule_content=content[:50000],
                rule_format="typescript",
                metadata=metadata,
            )
            count += 1

        return count

    def _parse_rule_meta(self, content, rule_name):
        """Extract metadata from an ESLint React rule file."""
        meta = {}

        # Extract description from docs: { description: '...' }
        desc_m = re.search(
            r'description\s*:\s*["\']([^"\']+)["\']', content
        )
        if desc_m:
            meta["description"] = desc_m.group(1)

        # Extract type (problem, suggestion, layout)
        type_m = re.search(r'type\s*:\s*["\'](\w+)["\']', content)
        if type_m:
            meta["type"] = type_m.group(1)

        # Extract fixable flag
        if re.search(r'fixable\s*:\s*["\']\w+["\']', content):
            meta["fixable"] = True

        # Extract hasSuggestions flag
        if re.search(r"hasSuggestions\s*:\s*true", content):
            meta["has_suggestions"] = True

        # Extract deprecated flag
        if re.search(r"deprecated\s*:\s*true", content):
            meta["deprecated"] = True

        return meta