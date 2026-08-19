"""Collector for eslint-plugin-react-hooks rules.

Collects rules from the official React Hooks ESLint plugin, which lives
in the facebook/react monorepo under packages/eslint-plugin-react-hooks.

Three categories of rules:
1. Static rules (2): rules-of-hooks, exhaustive-deps — in src/rules/*.ts
2. Deprecated rule (1): component-hook-factories — in index.ts
3. React Compiler lint rules (~21): dynamically generated from the
   ErrorCategory enum in the babel-plugin-react-compiler package.

Source: https://react.dev/reference/eslint-plugin-react-hooks
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

# Compiler rule severity mapping
COMPILER_SEVERITY_MAP = {
    "Error": "high",
    "Warn": "medium",
    "Off": "low",
}


class ReactHooksESLintCollector(BaseCollector):
    name = "react-hooks-eslint"
    display_name = "ESLint React Hooks"
    source_type = "github"
    source_url = "https://github.com/facebook/react.git"
    description = (
        "Official React Hooks ESLint plugin from Meta/React team. "
        "Includes rules-of-hooks (enforces Rules of Hooks), "
        "exhaustive-deps (verifies hook dependency arrays), and "
        "React Compiler lint rules (immutability, purity, refs, "
        "globals, effect dependencies, state management, etc)."
    )
    logo_url = "https://avatars.githubusercontent.com/u/69631"

    # Path to the compiler package within the monorepo
    COMPILER_PATH = "compiler/packages/babel-plugin-react-compiler/src/CompilerError.ts"

    def collect_rules(self):
        count = 0

        # Phase 1: Static rules from src/rules/*.ts
        count += self._collect_static_rules()

        # Phase 2: Deprecated rule from index.ts
        count += self._collect_deprecated_rules()

        # Phase 3: React Compiler lint rules from CompilerError.ts
        count += self._collect_compiler_rules()

        logger.info(f"[react-hooks-eslint] Processed {count} rules")

    def _collect_static_rules(self):
        """Collect rules-of-hooks and exhaustive-deps from src/rules/."""
        count = 0
        rules_dir = os.path.join(
            self.clone_dir,
            "packages", "eslint-plugin-react-hooks", "src", "rules",
        )
        if not os.path.isdir(rules_dir):
            logger.warning("[react-hooks-eslint] src/rules directory not found")
            return 0

        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith(".ts"):
                continue

            fpath = os.path.join(rules_dir, fname)
            rule_name = fname.replace(".ts", "").lower().replace("_", "-")

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            meta = self._parse_static_rule_meta(content)
            description = meta.get("description") or f"React Hooks rule: {rule_name}"
            rule_type = meta.get("type") or "suggestion"
            severity = SEVERITY_MAP.get(rule_type, "medium")

            tags = ["react-hooks", "react", "eslint", "sast"]
            if meta.get("deprecated"):
                tags.append("deprecated")
            if meta.get("recommended"):
                tags.append("recommended")

            metadata = {
                "rule_type": rule_type,
                "recommended": meta.get("recommended", False),
                "fixable": meta.get("fixable", False),
                "has_suggestions": meta.get("has_suggestions", False),
                "source": "eslint-plugin-react-hooks",
            }

            self.upsert(
                rule_id=f"react-hooks/{rule_name}",
                title=description[:500],
                description=description,
                severity=severity,
                category="react-hooks-linting",
                language="javascript",
                tags=tags,
                source_file=os.path.relpath(fpath, self.clone_dir),
                rule_content=content[:50000],
                rule_format="typescript",
                metadata=metadata,
            )
            count += 1

        return count

    def _collect_deprecated_rules(self):
        """Collect deprecated rules defined in index.ts."""
        index_path = os.path.join(
            self.clone_dir,
            "packages", "eslint-plugin-react-hooks", "src", "index.ts",
        )
        if not os.path.exists(index_path):
            return 0

        try:
            with open(index_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0

        # Find deprecated rule names and their removed-in version
        # Pattern: 'component-hook-factories': makeDeprecatedRule('7.1.0')
        deprecated_m = re.finditer(
            r"'([a-z-]+)':\s*makeDeprecatedRule\(['\"]([^'\"]+)['\"]\)",
            content,
        )
        for m in deprecated_m:
            rule_name = m.group(1)
            removed_in = m.group(2)
            description = f"Deprecated: this rule has been removed in {removed_in}."

            self.upsert(
                rule_id=f"react-hooks/{rule_name}",
                title=description[:500],
                description=description,
                severity="low",
                category="react-hooks-linting",
                language="javascript",
                tags=["react-hooks", "react", "eslint", "sast", "deprecated"],
                source_file=os.path.relpath(index_path, self.clone_dir),
                rule_content=content[:50000],
                rule_format="typescript",
                metadata={
                    "rule_type": "suggestion",
                    "deprecated": True,
                    "removed_in": removed_in,
                    "source": "eslint-plugin-react-hooks",
                },
            )
            count += 1

        return count

    def _collect_compiler_rules(self):
        """Collect React Compiler lint rules from CompilerError.ts.

        These rules are dynamically generated from the ErrorCategory enum
        via getRuleForCategoryImpl(). We parse the switch cases to extract
        rule name, description, severity, and preset for each category.
        """
        compiler_path = os.path.join(self.clone_dir, self.COMPILER_PATH)
        if not os.path.exists(compiler_path):
            logger.warning("[react-hooks-eslint] CompilerError.ts not found")
            return 0

        try:
            with open(compiler_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0

        # Parse getRuleForCategoryImpl switch cases.
        # Each case block looks like:
        #   case ErrorCategory.CapitalizedCalls: {
        #     return {
        #       category,
        #       severity: ErrorSeverity.Error,
        #       name: 'capitalized-calls',
        #       description: 'Validates against calling...',
        #       preset: LintRulePreset.Off,
        #     };
        #   }
        # We need to handle multi-line descriptions (string concatenation).

        # Extract the getRuleForCategoryImpl function body
        func_match = re.search(
            r"function getRuleForCategoryImpl\(.*?\{(.*?)\n\}",
            content,
            re.DOTALL,
        )
        if not func_match:
            logger.warning("[react-hooks-eslint] getRuleForCategoryImpl not found")
            return 0

        func_body = func_match.group(1)

        # Find each return { ... name, description, severity, preset } block
        block_pattern = re.compile(
            r"return\s*\{[^}]*?"
            r"severity:\s*ErrorSeverity\.(\w+)[^}]*?"
            r"name:\s*'([^']+)'[^}]*?"
            r"description:\s*'([^']+)'"
            r"(?:[^}]*?preset:\s*LintRulePreset\.(\w+))?",
            re.DOTALL,
        )

        for m in block_pattern.finditer(func_body):
            severity_str = m.group(1)
            rule_name = m.group(2)
            description = m.group(3)
            preset = m.group(4) or "Off"

            severity = COMPILER_SEVERITY_MAP.get(severity_str, "medium")

            tags = ["react-hooks", "react", "eslint", "sast", "react-compiler"]
            if preset == "Recommended":
                tags.append("recommended")

            metadata = {
                "rule_type": "problem",
                "severity_raw": severity_str,
                "preset": preset,
                "category": rule_name,
                "source": "react-compiler",
            }

            self.upsert(
                rule_id=f"react-hooks/{rule_name}",
                title=description[:500],
                description=description,
                severity=severity,
                category="react-hooks-linting",
                language="javascript",
                tags=tags,
                source_file=self.COMPILER_PATH,
                rule_content=content[:50000],
                rule_format="typescript",
                metadata=metadata,
            )
            count += 1

        return count

    def _parse_static_rule_meta(self, content):
        """Extract metadata from a static rule file."""
        meta = {}

        # Extract description
        desc_m = re.search(
            r"description\s*:\s*['\"`]([^'\"`]+)['\"`]", content
        )
        if desc_m:
            meta["description"] = desc_m.group(1)

        # Extract type
        type_m = re.search(r"type\s*:\s*['\"](\w+)['\"]", content)
        if type_m:
            meta["type"] = type_m.group(1)

        # Extract recommended flag
        if re.search(r"recommended\s*:\s*true", content):
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

        return meta