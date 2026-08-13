"""Collector for ESLint rules.

Collects rules from two sources:
1. The main ESLint repository (eslint/eslint) — all core linting rules
   including active, deprecated, and removed rules (312+ rules).
2. The eslint-plugin-security repository — 14 Node.js security-specific
   rules (eval detection, child_process injection, prototype pollution, etc).

The main ESLint repo provides:
  - lib/rules/*.js — 293 active rule definitions with meta blocks
  - docs/src/_data/rules.json — structured data for all 312 rules
    (active + deprecated + removed), including descriptions and replacements
  - docs/src/rules/*.md — documentation for each rule

The security plugin provides rules in rules/*.js with create() functions.
"""

import os
import re
import json
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Maps ESLint rule `type` (meta.type) to our severity
SEVERITY_MAP = {
    "problem": "high",
    "suggestion": "medium",
    "layout": "low",
}


class ESLintSecurityCollector(BaseCollector):
    name = "eslint_security"
    display_name = "ESLint Security"
    source_type = "github"
    # Primary source: main ESLint repo with all core rules.
    source_url = "https://github.com/eslint/eslint.git"
    description = (
        "ESLint pluggable JavaScript/TypeScript linter. Collects all core "
        "ESLint rules (active, deprecated, and removed) plus the "
        "eslint-plugin-security rules for Node.js security (eval usage, "
        "child_process injection, non-literal require/RegExp, prototype "
        "pollution, timing attacks)."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6019716"

    # Secondary source: eslint-plugin-security for additional security rules.
    SECURITY_PLUGIN_URL = "https://github.com/eslint-community/eslint-plugin-security.git"

    def collect_rules(self):
        count = 0

        # --- Phase 1: Collect from the main ESLint repo (lib/rules + docs data) ---
        count += self._collect_eslint_core_rules()

        # --- Phase 2: Collect from eslint-plugin-security ---
        count += self._collect_security_plugin_rules()

        logger.info(f"[eslint_security] Processed {count} rules total")

    # -------------------------------------------------------------------------
    # Main ESLint repo
    # -------------------------------------------------------------------------

    def _collect_eslint_core_rules(self):
        """Collect all rules from the main ESLint repository."""
        count = 0

        # Parse rules.json for structured metadata (descriptions, categories,
        # deprecated/removed status, replacements).
        rules_data = self._load_rules_json()
        rules_meta = self._load_rules_meta_json()

        # Walk lib/rules/*.js for active rule implementations.
        rules_dir = os.path.join(self.clone_dir, "lib", "rules")
        if not os.path.isdir(rules_dir):
            logger.warning("[eslint_security] lib/rules directory not found")
        else:
            for fname in sorted(os.listdir(rules_dir)):
                if not fname.endswith(".js"):
                    continue
                rule_name = fname.replace(".js", "")
                if rule_name == "index":
                    continue

                fpath = os.path.join(rules_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue

                meta = self._parse_rule_meta(content, rule_name)
                doc_info = rules_data.get(rule_name, {})
                meta_json = rules_meta.get(rule_name, {})

                description = (
                    meta.get("description")
                    or doc_info.get("description")
                    or f"ESLint rule: {rule_name}"
                )
                rule_type = meta.get("type") or doc_info.get("type") or "suggestion"
                severity = SEVERITY_MAP.get(rule_type, "medium")
                deprecated = meta.get("deprecated", False) or doc_info.get("deprecated", False)

                tags = ["eslint", "javascript", "sast"]
                if deprecated:
                    tags.append("deprecated")

                metadata = {
                    "rule_type": rule_type,
                    "recommended": meta.get("recommended", False),
                    "fixable": meta.get("fixable", False),
                    "deprecated": deprecated,
                    "source": "eslint-core",
                }
                if meta.get("url"):
                    metadata["url"] = meta["url"]
                if meta.get("replaced_by"):
                    metadata["replacedBy"] = meta["replaced_by"]

                self.upsert(
                    rule_id=f"eslint/{rule_name}",
                    title=description[:500],
                    description=description,
                    severity=severity,
                    category="javascript-linting",
                    language="javascript",
                    tags=tags,
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="javascript",
                    metadata=metadata,
                )
                count += 1

        # Collect deprecated/removed rules that only exist in rules.json
        # (no JS file in lib/rules anymore — they were removed from the codebase).
        lib_rule_names = set()
        if os.path.isdir(rules_dir):
            lib_rule_names = {
                f.replace(".js", "") for f in os.listdir(rules_dir)
                if f.endswith(".js") and f != "index.js"
            }

        for rule_name, info in rules_data.items():
            if rule_name in lib_rule_names:
                continue  # Already collected from lib/rules

            description = info.get("description") or f"ESLint rule: {rule_name}"
            rule_type = info.get("type") or "suggestion"
            severity = SEVERITY_MAP.get(rule_type, "medium")
            status = info.get("status", "removed")

            tags = ["eslint", "javascript", "sast", status]
            metadata = {
                "rule_type": rule_type,
                "status": status,
                "source": "eslint-core",
            }
            if info.get("replaced_by"):
                metadata["replacedBy"] = info["replaced_by"]

            # Try to find the doc file for content
            doc_path = os.path.join(
                self.clone_dir, "docs", "src", "rules", f"{rule_name}.md"
            )
            rule_content = ""
            if os.path.exists(doc_path):
                try:
                    with open(doc_path, "r", encoding="utf-8") as f:
                        rule_content = f.read()[:50000]
                except Exception:
                    pass

            self.upsert(
                rule_id=f"eslint/{rule_name}",
                title=description[:500],
                description=description,
                severity=severity,
                category="javascript-linting",
                language="javascript",
                tags=tags,
                source_file=os.path.relpath(doc_path, self.clone_dir) if os.path.exists(doc_path) else "",
                rule_content=rule_content,
                rule_format="markdown",
                metadata=metadata,
            )
            count += 1

        return count

    def _load_rules_json(self):
        """Load and flatten docs/src/_data/rules.json into a {rule_name: info} dict."""
        rules_path = os.path.join(
            self.clone_dir, "docs", "src", "_data", "rules.json"
        )
        result = {}

        if not os.path.exists(rules_path):
            return result

        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"[eslint_security] Failed to parse rules.json: {e}")
            return result

        # Active rules grouped by type (problem, suggestion, layout)
        for rule_type, rules_list in data.get("types", {}).items():
            for rule in rules_list:
                name = rule.get("name", "")
                if name:
                    result[name] = {
                        "description": rule.get("description", ""),
                        "type": rule_type,
                        "recommended": rule.get("recommended", False),
                        "fixable": rule.get("fixable", False),
                        "hasSuggestions": rule.get("hasSuggestions", False),
                        "status": "active",
                    }

        # Deprecated rules
        for rule in data.get("deprecated", []):
            name = rule.get("name", "")
            if name:
                replaced_by = []
                for r in rule.get("replacedBy", []):
                    if isinstance(r, dict):
                        repl_name = r.get("rule", {}).get("name", "")
                        if repl_name:
                            replaced_by.append(repl_name)
                result[name] = {
                    "description": "",  # Deprecated rules in JSON don't have descriptions
                    "type": "suggestion",
                    "deprecated": True,
                    "status": "deprecated",
                    "replaced_by": replaced_by,
                }

        # Removed rules
        for rule in data.get("removed", []):
            name = rule.get("removed", "")
            if name:
                replaced_by = []
                for r in rule.get("replacedBy", []):
                    if isinstance(r, dict):
                        repl_name = r.get("rule", {}).get("name", "")
                        if repl_name:
                            replaced_by.append(repl_name)
                result[name] = {
                    "description": f"Removed ESLint rule: {name}",
                    "type": "suggestion",
                    "status": "removed",
                    "replaced_by": replaced_by,
                }

        return result

    def _load_rules_meta_json(self):
        """Load docs/src/_data/rules_meta.json for additional metadata."""
        meta_path = os.path.join(
            self.clone_dir, "docs", "src", "_data", "rules_meta.json"
        )
        if not os.path.exists(meta_path):
            return {}

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _parse_rule_meta(self, content, rule_name):
        """Extract metadata from an ESLint rule's module.exports meta block."""
        meta = {}

        # Extract description from meta.docs.description
        desc_m = re.search(
            r'description\s*:\s*["\']([^"\']+)["\']', content
        )
        if desc_m:
            meta["description"] = desc_m.group(1)

        # Extract type (problem, suggestion, layout)
        type_m = re.search(r'type\s*:\s*["\'](\w+)["\']', content)
        if type_m:
            meta["type"] = type_m.group(1)

        # Extract recommended flag
        if re.search(r'recommended\s*:\s*true', content):
            meta["recommended"] = True

        # Extract fixable flag
        if re.search(r'fixable\s*:\s*["\']\w+["\']', content):
            meta["fixable"] = True

        # Extract deprecated flag
        if re.search(r'deprecated\s*:\s*true', content):
            meta["deprecated"] = True

        # Extract docs URL
        url_m = re.search(r'url\s*:\s*["\']([^"\']+)["\']', content)
        if url_m:
            meta["url"] = url_m.group(1)

        # Extract replacedBy array
        replaced_m = re.search(
            r'replacedBy\s*:\s*\[([^\]]*)\]', content, re.DOTALL
        )
        if replaced_m:
            replaced_names = re.findall(r'name\s*:\s*["\']([^"\']+)["\']', replaced_m.group(1))
            if replaced_names:
                meta["replaced_by"] = replaced_names

        return meta

    # -------------------------------------------------------------------------
    # eslint-plugin-security
    # -------------------------------------------------------------------------

    def _collect_security_plugin_rules(self):
        """Collect rules from the eslint-plugin-security repository.

        This repo is cloned separately to a sibling directory.
        """
        import tempfile

        security_dir = os.path.join(
            os.path.dirname(self.clone_dir), "eslint_security_plugin"
        )

        # Clone if not present
        if not os.path.exists(os.path.join(security_dir, ".git")):
            import git
            os.makedirs(os.path.dirname(security_dir), exist_ok=True)
            logger.info("[eslint_security] Cloning eslint-plugin-security...")
            git.Repo.clone_from(
                self.SECURITY_PLUGIN_URL, security_dir,
                depth=1, single_branch=True,
            )

        rules_dir = os.path.join(security_dir, "rules")
        if not os.path.isdir(rules_dir):
            rules_dir = os.path.join(security_dir, "lib", "rules")
        if not os.path.isdir(rules_dir):
            logger.warning("[eslint_security] security plugin rules dir not found")
            return 0

        count = 0
        for fname in os.listdir(rules_dir):
            if not fname.endswith(".js"):
                continue

            fpath = os.path.join(rules_dir, fname)
            rel_path = os.path.relpath(fpath, security_dir)
            rule_name = fname.replace(".js", "")

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            # Extract description from meta
            description = ""
            desc_match = re.search(
                r'description\s*[:=]\s*["\']([^"\']+)["\']', content
            )
            if desc_match:
                description = desc_match.group(1)

            # Try to extract from docs
            doc_path = os.path.join(security_dir, "docs", "rules", f"{rule_name}.md")
            if os.path.exists(doc_path):
                try:
                    with open(doc_path, "r") as f:
                        doc_content = f.read()
                    lines = doc_content.split("\n")
                    for i, line in enumerate(lines):
                        if line.startswith("#"):
                            for j in range(i + 1, min(i + 10, len(lines))):
                                if lines[j].strip():
                                    description = lines[j].strip()
                                    break
                            break
                except Exception:
                    pass

            # Severity based on rule type
            high_severity = [
                "detect-eval-with-expression", "detect-child-process",
                "detect-non-literal-require", "detect-possible-timing-attacks",
            ]
            severity = "high" if rule_name in high_severity else "medium"

            title = rule_name.replace("detect-", "").replace("-", " ").title()
            if rule_name.startswith("detect-"):
                title = f"Detect {title}"

            self.upsert(
                rule_id=f"security/{rule_name}",
                title=title[:500],
                description=description or f"ESLint security rule: {rule_name}",
                severity=severity,
                category="javascript-security",
                language="javascript",
                tags=["eslint", "javascript", "nodejs", "sast", "security-plugin"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="javascript",
                metadata={"plugin": "eslint-plugin-security"},
            )
            count += 1

        return count