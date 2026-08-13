"""Collector for dlint (Python security linter) rules.

dlint is a flake8 plugin that scans Python code for insecure patterns.
Rules use DUOxxx codes and are defined in dlint/linters/ as Python classes
with _code and _error_tmpl class attributes.
"""

import os
import re
import ast
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class DlintCollector(BaseCollector):
    name = "dlint"
    display_name = "dlint"
    source_type = "github"
    source_url = "https://github.com/dlint-py/dlint.git"
    description = (
        "dlint is a flake8 plugin that scans Python code for insecure "
        "patterns including dangerous builtins (eval, exec), insecure module "
        "usage (pickle, marshal, yaml), weak crypto, and more. Rules use "
        "DUOxxx codes."
    )
    logo_url = "https://avatars.githubusercontent.com/u/44328851"

    def collect_rules(self):
        count = 0

        linters_dir = os.path.join(self.clone_dir, "dlint", "linters")
        if not os.path.isdir(linters_dir):
            logger.warning("[dlint] linters directory not found")
            return

        for root, dirs, files in os.walk(linters_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in sorted(files):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                if fname in ("base.py",):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_linter_file(fpath, rel_path)

        logger.info(f"[dlint] Processed {count} rules")

    def _parse_linter_file(self, fpath, rel_path):
        """Parse a dlint linter file for rule metadata.

        Each linter class defines:
          _code = 'DUOxxx'        -- rule ID
          _error_tmpl = 'message'  -- the error message (includes the code)
          off_by_default = False  -- whether the rule is disabled by default
          class docstring         -- human-readable description
        """
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract the DUO code
        code_match = re.search(r"_code\s*=\s*['\"]([^'\"]+)['\"]", content)
        if not code_match:
            return 0
        rule_code = code_match.group(1)

        # Extract the error template (the full message including code prefix)
        tmpl_match = re.search(
            r"_error_tmpl\s*=\s*'([^']+)'", content
        )
        if not tmpl_match:
            tmpl_match = re.search(
                r'_error_tmpl\s*=\s*"([^"]+)"', content
            )
        error_tmpl = tmpl_match.group(1) if tmpl_match else ""

        # Extract off_by_default
        off_match = re.search(r"off_by_default\s*=\s*(True|False)", content)
        off_by_default = off_match.group(1) == "True" if off_match else False

        # Extract class docstring for description
        description = ""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    doc = ast.get_docstring(node)
                    if doc:
                        description = doc.strip()
                        break
        except Exception:
            pass

        # If no docstring, use the error template as description
        if not description:
            description = error_tmpl

        # The title is the error template (which includes the DUO code)
        # or fall back to the code itself
        title = error_tmpl if error_tmpl else f"dlint {rule_code}"
        if len(title) > 500:
            title = title[:500]

        # dlint doesn't have severity levels — all rules are security checks
        # Use "medium" as default severity since dlint flags insecure patterns
        severity = "medium"

        # Derive category from the linter file name
        fname = os.path.basename(fpath).replace(".py", "")
        if fname.startswith("bad_"):
            category = fname.replace("bad_", "").replace("_use", "")
        else:
            category = "security"

        self.upsert(
            rule_id=rule_code,
            title=title,
            description=description[:2000],
            severity=severity,
            category=category,
            language="python",
            cwe_ids=[],
            tags=["dlint", "python", "sast", "flake8", category],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="python",
            metadata={
                "dlint_code": rule_code,
                "error_template": error_tmpl,
                "off_by_default": off_by_default,
            },
        )
        return 1