"""Collector for Flawfinder C/C++ security scanner rules."""

import os
import re
import ast
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Flawfinder embeds CWE identifiers inside the warning text, e.g.
#   "Does not check for buffer overflows ... (CWE-120)"
# or multiple: "(CWE-119!/ CWE-120)" / "(CWE-829, CWE-20)"
_CWE_RE = re.compile(r'CWE-(\d+)')

# Severity mapping: Flawfinder levels 1-5 → aggregator severity bands.
# Level 0 means "no risk" (informational only, e.g. input functions) and is
# still collected as "info".
_SEVERITY_MAP = {
    5: "high",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
    0: "info",
}


class FlawfinderCollector(BaseCollector):
    name = "flawfinder"
    display_name = "Flawfinder"
    source_type = "github"
    source_url = "https://github.com/david-a-wheeler/flawfinder.git"
    description = (
        "Simple C/C++ security scanner that searches source code for "
        "common dangerous functions. Detects buffer overflows, format string "
        "issues, race conditions, temporary file vulnerabilities, and more."
    )
    logo_url = "https://avatars.githubusercontent.com/u/0"  # no org avatar

    def collect_rules(self):
        count = 0
        src_path = os.path.join(self.clone_dir, "flawfinder.py")
        if not os.path.isfile(src_path):
            logger.warning(f"[flawfinder] flawfinder.py not found at {src_path}")
            return

        with open(src_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        rel_path = os.path.relpath(src_path, self.clone_dir)
        rules = self._parse_ruleset(source)

        for rule in rules:
            self.upsert(
                rule_id=rule["id"],
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                category=rule["category"],
                language="c",
                cwe_ids=rule.get("cwe_ids", []),
                tags=["flawfinder", "c", "c++", "sast"],
                source_file=rel_path,
                rule_content=rule.get("raw_entry", ""),
                rule_format="python",
                metadata=rule.get("metadata", {}),
            )
            count += 1

        logger.info(f"[flawfinder] Processed {count} rules")

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_ruleset(self, source):
        """Extract rule definitions from flawfinder.py's ``c_ruleset`` dict.

        The ruleset is a plain Python dict literal assigned to ``c_ruleset``
        near the top of the file.  Each entry has the shape::

            "function_name|alt_name": (
                hook_fn,            # index 0 – not needed for the DB
                level,              # index 1 – int 0-5
                warning,            # index 2 – human-readable description
                suggestion,         # index 3 – remediation text
                category,           # index 4 – e.g. "buffer", "race"
                url,                # index 5 – usually ""
                other_dict,         # index 6 – extra flags
                rule_id,            # index 7 – "FF1nnn"
            )

        We parse the file with :mod:`ast`, find the ``c_ruleset`` assignment,
        and walk every key/value pair so we don't have to import the module
        (which has side-effects at import time).
        """
        rules = []
        seen_ids = set()

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            logger.error(f"[flawfinder] Failed to parse flawfinder.py: {exc}")
            return rules

        # Locate the `c_ruleset = { ... }` top-level assignment.
        ruleset_node = None
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "c_ruleset":
                        ruleset_node = node.value
                        break
                if ruleset_node:
                    break

        if not isinstance(ruleset_node, ast.Dict):
            logger.warning("[flawfinder] c_ruleset dict not found in source")
            return rules

        for key_node, value_node in zip(ruleset_node.keys, ruleset_node.values):
            # Key: pipe-separated function names (string literal)
            key_str = self._ast_literal_str(key_node)
            if key_str is None:
                continue

            # Value: tuple — (hook, level, warning, suggestion, category, url, other, rule_id)
            fields = self._extract_tuple_fields(value_node)
            if fields is None:
                continue

            level, warning, suggestion, category, rule_id = fields
            function_names = [n.strip() for n in key_str.split("|") if n.strip()]
            primary_name = function_names[0] if function_names else key_str

            # Use the Flawfinder rule ID (FF1nnn) as the canonical ID.
            fid = rule_id if rule_id else f"flawfinder_{primary_name}"
            if fid in seen_ids:
                continue
            seen_ids.add(fid)

            cwe_ids = self._extract_cwe_ids(warning)
            severity = _SEVERITY_MAP.get(level, "info")

            description = warning or f"Flawfinder check for {primary_name}"
            if suggestion:
                description = f"{description} Suggestion: {suggestion}"

            # Build a human-readable title.
            title = f"Flawfinder {fid}: {primary_name}"

            # Reconstruct a compact raw-entry string for rule_content.
            raw_entry = self._reconstruct_raw_entry(
                key_str, level, warning, suggestion, category, rule_id
            )

            metadata = {
                "flawfinder_id": rule_id,
                "function_names": function_names,
                "level": level,
                "warning": warning,
                "suggestion": suggestion,
                "category": category,
            }

            rules.append({
                "id": fid,
                "title": title,
                "description": description,
                "severity": severity,
                "category": category or "c-security",
                "cwe_ids": cwe_ids,
                "raw_entry": raw_entry,
                "metadata": metadata,
            })

        return rules

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ast_literal_str(node: ast.AST) -> str | None:
        """Return the string value of an AST string-literal node, or None."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        # Python 3.7 compat
        if isinstance(node, ast.Str):  # type: ignore[attr-defined]
            return node.s  # type: ignore[union-attr]
        return None

    @staticmethod
    def _ast_literal_int(node: ast.AST) -> int | None:
        """Return the int value of an AST int-literal node, or None."""
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Num):  # type: ignore[attr-defined]
            return node.n  # type: ignore[union-attr]
        return None

    def _extract_tuple_fields(self, value_node: ast.AST) -> tuple | None:
        """Extract (level, warning, suggestion, category, rule_id) from a
        ruleset value tuple node.

        The tuple has 7 or 8 elements:
            (hook, level, warning, suggestion, category, url, other[, rule_id])
        Older entries may lack the ``rule_id`` element; we fall back to None.
        """
        if not isinstance(value_node, ast.Tuple):
            return None

        elts = value_node.elts
        if len(elts) < 7:
            return None

        # Indices:  0=hook, 1=level, 2=warning, 3=suggestion,
        #           4=category, 5=url, 6=other, 7=rule_id
        level_node = elts[1]
        raw_level = self._ast_literal_int(level_node)
        level: int = raw_level if raw_level is not None else self._safe_eval_int(level_node)

        warning: str = self._ast_literal_str(elts[2]) or ""
        suggestion: str = self._ast_literal_str(elts[3]) or ""
        category: str = self._ast_literal_str(elts[4]) or ""
        rule_id: str | None = None
        if len(elts) >= 8:
            rule_id = self._ast_literal_str(elts[7])

        return level, warning, suggestion, category, rule_id

    @staticmethod
    def _safe_eval_int(node: ast.AST) -> int:
        """Try to evaluate an AST node to an int, returning 1 on failure."""
        try:
            val = ast.literal_eval(node)
            return int(val) if isinstance(val, int) else 1
        except Exception:
            return 1

    @staticmethod
    def _extract_cwe_ids(warning):
        """Pull all CWE-NNN identifiers from a warning string."""
        return ["CWE-" + m for m in _CWE_RE.findall(warning)]

    @staticmethod
    def _reconstruct_raw_entry(key, level, warning, suggestion, category, rule_id):
        """Build a compact text representation of the rule for rule_content."""
        parts = [
            f"# Function(s): {key}",
            f"# Level: {level}",
            f"# Category: {category}",
            f"# Rule ID: {rule_id or 'N/A'}",
            f"# Warning: {warning}",
        ]
        if suggestion:
            parts.append(f"# Suggestion: {suggestion}")
        return "\n".join(parts)