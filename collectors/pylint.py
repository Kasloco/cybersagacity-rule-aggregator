"""Collector for Pylint rules (PyCQA).

Pylint is a Python static analysis tool that checks for errors,
enforces coding standards, and looks for code smells.
"""

import os
import re
import ast
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Pylint message ID first letter = category
CATEGORY_MAP = {
    "C": ("convention", "low"),
    "R": ("refactor", "low"),
    "W": ("warning", "medium"),
    "E": ("error", "high"),
    "F": ("fatal", "critical"),
    "I": ("info", "info"),
}


class PylintCollector(BaseCollector):
    name = "pylint"
    display_name = "Pylint"
    source_type = "github"
    source_url = "https://github.com/pylint-dev/pylint.git"
    description = (
        "Pylint analyzes Python code for errors, enforces coding standards, "
        "detects code smells, and checks for formatting issues. "
        "Covers conventions, refactoring, warnings, errors, and fatal issues."
    )
    logo_url = "https://avatars.githubusercontent.com/u/8749848"

    def collect_rules(self):
        count = 0

        # Pylint checks are in pylint/checkers/ as Python files
        checkers_dir = os.path.join(self.clone_dir, "pylint", "checkers")
        if not os.path.isdir(checkers_dir):
            # Try alternate path
            checkers_dir = os.path.join(self.clone_dir, "checkers")
            if not os.path.isdir(checkers_dir):
                logger.warning("[pylint] Checkers directory not found")
                return

        for fname in os.listdir(checkers_dir):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            fpath = os.path.join(checkers_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)
            count += self._parse_checker(fpath, rel_path)

        logger.info(f"[pylint] Processed {count} rules")

    def _parse_checker(self, fpath, rel_path):
        """Parse a Pylint checker file for message definitions."""
        count = 0

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Pylint defines messages as dicts: msgs = {"W1201": (msg, symbol, desc, ...), ...}
        # Use regex to find message ID definitions
        # Pattern: "X####":  (or 'X####':  )
        msg_pattern = re.compile(
            r'["\']([CEFIRW]\d{4})["\']\s*:\s*\(\s*'
            r'["\']((?:[^"\'\\]|\\.)*)["\']\s*,\s*'  # short message
            r'["\']((?:[^"\'\\]|\\.)*)["\']'  # symbol name
        )

        for match in msg_pattern.finditer(content):
            msg_id = match.group(1)
            message = match.group(2)
            symbol = match.group(3)

            # Category and severity from first letter
            first_letter = msg_id[0]
            category, severity = CATEGORY_MAP.get(
                first_letter, ("unknown", "medium")
            )

            rule_id = f"pylint:{msg_id}"

            self.upsert(
                rule_id=rule_id,
                title=symbol.replace("_", " ").title()[:500],
                description=message[:2000],
                severity=severity,
                category=category,
                language="python",
                cwe_ids=[],
                tags=["pylint", "python", "sast", category],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="python",
                metadata={
                    "pylint_id": msg_id,
                    "symbol": symbol,
                    "category_letter": first_letter,
                },
            )
            count += 1

        return count