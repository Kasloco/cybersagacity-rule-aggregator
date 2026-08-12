"""Collector for PHPStan PHP static analysis rules.

PHPStan is a PHP static analysis tool that finds bugs without running code.
The actual rules are in the phpstan-src repo (phpstan/phpstan is a wrapper).
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class PHPStanCollector(BaseCollector):
    name = "phpstan"
    display_name = "PHPStan"
    source_type = "github"
    source_url = "https://github.com/phpstan/phpstan-src.git"
    description = (
        "PHPStan finds bugs in PHP code without actually running it. "
        "Covers type checking, dead code detection, undefined variables, "
        "incorrect function calls, and coding standard violations."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1990057"

    def collect_rules(self):
        count = 0

        # PHPStan rules are in src/Rules/ as PHP files
        rules_dir = os.path.join(self.clone_dir, "src", "Rules")

        if not os.path.isdir(rules_dir):
            # Try alternate paths
            for alt in [
                os.path.join(self.clone_dir, "src"),
                os.path.join(self.clone_dir, "rules"),
            ]:
                if os.path.isdir(alt):
                    rules_dir = alt
                    break
            else:
                logger.warning("[phpstan] Rules directory not found")
                return

        for root, dirs, files in os.walk(rules_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".php") or fname.startswith("_"):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_rule_file(fpath, rel_path)

        logger.info(f"[phpstan] Processed {count} rules")

    def _parse_rule_file(self, fpath, rel_path):
        """Parse a PHPStan rule PHP file."""
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract class name (rule identifier)
        class_match = re.search(r'class\s+(\w+)', content)
        if not class_match:
            return 0

        class_name = class_match.group(1)

        # Extract description from docblock
        docblock_match = re.search(r'/\*\*\s*\n(.*?)\*/', content, re.DOTALL)
        description = ""
        if docblock_match:
            docblock = docblock_match.group(1)
            lines = [
                line.strip().lstrip("*").strip()
                for line in docblock.split("\n")
                if line.strip() and not line.strip().startswith("@")
            ]
            description = " ".join(lines)[:2000]

        # Derive rule identifier from class name
        # PHPStan uses patterns like: FinalClassRule -> class.final
        rule_id = re.sub(
            r'([a-z])([A-Z])', r'\1.\2', class_name
        ).lower().replace("_rule", "").replace("rule", "")

        # Determine severity from class content
        severity = "medium"
        if "Error" in class_name or "error" in content[:500].lower():
            severity = "high"
        elif "Warning" in class_name:
            severity = "medium"
        elif "Info" in class_name:
            severity = "low"

        # Category from subdirectory
        category = os.path.basename(os.path.dirname(fpath)).lower()

        self.upsert(
            rule_id=f"phpstan:{rule_id}",
            title=class_name,
            description=description or f"PHPStan rule: {class_name}",
            severity=severity,
            category=category if category else "php",
            language="php",
            cwe_ids=[],
            tags=["phpstan", "php", "sast", category] if category else ["phpstan", "php", "sast"],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="php",
            metadata={
                "class_name": class_name,
                "rule_id": rule_id,
            },
        )
        return 1