"""Collector for Hadolint Dockerfile linter rules.

Hadolint is a Dockerfile linter that checks for best practices,
common mistakes, and style issues in Dockerfiles.
Rules are defined in Haskell files with DLxxxx codes.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "DLErrorC": "high",
    "DLWarningC": "medium",
    "DLInfoC": "low",
    "DLStyleC": "low",
    "DLIgnoreC": "info",
}


class HadolintCollector(BaseCollector):
    name = "hadolint"
    display_name = "Hadolint"
    source_type = "github"
    source_url = "https://github.com/hadolint/hadolint.git"
    description = (
        "Hadolint is a Dockerfile linter that enforces best practices, "
        "detects common mistakes, and checks style conventions. "
        "Covers shell commands, base images, labels, and Dockerfile syntax."
    )
    logo_url = "https://avatars.githubusercontent.com/u/28815823"

    def collect_rules(self):
        count = 0

        # Hadolint rules are in src/Hadolint/Rule/ (note: singular "Rule")
        rules_dir = os.path.join(self.clone_dir, "src", "Hadolint", "Rule")

        if not os.path.isdir(rules_dir):
            # Try alternate path
            rules_dir = os.path.join(self.clone_dir, "src", "Hadolint", "Rules")
            if not os.path.isdir(rules_dir):
                logger.warning("[hadolint] Rules directory not found")
                return

        for fname in os.listdir(rules_dir):
            if not fname.endswith(".hs"):
                continue
            # Skip Shellcheck.hs — it wraps shellcheck rules, not DL rules
            if fname.lower() == "shellcheck.hs":
                continue
            if not fname.startswith("DL"):
                continue

            fpath = os.path.join(rules_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)
            count += self._parse_rule_file(fpath, rel_path)

        logger.info(f"[hadolint] Processed {count} rules")

    def _parse_rule_file(self, fpath, rel_path):
        """Parse a Hadolint Haskell rule file."""
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract code, severity, and message
        code_match = re.search(r'code\s*=\s*"(DL\d+)"', content)
        sev_match = re.search(r'severity\s*=\s*(DL\w+C)', content)
        msg_match = re.search(
            r'message\s*=\s*"((?:[^"\\]|\\.)*)"', content
        )

        # Some files use helper functions like dl3001 = simpleRule...
        if not code_match:
            # Try to extract code from filename
            code_match = re.match(r"(DL\d+)", os.path.basename(fpath))
            if code_match:
                code_match = type("M", (), {"group": lambda self, n: os.path.basename(fpath).replace(".hs", "")})()

        if not code_match:
            return 0

        rule_id = code_match.group(1) if hasattr(code_match, 'group') else os.path.basename(fpath).replace(".hs", "")
        severity_raw = sev_match.group(1) if sev_match else "DLWarningC"
        message = msg_match.group(1) if msg_match else ""

        # Clean up escaped characters in message
        message = message.replace("\\n", " ").replace('\\"', '"')
        severity = SEVERITY_MAP.get(severity_raw, "medium")

        self.upsert(
            rule_id=f"hadolint:{rule_id}",
            title=message[:500] if message else f"Hadolint {rule_id}",
            description=message,
            severity=severity,
            category="dockerfile",
            language="dockerfile",
            cwe_ids=[],
            tags=["hadolint", "dockerfile", "linter", severity_raw.lower()],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="haskell",
            metadata={
                "hadolint_code": rule_id,
                "severity_raw": severity_raw,
            },
        )
        return 1