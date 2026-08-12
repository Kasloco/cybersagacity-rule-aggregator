"""Collector for Brakeman (Ruby/Rails security scanner) rules."""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Brakeman confidence levels → aggregator severity.
# Brakeman uses :high, :medium, :low, :weak.
CONFIDENCE_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "weak": "info",
}


class BrakemanCollector(BaseCollector):
    name = "brakeman"
    display_name = "Brakeman"
    source_type = "github"
    source_url = "https://github.com/presidentbeef/brakeman.git"
    description = (
        "Static analysis security scanner for Ruby on Rails. Detects SQL "
        "injection, XSS, mass assignment, command injection, unsafe "
        "deserialization, SSRF, and dozens of other Rails-specific "
        "vulnerabilities mapped to CWEs."
    )
    logo_url = "https://avatars.githubusercontent.com/u/10518617"

    def collect_rules(self):
        count = 0
        checks_dir = os.path.join(self.clone_dir, "lib", "brakeman", "checks")
        if not os.path.isdir(checks_dir):
            logger.warning(f"[brakeman] checks dir not found at {checks_dir}")
            return

        for fname in sorted(os.listdir(checks_dir)):
            if not fname.endswith(".rb"):
                continue
            # Skip base_check.rb and eol_check.rb — they are infrastructure,
            # not individual security checks.
            if fname in ("base_check.rb", "eol_check.rb"):
                continue

            fpath = os.path.join(checks_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            rules = self._parse_check_file(content, fname, rel_path)
            for rule in rules:
                self.upsert(
                    rule_id=rule["id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    category=rule["category"],
                    language="ruby",
                    cwe_ids=rule.get("cwe_ids", []),
                    tags=rule.get("tags", ["brakeman", "ruby", "rails", "sast"]),
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="ruby",
                    metadata=rule.get("metadata", {}),
                )
                count += 1

        logger.info(f"[brakeman] Processed {count} checks")

    def _parse_check_file(self, content, fname, rel_path):
        """Extract rule metadata from a Brakeman check Ruby file.

        Each check file defines a class that extends Brakeman::BaseCheck and
        registers itself via ``Brakeman::Checks.add self``.  Within the
        ``run_check`` method (or helpers), it calls ``warn`` with a hash
        containing ``:warning_code``, ``:warning_type``, ``:confidence``,
        ``:cwe_id``, and ``:message``.

        A single check file can emit multiple distinct warning codes (e.g.
        ``check_sql.rb`` emits ``:sql_injection`` and
        ``:sql_injection_limit_offset``), so we collect all unique warning
        codes and their associated metadata.
        """
        rules = []

        # -- Class name / check name --
        class_match = re.search(r"class\s+(?:Brakeman::)?(\w+)\s*<", content)
        class_name = class_match.group(1) if class_match else fname.replace(
            ".rb", ""
        ).replace("_", " ").title()

        # -- Description --
        desc_match = re.search(r'@description\s*=\s*"([^"]+)"', content)
        description = desc_match.group(1) if desc_match else class_name

        # -- Warning codes, types, CWEs, confidences, messages --
        # Brakeman's warn calls use :warning_code => :symbol_name
        warning_codes = re.findall(
            r':warning_code\s*=>\s*:([:\w]+)', content
        )
        if not warning_codes:
            # Some checks use the hash-rocket syntax with string keys
            warning_codes = re.findall(
                r':warning_code\s*=>\s*"([^"]+)"', content
            )

        warning_types = re.findall(r':warning_type\s*=>\s*"([^"]+)"', content)
        cwe_matches = re.findall(r':cwe_id\s*=>\s*\[([\d,\s]+)\]', content)
        confidence_matches = re.findall(
            r':confidence\s*=>\s*:(\w+)', content
        )
        # Also catch confidence assigned to a variable: confidence = :high
        var_confidences = re.findall(
            r'confidence\s*=\s*:(\w+)', content
        )

        # Combine all confidence values found
        all_confidences = confidence_matches + var_confidences
        # Pick the highest confidence (most severe)
        severity = self._pick_severity(all_confidences)

        # Parse CWE IDs - each cwe_id match can contain multiple comma-separated IDs
        cwe_ids = []
        for cwe_str in cwe_matches:
            for num in re.findall(r'\d+', cwe_str):
                cwe_id = f"CWE-{num}"
                if cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id)

        # Warning type (category)
        category = warning_types[0] if warning_types else "Security"

        if not warning_codes:
            # No warning_code found — create a single rule from the file
            rule_id = fname.replace(".rb", "").replace("check_", "")
            rules.append({
                "id": f"brakeman_{rule_id}",
                "title": f"{class_name}: {description}",
                "description": description,
                "severity": severity,
                "category": category,
                "cwe_ids": cwe_ids,
                "tags": ["brakeman", "ruby", "rails", "sast",
                         category.lower().replace(" ", "-")],
                "metadata": {
                    "class_name": class_name,
                    "warning_type": category,
                    "confidence_levels": list(set(all_confidences)),
                    "source_file": rel_path,
                },
            })
            return rules

        # Deduplicate warning codes, preserving order
        seen_codes = set()
        unique_codes = []
        for code in warning_codes:
            if code not in seen_codes:
                seen_codes.add(code)
                unique_codes.append(code)

        # Build a rule per unique warning code
        for idx, code in enumerate(unique_codes):
            wtype = (
                warning_types[idx] if idx < len(warning_types)
                else (warning_types[0] if warning_types else "Security")
            )
            cwe_for_rule = cwe_ids if idx == 0 else (
                cwe_ids[idx:idx + 1] if idx < len(cwe_ids) else []
            )

            rule_id = f"brakeman_{code}"
            title = f"Brakeman: {code.replace('_', ' ').title()}"
            desc = description
            if len(unique_codes) > 1:
                desc = f"{description} (warning: {code})"

            rules.append({
                "id": rule_id,
                "title": title,
                "description": desc,
                "severity": severity,
                "category": wtype,
                "cwe_ids": cwe_for_rule,
                "tags": ["brakeman", "ruby", "rails", "sast",
                         wtype.lower().replace(" ", "-")],
                "metadata": {
                    "class_name": class_name,
                    "warning_code": code,
                    "warning_type": wtype,
                    "confidence_levels": list(set(all_confidences)),
                    "source_file": rel_path,
                },
            })

        return rules

    @staticmethod
    def _pick_severity(confidences):
        """Pick the highest severity from a list of Brakeman confidence levels."""
        if not confidences:
            return "medium"
        # Priority: high > medium > low > weak
        priority = {"high": 4, "medium": 3, "low": 2, "weak": 1}
        best = "weak"
        for c in confidences:
            c_lower = c.lower()
            if priority.get(c_lower, 0) > priority.get(best, 0):
                best = c_lower
        return CONFIDENCE_MAP.get(best, "medium")