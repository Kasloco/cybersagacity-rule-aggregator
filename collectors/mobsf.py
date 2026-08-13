"""Collector for Mobile Security Framework (MobSF) rules.

MobSF is an open-source mobile application security testing framework
that supports SAST, DAST, and IAST-like analysis for Android and iOS apps.

Rules are defined as:
- YAML files under mobsf/StaticAnalyzer/views/android/rules/ (android_rules,
  android_apis, android_niap, android_permissions)
- Python dicts in mobsf/StaticAnalyzer/views/ios/rules/ipa_rules.py (IPA_RULES)
- Python dicts in mobsf/StaticAnalyzer/views/android/kb/android_manifest_desc.py
  (MANIFEST_DESC)
"""

import os
import re
import yaml
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Severity normalization: MobSF uses 'warning', 'high', 'info'
SEVERITY_MAP = {
    "warning": "medium",
    "high": "high",
    "info": "info",
    "critical": "critical",
    "low": "low",
}


def _normalize_severity(sev):
    if not sev:
        return "info"
    sev = str(sev).strip().lower()
    return SEVERITY_MAP.get(sev, sev)


class MobSFCollector(BaseCollector):
    name = "mobsf"
    display_name = "Mobile Security Framework (MobSF)"
    source_type = "github"
    source_url = "https://github.com/MobSF/Mobile-Security-Framework-MobSF.git"
    description = (
        "MobSF is an open-source mobile application security testing framework "
        "supporting Android APK/AAB and iOS IPA/source. Provides static (SAST), "
        "dynamic (DAST), and IAST-like analysis including malware analysis."
    )
    logo_url = "https://avatars.githubusercontent.com/u/10142754"

    def collect_rules(self):
        count = 0

        base = os.path.join(self.clone_dir, "mobsf")

        # 1. Parse YAML rule files under StaticAnalyzer/views/android/rules/
        android_rules_dir = os.path.join(
            base, "StaticAnalyzer", "views", "android", "rules"
        )
        if os.path.isdir(android_rules_dir):
            for fname in sorted(os.listdir(android_rules_dir)):
                if fname.endswith(".yaml") or fname.endswith(".yml"):
                    fpath = os.path.join(android_rules_dir, fname)
                    count += self._parse_yaml_rules(fpath, fname)

        # 2. Parse iOS IPA rules (Python list of dicts)
        ipa_rules_file = os.path.join(
            base, "StaticAnalyzer", "views", "ios", "rules", "ipa_rules.py"
        )
        if os.path.isfile(ipa_rules_file):
            count += self._parse_ipa_rules(ipa_rules_file)

        # 3. Parse Android manifest analysis descriptions (Python dict)
        manifest_desc_file = os.path.join(
            base, "StaticAnalyzer", "views", "android", "kb",
            "android_manifest_desc.py",
        )
        if os.path.isfile(manifest_desc_file):
            count += self._parse_manifest_desc(manifest_desc_file)

        logger.info(f"[mobsf] Processed {count} rules")

    def _parse_yaml_rules(self, fpath, source_file):
        """Parse MobSF YAML rule files (list of rule dicts with id, message, severity, metadata)."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[mobsf] Failed to parse {fpath}: {e}")
            return 0

        if not isinstance(data, list):
            return 0

        for entry in data:
            if not isinstance(entry, dict):
                continue
            rule_id = entry.get("id")
            if not rule_id:
                continue

            title = entry.get("message") or entry.get("description") or rule_id
            severity = _normalize_severity(entry.get("severity", "info"))

            metadata = entry.get("metadata", {}) or {}
            cwe = ""
            if isinstance(metadata, dict):
                cwe = metadata.get("cwe", "") or ""

            desc = entry.get("message") or title
            # Build a richer description
            parts = [f"MobSF rule from {source_file}: {desc}"]
            if isinstance(metadata, dict):
                if metadata.get("cvss"):
                    parts.append(f"CVSS: {metadata['cvss']}")
                if metadata.get("owasp-mobile"):
                    parts.append(f"OWASP Mobile: {metadata['owasp-mobile']}")
                if metadata.get("masvs"):
                    parts.append(f"MASVS: {metadata['masvs']}")

            self.upsert(
                f"mobsf-{rule_id}",
                title,
                severity=severity,
                cwe_ids=cwe,
                description=" | ".join(parts)[:500],
            )
            count += 1

        return count

    def _parse_ipa_rules(self, fpath):
        """Parse ipa_rules.py IPA_RULES list (list of dicts with description, severity, cwe)."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract each dict in IPA_RULES list
        # Pattern: { 'description': '...', ... 'severity': ..., 'cwe': ..., }
        # We use a simple regex to find dict blocks within IPA_RULES
        # Each rule dict starts with { and has 'description' key

        # Find all dict blocks between IPA_RULES = [ and the closing ]
        match = re.search(r'IPA_RULES\s*=\s*\[(.*?)\]\s*$', content, re.DOTALL | re.MULTILINE)
        if not match:
            return 0

        rules_text = match.group(1)

        # Split by top-level dict boundaries (}, {)
        # Each rule dict starts with { and ends with },
        rule_dicts = re.findall(
            r'\{([^{}]*?(?:\{[^{}]*\}[^{}]*?)*)\}',
            rules_text,
            re.DOTALL,
        )

        for i, rule_text in enumerate(rule_dicts):
            # Extract description
            desc_match = re.search(
                r"'description':\s*'((?:[^'\\]|\\.)*)'",
                rule_text,
            )
            if not desc_match:
                continue
            description = desc_match.group(1).replace("\\'", "'")

            # Extract severity
            sev_match = re.search(
                r"'severity':\s*(\w+)",
                rule_text,
            )
            severity = sev_match.group(1) if sev_match else "info"
            severity = _normalize_severity(severity)

            # Extract CWE
            cwe_match = re.search(
                r"'cwe':\s*(?:STDS\[['\"]cwe['\"]\]\[['\"](cwe-\d+)['\"]\]|['\"](cwe-\d+)['\"]\s*\]|['\"](.*?)['\"]\s*\])",
                rule_text,
            )
            cwe = ""
            if cwe_match:
                cwe = cwe_match.group(1) or cwe_match.group(2) or cwe_match.group(3) or ""

            # Extract MASVS
            masvs_match = re.search(
                r"'masvs':\s*(?:STDS\[['\"]masvs['\"]\]\[['\"]([\w-]+)['\"]\]|['\"]([\w-]+)['\"]\s*\]|'')",
                rule_text,
            )
            masvs = ""
            if masvs_match:
                masvs = masvs_match.group(1) or masvs_match.group(2) or ""

            rule_id = f"mobsf-ipa-rule-{i+1}"
            desc_parts = [f"MobSF iOS IPA binary analysis rule: {description}"]
            if masvs:
                desc_parts.append(f"MASVS: {masvs}")

            self.upsert(
                rule_id,
                description[:200],
                severity=severity,
                cwe_ids=cwe,
                description=" | ".join(desc_parts)[:500],
            )
            count += 1

        return count

    def _parse_manifest_desc(self, fpath):
        """Parse android_manifest_desc.py MANIFEST_DESC dict.

        Structure:
        MANIFEST_DESC = {
            'key': {
                'title': '...',
                'level': 'high'|'warning'|'info',
                'description': '...',
                'name': '...',
            },
            ...
        }
        """
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        # Find MANIFEST_DESC = { ... }
        match = re.search(
            r'MANIFEST_DESC\s*=\s*\{(.*?)(?:\nDVM_|\Z)',
            content,
            re.DOTALL,
        )
        if not match:
            # Try without the trailing boundary
            match = re.search(r'MANIFEST_DESC\s*=\s*\{(.*)\}', content, re.DOTALL)

        if not match:
            return 0

        desc_text = match.group(1)

        # Find each entry: 'key': { ... 'title': '...', 'level': '...', 'description': '...' ... }
        # Split by top-level keys
        entries = re.findall(
            r"^\s+'([^']+)':\s*\{(.*?)\n    \},",
            desc_text,
            re.DOTALL | re.MULTILINE,
        )

        for key, body in entries:
            title_match = re.search(r"'title':\s*\((.*?)\)\s*,|'title':\s*'(.*?)'\s*,",
                                    body, re.DOTALL)
            title = ""
            if title_match:
                title = (title_match.group(1) or title_match.group(2) or "").strip()
                title = re.sub(r"\s+", " ", title)
                title = title.replace("(", "").replace(")", "")

            level_match = re.search(r"'level':\s*'(\w+)'", body)
            level = level_match.group(1) if level_match else "info"
            severity = _normalize_severity(level)

            desc_match = re.search(
                r"'description':\s*\((.*?)\)\s*,|'description':\s*'(.*?)'\s*,",
                body,
                re.DOTALL,
            )
            description = ""
            if desc_match:
                description = (desc_match.group(1) or desc_match.group(2) or "").strip()
                description = re.sub(r"\s+", " ", description)

            if not title:
                title = f"Android manifest check: {key}"

            self.upsert(
                f"mobsf-manifest-{key}",
                title[:200],
                severity=severity,
                description=f"MobSF Android manifest analysis: {description[:400]}",
            )
            count += 1

        return count