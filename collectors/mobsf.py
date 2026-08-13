"""Collector for Mobile Security Framework (MobSF) rules.

MobSF is an open-source mobile application security testing framework
that supports SAST, DAST, and IAST-like analysis for Android and iOS apps.
Rules are defined in MobSF/rules/ as JSON/YAML files and in StaticAnalyzer/
as Python rule definitions.
"""

import os
import re
import json
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


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

        # MobSF rules are in StaticAnalyzer/views/ as Python files with rule definitions
        static_dir = os.path.join(self.clone_dir, "StaticAnalyzer", "views")
        if os.path.isdir(static_dir):
            for root, dirs, files in os.walk(static_dir):
                for fname in files:
                    if fname.endswith(".py") and not fname.startswith("__"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_python_rules(fpath)

        # Also check MobSF/rules/ for JSON/YAML rule files
        rules_dir = os.path.join(self.clone_dir, "MobSF", "rules")
        if os.path.isdir(rules_dir):
            for root, dirs, files in os.walk(rules_dir):
                for fname in files:
                    if fname.endswith(".json"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_json_rules(fpath)

        # Check for security findings rules in StaticAnalyzer tools
        tools_dir = os.path.join(self.clone_dir, "StaticAnalyzer", "tools")
        if os.path.isdir(tools_dir):
            for root, dirs, files in os.walk(tools_dir):
                for fname in files:
                    if fname.endswith(".json"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_json_rules(fpath)

        logger.info(f"[mobsf] Processed {count} rules")

    def _parse_python_rules(self, fpath):
        """Parse MobSF Python files for rule/finding definitions."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        fname = os.path.basename(fpath).replace(".py", "")

        # Look for rule tuple/dict definitions
        # Pattern: ('RULE_ID', 'Description', severity)
        for m in re.finditer(
            r'\(\s*[\'"]([A-Z][A-Z0-9_]+)[\'"],\s*[\'"]([^\'"]+)[\'"]',
            content,
        ):
            rule_id = f"mobsf-{m.group(1).lower()}"
            title = m.group(2)
            self.upsert(
                rule_id,
                title,
                severity="medium",
                description=f"MobSF security rule: {title}",
            )
            count += 1

        # Look for dict entries with 'id' or 'rule' keys
        for m in re.finditer(r'[\'"](?:id|rule_id|finding)[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]', content):
            rule_id = f"mobsf-{m.group(1).lower()}"
            self.upsert(
                rule_id,
                f"MobSF finding: {m.group(1)}",
                severity="medium",
                description=f"MobSF security finding: {m.group(1)}",
            )
            count += 1

        # If no rules found, register the module itself
        if count == 0:
            self.upsert(
                f"mobsf-module-{fname}",
                f"MobSF {fname} analysis module",
                severity="info",
                description=f"MobSF static analysis module: {fname}",
            )
            count += 1

        return count

    def _parse_json_rules(self, fpath):
        """Parse MobSF JSON rule files."""
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return 0

        count = 0
        fname = os.path.basename(fpath)

        def walk_rules(obj, path=""):
            nonlocal count
            if isinstance(obj, dict):
                rule_id = obj.get("id") or obj.get("rule_id") or obj.get("code")
                title = obj.get("title") or obj.get("name") or obj.get("description")
                if rule_id and title:
                    r_id = f"mobsf-{str(rule_id).lower()}"
                    self.upsert(
                        r_id,
                        str(title),
                        severity=obj.get("severity", "medium").lower(),
                        cwe_ids=obj.get("cwe", ""),
                        description=str(obj.get("description", ""))[:500],
                    )
                    count += 1
                for k, v in obj.items():
                    walk_rules(v, f"{path}/{k}")
            elif isinstance(obj, list):
                for item in obj:
                    walk_rules(item, path)

        walk_rules(data)
        return count