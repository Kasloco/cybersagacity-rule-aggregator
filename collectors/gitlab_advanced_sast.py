"""Collector for GitLab Advanced SAST rules.

GitLab Advanced SAST provides cross-file/cross-function taint analysis
and is distinct from legacy GitLab SAST (which wraps existing open-source
analyzers). Chris Near's spreadsheet marks it as "Yes" for SATriage support.

The rules are in the GitLab repository under
lib/gitlab/ci/templates/security/ or in the gitlab-org/security-products
analyzers. This collector parses YAML/JSON rule definitions.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class GitLabAdvancedSASTCollector(BaseCollector):
    name = "gitlab_advanced_sast"
    display_name = "GitLab Advanced SAST"
    source_type = "github"
    source_url = "https://github.com/gitlab-org/security-products/analyzers.git"
    description = (
        "GitLab Advanced SAST provides cross-file/cross-function taint "
        "analysis for C/C++, C#, Java, JavaScript, PHP, Python, and Scala. "
        "Distinguishable from legacy GitLab SAST which wraps existing "
        "open-source analyzers."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1192774"

    def collect_rules(self):
        count = 0

        # Look for rule definitions in various locations
        search_dirs = [
            os.path.join(self.clone_dir, "rules"),
            os.path.join(self.clone_dir, "analyzer"),
            os.path.join(self.clone_dir, "profiles"),
            os.path.join(self.clone_dir, "lib", "gitlab", "ci", "templates", "security"),
        ]

        for search_dir in search_dirs:
            if os.path.isdir(search_dir):
                for root, dirs, files in os.walk(search_dir):
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    for fname in files:
                        if fname.endswith((".yml", ".yaml")):
                            fpath = os.path.join(root, fname)
                            count += self._parse_yaml(fpath)
                        elif fname.endswith(".json"):
                            fpath = os.path.join(root, fname)
                            count += self._parse_json(fpath)

        # If no structured rules found, look for Go source with rule definitions
        if count == 0:
            for root, dirs, files in os.walk(self.clone_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d != ".git"]
                for fname in files:
                    if fname.endswith(".go") and "rule" in fname.lower():
                        fpath = os.path.join(root, fname)
                        count += self._parse_go_rules(fpath)

        logger.info(f"[gitlab_advanced_sast] Processed {count} rules")

    def _parse_yaml(self, fpath):
        """Parse YAML rule files for rule definitions."""
        try:
            import yaml
            with open(fpath, "r") as f:
                data = yaml.safe_load(f)
        except Exception:
            return 0

        count = 0
        if isinstance(data, dict):
            rules = data.get("rules") or data.get("checks") or []
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, dict):
                        rule_id = rule.get("id") or rule.get("name")
                        title = rule.get("name") or rule.get("description") or rule_id
                        severity = rule.get("severity", "medium")
                        cwe = rule.get("cwe") or rule.get("cwe_id")

                        if rule_id:
                            self.upsert(
                                str(rule_id),
                                str(title),
                                severity=str(severity).lower(),
                                cwe_ids=f"CWE-{cwe}" if cwe else "",
                                description=str(rule.get("description", ""))[:500],
                            )
                            count += 1
        return count

    def _parse_json(self, fpath):
        """Parse JSON rule files."""
        import json
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
        except Exception:
            return 0

        count = 0
        rules = data if isinstance(data, list) else data.get("rules", [])
        for rule in rules:
            if isinstance(rule, dict):
                rule_id = rule.get("id") or rule.get("name")
                if rule_id:
                    self.upsert(
                        str(rule_id),
                        str(rule.get("name", rule_id)),
                        severity=str(rule.get("severity", "medium")).lower(),
                        cwe_ids=f"CWE-{rule.get('cwe')}" if rule.get("cwe") else "",
                    )
                    count += 1
        return count

    def _parse_go_rules(self, fpath):
        """Parse Go source files for rule definitions."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        # Look for rule ID patterns
        for m in re.finditer(r'RuleID\s*[:=]\s*"([^"]+)"', content):
            rule_id = f"gitlab-advanced-sast-{m.group(1)}"
            self.upsert(
                rule_id,
                f"GitLab Advanced SAST: {m.group(1)}",
                severity="medium",
            )
            count += 1

        # Also look for severity constants
        for m in re.finditer(r'Severity\s*[:=]\s*"(\w+)"', content):
            sev = m.group(1).lower()
            rule_id = f"gitlab-advanced-sast-severity-{sev}"
            self.upsert(
                rule_id,
                f"GitLab Advanced SAST severity: {sev}",
                severity=sev,
            )
            count += 1

        return count