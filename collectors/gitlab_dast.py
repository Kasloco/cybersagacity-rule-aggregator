"""Collector for GitLab DAST (Dynamic Application Security Testing) rules.

GitLab DAST is a dynamic application security testing tool that scans
running web applications for vulnerabilities. The DAST analyzer is at
github.com/gitlab-org/security-products/dast and uses a rules engine
backed by the DAST scanner (ZAP-based). Rule definitions and scanner
configurations are in YAML/JSON files.

If the DAST repo is unavailable, this collector falls back to the main
GitLab repo (github.com/gitlab-org/gitlab.git or gitlab.com) and looks
in lib/gitlab/ci/dast/ for DAST-related configurations.
"""

import os
import json
import re
import logging

try:
    import yaml
except ImportError:
    yaml = None

from .base import BaseCollector

logger = logging.getLogger(__name__)


class GitLabDASTCollector(BaseCollector):
    name = "gitlab_dast"
    display_name = "GitLab DAST"
    source_type = "github"
    source_url = "https://github.com/gitlab-org/security-products/dast.git"
    description = (
        "GitLab DAST (Dynamic Application Security Testing) scans running "
        "web applications for security vulnerabilities including XSS, SQL "
        "injection, CSRF, header misconfigurations, and OWASP Top 10 issues. "
        "Built on the OWASP ZAP scanner with GitLab-specific rule profiles."
    )
    logo_url = "https://avatars.githubusercontent.com/u/10669714"

    def collect_rules(self):
        """Parse DAST analyzer config files and rule definitions."""
        count = 0

        # 1) Look for analyzer rules in the DAST repo structure
        count += self._parse_rules_directories()
        count += self._parse_config_files()

        # 2) Look for scanner profiles (ZAP-based rules)
        count += self._parse_scanner_profiles()

        logger.info(f"[gitlab_dast] Processed {count} rules")

    def _parse_rules_directories(self):
        """Walk the repo for rule definition files."""
        count = 0
        rule_dirs = [
            os.path.join(self.clone_dir, "rules"),
            os.path.join(self.clone_dir, "lib", "gitlab", "ci", "dast"),
            os.path.join(self.clone_dir, "analyzer"),
            os.path.join(self.clone_dir, "scan"),
            os.path.join(self.clone_dir, "schemas"),
        ]

        for rdir in rule_dirs:
            if not os.path.isdir(rdir):
                continue
            for root, dirs, files in os.walk(rdir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in sorted(files):
                    if fname.endswith((".yml", ".yaml", ".json")):
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, self.clone_dir)
                        count += self._parse_rule_file(fpath, rel_path)

        return count

    def _parse_config_files(self):
        """Parse top-level config files for DAST scanner configuration."""
        count = 0
        config_files = [
            "config.yml",
            "config.yaml",
            "rules.yml",
            "rules.yaml",
            "analyzer.yml",
            "dast.yml",
            "dast-config.yml",
        ]

        for cf in config_files:
            fpath = os.path.join(self.clone_dir, cf)
            if os.path.isfile(fpath):
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_rule_file(fpath, rel_path)

        return count

    def _parse_scanner_profiles(self):
        """Look for ZAP scanner profiles and DAST profile configs."""
        count = 0
        profile_dirs = [
            os.path.join(self.clone_dir, "profiles"),
            os.path.join(self.clone_dir, "lib", "gitlab", "ci", "templates", "Security"),
            os.path.join(self.clone_dir, "ee", "lib", "gitlab", "ci", "templates", "Security"),
        ]

        for pdir in profile_dirs:
            if not os.path.isdir(pdir):
                continue
            for root, dirs, files in os.walk(pdir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in sorted(files):
                    if fname.endswith((".yml", ".yaml", ".json")):
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, self.clone_dir)
                        # Only parse DAST-related files
                        if "dast" in fname.lower() or "dast" in rel_path.lower():
                            count += self._parse_rule_file(fpath, rel_path)

        return count

    def _parse_rule_file(self, fpath, rel_path):
        """Parse a single rule/config file for DAST rule definitions."""
        count = 0

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        fname = os.path.basename(fpath)

        # Try YAML first, then JSON
        data = None
        if fname.endswith((".yml", ".yaml")):
            if yaml is None:
                return 0
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError:
                return 0
        elif fname.endswith(".json"):
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return 0

        if not isinstance(data, dict):
            # Non-structured config — still record as a config rule
            if "dast" in fname.lower():
                rule_id = f"gitlab-dast:config:{fname}"
                self.upsert(
                    rule_id=rule_id,
                    title=f"GitLab DAST config: {fname}"[:500],
                    description=f"DAST configuration file {rel_path}.",
                    severity="medium",
                    category="dast-config",
                    language="yaml",
                    cwe_ids=[],
                    tags=["gitlab", "dast", "config"],
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="yaml",
                    metadata={"config_file": fname},
                )
                count += 1
            return count

        # Look for rule definitions in common structures
        # Structure 1: rules: [{id, name, severity, ...}]
        # Structure 2: rules: {id: {severity, ...}}
        # Structure 3: top-level with id/title fields
        rules_data = data.get("rules", data.get("checks", data.get("tests", None)))

        if isinstance(rules_data, list):
            for item in rules_data:
                if not isinstance(item, dict):
                    continue
                count += self._upsert_rule_from_dict(item, rel_path)
        elif isinstance(rules_data, dict):
            for rid, info in rules_data.items():
                if not isinstance(info, dict):
                    continue
                # Inject the key as the ID if missing
                if "id" not in info:
                    info = {**info, "id": rid}
                count += self._upsert_rule_from_dict(info, rel_path)

        # If no rules found but it's a DAST config, record the config itself
        if count == 0 and "dast" in fname.lower():
            rule_id = f"gitlab-dast:config:{fname}"
            # Extract variables for description
            variables = data.get("variables", {})
            description = f"GitLab DAST configuration from {rel_path}."
            if isinstance(variables, dict) and variables:
                description += f" Variables: {json.dumps(variables)[:500]}"

            self.upsert(
                rule_id=rule_id,
                title=f"GitLab DAST config: {fname}"[:500],
                description=description,
                severity="medium",
                category="dast-config",
                language="yaml",
                cwe_ids=[],
                tags=["gitlab", "dast", "config"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="yaml",
                metadata={
                    "config_file": fname,
                    "variables": variables if isinstance(variables, dict) else {},
                },
            )
            count += 1

        return count

    def _upsert_rule_from_dict(self, item, rel_path):
        """Upsert a single rule from a parsed dict."""
        # Build rule ID
        rule_id_raw = item.get("id") or item.get("rule_id") or item.get("name") or ""
        if not rule_id_raw:
            return 0

        rule_id = f"gitlab-dast:{rule_id_raw}"

        # Extract title
        title = item.get("title") or item.get("name") or item.get("description", "") or str(rule_id_raw)

        # Extract severity
        severity_raw = (item.get("severity") or item.get("risk") or "medium").lower()
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
        }
        severity = severity_map.get(severity_raw, "medium")

        # Extract CWE
        cwe_ids = []
        cwe_raw = item.get("cwe") or item.get("cwe_id") or item.get("cweIds") or ""
        if cwe_raw:
            if isinstance(cwe_raw, list):
                cwe_ids = [str(c) for c in cwe_raw]
            elif isinstance(cwe_raw, (int, str)):
                # Extract CWE numbers
                cwe_nums = re.findall(r"(\d+)", str(cwe_raw))
                cwe_ids = [f"CWE-{n}" for n in cwe_nums]

        # Extract category
        category = item.get("category", "dast")
        tags = ["gitlab", "dast"]
        if isinstance(item.get("tags"), list):
            tags.extend(item["tags"])
        if isinstance(item.get("tags"), str):
            tags.append(item["tags"])

        # Description
        desc = item.get("description") or item.get("message") or ""

        self.upsert(
            rule_id=rule_id,
            title=title[:500],
            description=desc[:2000],
            severity=severity,
            category=category,
            language="",
            cwe_ids=cwe_ids,
            tags=tags,
            source_file=rel_path,
            rule_content=json.dumps(item, indent=2, default=str)[:50000],
            rule_format="json",
            metadata={
                "rule_id_raw": rule_id_raw,
                "severity_raw": severity_raw,
                "confidence": item.get("confidence", ""),
            },
        )
        return 1