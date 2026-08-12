"""Collector for Snyk security rules and vulnerability database.

Snyk maintains a public vulnerability database and security rules through
their GitHub repos. This collector pulls from:
1. snyk/snyk - CLI and policy rules
2. snyk-policy.json files that define ignore/patch rules per vulnerability
"""

import os
import json
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class SnykCollector(BaseCollector):
    name = "snyk"
    display_name = "Snyk"
    source_type = "github"
    source_url = "https://github.com/snyk/snyk.git"
    description = (
        "Snyk security platform. Detects vulnerabilities in dependencies, "
        "container images, IaC, and source code. Rules cover known CVEs, "
        "license issues, and misconfigurations with severity ratings and "
        "fix recommendations."
    )
    logo_url = "https://avatars.githubusercontent.com/u/24964600"

    def collect_rules(self):
        count = 0

        # Snyk's rules are spread across multiple locations in the repo:
        # 1. src/lib/snyk-test/policy-rules/ - test policy rules
        # 2. .snyk files with ignore/patch rules
        # 3. src/lib/ecosystems/ - ecosystem-specific vulnerability patterns

        # Walk for .snyk policy files and JSON rule definitions
        for root, dirs, files in os.walk(self.clone_dir):
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".") and d != "node_modules"
                and d != "test" and d != "tests"
            ]

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                if fname == ".snyk" or fname.endswith(".snyk"):
                    count += self._parse_snyk_policy(fpath, rel_path)
                elif fname.endswith(".json") and "rule" in fname.lower():
                    count += self._parse_json_rules(fpath, rel_path)
                elif fname.endswith(".yml") or fname.endswith(".yaml"):
                    if "rule" in rel_path.lower() or "policy" in rel_path.lower():
                        count += self._parse_yaml_rules(fpath, rel_path)

        # Also look for Snyk Code (SAST) rules in src/lib/
        code_rules_dir = os.path.join(self.clone_dir, "src", "lib")
        if os.path.isdir(code_rules_dir):
            for root, dirs, files in os.walk(code_rules_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
                for fname in files:
                    if fname.endswith(".ts") or fname.endswith(".js"):
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, self.clone_dir)
                        if "rule" in fname.lower() or "severity" in fname.lower():
                            count += self._parse_code_rule(fpath, rel_path)

        logger.info(f"[snyk] Processed {count} rules")

    def _parse_snyk_policy(self, fpath, rel_path):
        """Parse a .snyk policy file for ignore/patch rules."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # .snyk files are YAML with version, ignore, and patch sections
        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            # Fall back to text parsing
            return 0

        if not isinstance(data, dict):
            return 0

        # Parse ignore rules
        ignore = data.get("ignore", {})
        if isinstance(ignore, dict):
            for vuln_id, reasons in ignore.items():
                if not vuln_id:
                    continue

                # reasons may be a list of dicts with 'reason' and 'expires'
                rule_reason = ""
                if isinstance(reasons, list) and reasons:
                    rule_reason = reasons[0].get("reason", "") if isinstance(reasons[0], dict) else str(reasons[0])
                elif isinstance(reasons, dict):
                    rule_reason = reasons.get("reason", "")
                elif isinstance(reasons, str):
                    rule_reason = reasons

                self.upsert(
                    rule_id=f"snyk:ignore-{vuln_id}",
                    title=f"Snyk Ignore: {vuln_id}",
                    description=rule_reason or f"Policy to ignore {vuln_id}",
                    severity="info",
                    category="ignore-policy",
                    language="",
                    cwe_ids=[],
                    tags=["snyk", "policy", "ignore"],
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="yaml",
                    metadata={
                        "vuln_id": vuln_id,
                        "type": "ignore",
                        "reasons": reasons if isinstance(reasons, list) else [reasons],
                    },
                )
                count += 1

        # Parse patch rules
        patch = data.get("patch", {})
        if isinstance(patch, dict):
            for key, val in patch.items():
                if not key:
                    continue
                self.upsert(
                    rule_id=f"snyk:patch-{key}",
                    title=f"Snyk Patch: {key}",
                    description=f"Snyk patch policy for {key}",
                    severity="high",
                    category="patch-policy",
                    language="",
                    cwe_ids=[],
                    tags=["snyk", "policy", "patch"],
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="yaml",
                    metadata={
                        "patch_id": key,
                        "type": "patch",
                        "patch_data": val,
                    },
                )
                count += 1

        return count

    def _parse_json_rules(self, fpath, rel_path):
        """Parse JSON rule definition files."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return 0

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and ("id" in item or "ruleId" in item):
                    count += self._upsert_snyk_rule(item, rel_path)
        elif isinstance(data, dict):
            if "id" in data or "ruleId" in data:
                count += self._upsert_snyk_rule(data, rel_path)
            # Check for nested rules arrays
            for key in ("rules", "patterns", "checks"):
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, dict):
                            count += self._upsert_snyk_rule(item, rel_path)

        return count

    def _parse_yaml_rules(self, fpath, rel_path):
        """Parse YAML rule files."""
        count = 0
        try:
            import yaml
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (ImportError, Exception):
            return 0

        if not isinstance(data, dict):
            return 0

        for key, val in data.items():
            if isinstance(val, dict) and ("id" in val or "severity" in val):
                count += self._upsert_snyk_rule(val, rel_path, fallback_id=key)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        count += self._upsert_snyk_rule(item, rel_path, fallback_id=key)

        return count

    def _parse_code_rule(self, fpath, rel_path):
        """Parse TypeScript/JavaScript rule files for Snyk Code (SAST) rules."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Look for rule ID patterns in source
        rule_ids = re.findall(
            r"(?:ruleId|rule_id|RuleId)\s*[:=]\s*['\"]([^'\"]+)['\"]", content
        )

        if not rule_ids:
            return 0

        for rid in set(rule_ids):
            # Extract severity if nearby
            severity_match = re.search(
                r"(?:severity|Severity)\s*[:=]\s*['\"]([^'\"]+)['\"]",
                content,
            )
            severity_raw = severity_match.group(1).lower() if severity_match else "medium"
            severity_map = {
                "critical": "critical", "high": "high",
                "medium": "medium", "low": "low", "info": "info",
            }
            severity = severity_map.get(severity_raw, "medium")

            self.upsert(
                rule_id=f"snyk-code:{rid}",
                title=f"Snyk Code: {rid}",
                description=f"Snyk Code SAST rule: {rid}",
                severity=severity,
                category="sast",
                language="",
                cwe_ids=[],
                tags=["snyk", "snyk-code", "sast"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="typescript",
                metadata={
                    "rule_id": rid,
                    "scanner": "snyk-code",
                },
            )
            count += 1

        return count

    def _upsert_snyk_rule(self, item, rel_path, fallback_id=""):
        """Upsert a single Snyk rule from a dict."""
        rule_id = item.get("id") or item.get("ruleId") or fallback_id
        if not rule_id:
            return 0

        severity_raw = str(item.get("severity", "medium")).lower()
        severity_map = {
            "critical": "critical", "high": "high",
            "medium": "medium", "low": "low", "info": "info",
        }
        severity = severity_map.get(severity_raw, "medium")

        title = item.get("title") or item.get("name") or rule_id
        description = item.get("description") or item.get("detail") or ""

        # CWE extraction
        cwe_ids = []
        cwe = item.get("cwe") or item.get("CWE")
        if cwe:
            if isinstance(cwe, list):
                cwe_ids = [f"CWE-{c}" if not str(c).startswith("CWE") else str(c) for c in cwe]
            elif isinstance(cwe, str):
                cwe_nums = re.findall(r"CWE-(\d+)", cwe)
                cwe_ids = [f"CWE-{n}" for n in cwe_nums]

        language = item.get("language", "") or item.get("ecosystem", "")

        self.upsert(
            rule_id=f"snyk:{rule_id}",
            title=title[:500],
            description=description[:2000],
            severity=severity,
            category=item.get("category", "vulnerability"),
            language=language,
            cwe_ids=cwe_ids,
            tags=["snyk", "vulnerability"],
            source_file=rel_path,
            rule_content=json.dumps(item, indent=2)[:50000],
            rule_format="json",
            metadata={
                "snyk_id": rule_id,
                "scanner": item.get("scanner", "snyk"),
                "pkg_manager": item.get("packageManager", ""),
            },
        )
        return 1