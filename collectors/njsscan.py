"""Collector for njsscan (Node.js security scanner) rules.

njsscan is a static analysis tool that finds security issues in Node.js
applications. Rules are YAML files in njsscan/rules/ with three categories:
  - semantic_grep/   - Semgrep-style pattern rules (YAML with id, message, severity, metadata.cwe)
  - pattern_matcher/ - Regex-based template matching rules
  - missing_controls.yaml - Security control checks (helmet headers, CSRF, rate limiting)
"""

import os
import yaml
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class NjsscanCollector(BaseCollector):
    name = "njsscan"
    display_name = "njsscan"
    source_type = "github"
    source_url = "https://github.com/ajinabraham/njsscan.git"
    description = (
        "njsscan is a semantic and pattern-based static analysis tool for "
        "Node.js applications. Detects XSS, SQL injection, SSRF, XXE, path "
        "traversal, insecure eval, deserialization, missing security headers, "
        "and more. Rules are mapped to CWEs."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6556761"

    def collect_rules(self):
        count = 0

        rules_dir = os.path.join(self.clone_dir, "njsscan", "rules")
        if not os.path.isdir(rules_dir):
            logger.warning("[njsscan] rules directory not found")
            return

        # Parse missing_controls.yaml
        mc_path = os.path.join(rules_dir, "missing_controls.yaml")
        if os.path.isfile(mc_path):
            rel_path = os.path.relpath(mc_path, self.clone_dir)
            count += self._parse_missing_controls(mc_path, rel_path)

        # Parse semantic_grep YAML files
        sg_dir = os.path.join(rules_dir, "semantic_grep")
        if os.path.isdir(sg_dir):
            for root, dirs, files in os.walk(sg_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in sorted(files):
                    if not fname.endswith((".yaml", ".yml")):
                        continue
                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, self.clone_dir)
                    count += self._parse_semantic_grep(fpath, rel_path)

        # Parse pattern_matcher YAML files
        pm_dir = os.path.join(rules_dir, "pattern_matcher")
        if os.path.isdir(pm_dir):
            for fname in sorted(os.listdir(pm_dir)):
                if not fname.endswith((".yaml", ".yml")):
                    continue
                fpath = os.path.join(pm_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_pattern_matcher(fpath, rel_path)

        logger.info(f"[njsscan] Processed {count} rules")

    def _parse_missing_controls(self, fpath, rel_path):
        """Parse missing_controls.yaml for security control rules."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[njsscan] Failed to parse {fpath}: {e}")
            return 0

        controls = data.get("controls", {}) if data else {}
        for name, info in controls.items():
            meta = info.get("metadata", {})
            description = meta.get("description", "")
            severity_raw = meta.get("severity", "INFO")
            cwe = meta.get("cwe", "")
            owasp = meta.get("owasp-web", "")

            cwe_ids = []
            if cwe:
                cwe_ids = [cwe.upper().replace("CWE-", "CWE-")]
                # Normalize: ensure CWE-xxx format
                cwe_ids = [f"CWE-{cwe_ids[0].replace('CWE-', '')}"]

            self.upsert(
                rule_id=f"njsscan:{name}",
                title=description[:500] if description else name,
                description=description[:2000],
                severity=SEVERITY_MAP.get(severity_raw, "low"),
                category="missing-control",
                language="javascript",
                cwe_ids=cwe_ids,
                tags=["njsscan", "javascript", "nodejs", "sast",
                      "missing-control", severity_raw.lower()],
                source_file=rel_path,
                rule_content=yaml.dump(info, default_flow_style=False)[:50000],
                rule_format="yaml",
                metadata={
                    "control_name": name,
                    "owasp_web": owasp,
                    "native_severity": severity_raw,
                    "rule_type": "missing_control",
                },
            )
            count += 1

        return count

    def _parse_semantic_grep(self, fpath, rel_path):
        """Parse a semantic_grep YAML file for pattern-based rules."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[njsscan] Failed to parse {fpath}: {e}")
            return 0

        rules = data.get("rules", []) if data else []
        for rule in rules:
            rid = rule.get("id", "")
            if not rid:
                continue
            message = rule.get("message", "")
            severity_raw = rule.get("severity", "WARNING")
            meta = rule.get("metadata", {})
            cwe = meta.get("cwe", "")
            owasp = meta.get("owasp-web", "")

            cwe_ids = []
            if cwe:
                cwe_clean = str(cwe).upper().replace("CWE-", "")
                cwe_ids = [f"CWE-{cwe_clean}"]

            # Derive category from the file path
            path_parts = rel_path.split(os.sep)
            category = ""
            if "semantic_grep" in path_parts:
                idx = path_parts.index("semantic_grep")
                if idx + 1 < len(path_parts):
                    category = path_parts[idx + 1]

            self.upsert(
                rule_id=f"njsscan:{rid}",
                title=message[:500] if message else rid,
                description=message[:2000],
                severity=SEVERITY_MAP.get(severity_raw, "medium"),
                category=category or "security",
                language="javascript",
                cwe_ids=cwe_ids,
                tags=["njsscan", "javascript", "nodejs", "sast",
                      "semantic-grep", category or "general",
                      severity_raw.lower()],
                source_file=rel_path,
                rule_content=yaml.dump(rule, default_flow_style=False)[:50000],
                rule_format="yaml",
                metadata={
                    "rule_id": rid,
                    "owasp_web": owasp,
                    "native_severity": severity_raw,
                    "rule_type": "semantic_grep",
                },
            )
            count += 1

        return count

    def _parse_pattern_matcher(self, fpath, rel_path):
        """Parse a pattern_matcher YAML file for regex-based template rules."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[njsscan] Failed to parse {fpath}: {e}")
            return 0

        # pattern_matcher files are lists of rules
        rules = data if isinstance(data, list) else data.get("rules", []) if data else []
        for rule in rules:
            rid = rule.get("id", "")
            if not rid:
                continue
            message = rule.get("message", "")
            severity_raw = rule.get("severity", "WARNING")
            rule_type = rule.get("type", "Regex")
            pattern = rule.get("pattern", "")
            meta = rule.get("metadata", {})
            cwe = meta.get("cwe", "")
            owasp = meta.get("owasp-web", "")

            cwe_ids = []
            if cwe:
                cwe_clean = str(cwe).upper().replace("CWE-", "")
                cwe_ids = [f"CWE-{cwe_clean}"]

            self.upsert(
                rule_id=f"njsscan:{rid}",
                title=message[:500] if message else rid,
                description=message[:2000],
                severity=SEVERITY_MAP.get(severity_raw, "medium"),
                category="pattern-matcher",
                language="javascript",
                cwe_ids=cwe_ids,
                tags=["njsscan", "javascript", "nodejs", "sast",
                      "pattern-matcher", severity_raw.lower()],
                source_file=rel_path,
                rule_content=yaml.dump(rule, default_flow_style=False)[:50000],
                rule_format="yaml",
                metadata={
                    "rule_id": rid,
                    "rule_type": rule_type,
                    "pattern": pattern,
                    "owasp_web": owasp,
                    "native_severity": severity_raw,
                },
            )
            count += 1

        return count