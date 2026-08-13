"""Collector for nodejsscan (Node.js security scanner web UI) rules.

nodejsscan is a web-based static analysis tool for Node.js applications.
It uses njsscan as its scanning engine — the rules are identical, defined
in YAML files. However, nodejsscan is a separate project with its own
repository, so we collect from it independently. Since nodejsscan depends
on njsscan via pip (njsscan==0.4.0), the rules live in the njsscan package.

This collector clones the nodejsscan repo and, if the njsscan rules are
not vendored within it, clones njsscan as a secondary source to parse the
same rule set. The rules are then upserted with nodejsscan-prefixed IDs
to distinguish them from the njsscan collector's entries.
"""

import os
import logging

import git

from .base import BaseCollector, CLONE_BASE
from .njsscan import NjsscanCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class NodejsscanCollector(BaseCollector):
    name = "nodejsscan"
    display_name = "nodejsscan"
    source_type = "github"
    source_url = "https://github.com/ajinabraham/nodejsscan.git"
    description = (
        "nodejsscan is a web-based static analysis tool for Node.js "
        "applications. It scans for security vulnerabilities including XSS, "
        "SQL injection, SSRF, XXE, path traversal, insecure deserialization, "
        "and missing security controls. Built on top of njsscan."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6556761"

    # njsscan repo URL — nodejsscan depends on it
    NJSSCAN_URL = "https://github.com/ajinabraham/njsscan.git"
    njsscan_clone_dir = os.path.join(CLONE_BASE, "njsscan")

    def collect_rules(self):
        count = 0

        # nodejsscan uses njsscan as a dependency for its rules.
        # The rules are in the njsscan package, not vendored in nodejsscan.
        # We clone njsscan as a secondary source for rule definitions.
        rules_dir = os.path.join(self.njsscan_clone_dir, "njsscan", "rules")

        # If njsscan isn't cloned yet, clone it
        if not os.path.isdir(rules_dir):
            logger.info("[nodejsscan] Cloning njsscan for rule definitions...")
            try:
                if os.path.exists(os.path.join(self.njsscan_clone_dir, ".git")):
                    repo = git.Repo(self.njsscan_clone_dir)
                    repo.remotes.origin.pull()
                else:
                    git.Repo.clone_from(
                        self.NJSSCAN_URL, self.njsscan_clone_dir,
                        depth=1, single_branch=True,
                    )
            except Exception as e:
                logger.warning(f"[nodejsscan] Could not clone njsscan: {e}")
                return

        if not os.path.isdir(rules_dir):
            logger.warning("[nodejsscan] njsscan rules directory not found")
            return

        # Reuse the njsscan collector's parsing logic, but with nodejsscan IDs
        # We temporarily set the clone_dir to the njsscan clone for parsing
        original_clone_dir = self.clone_dir
        self.clone_dir = self.njsscan_clone_dir
        original_name = self.name
        self.name = "njsscan"  # _parse methods use self.name for logging

        # Delegate to the njsscan parser methods
        njsscan_parser = NjsscanCollector.__new__(NjsscanCollector)
        njsscan_parser.clone_dir = self.njsscan_clone_dir
        njsscan_parser.vendor = self.vendor
        njsscan_parser.sync_id = self.sync_id
        njsscan_parser.stats = self.stats
        njsscan_parser.seen_rule_ids = self.seen_rule_ids

        # Parse missing_controls.yaml
        mc_path = os.path.join(rules_dir, "missing_controls.yaml")
        if os.path.isfile(mc_path):
            rel_path = os.path.relpath(mc_path, self.njsscan_clone_dir)
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
                    rel_path = os.path.relpath(fpath, self.njsscan_clone_dir)
                    count += self._parse_semantic_grep(fpath, rel_path)

        # Parse pattern_matcher YAML files
        pm_dir = os.path.join(rules_dir, "pattern_matcher")
        if os.path.isdir(pm_dir):
            for fname in sorted(os.listdir(pm_dir)):
                if not fname.endswith((".yaml", ".yml")):
                    continue
                fpath = os.path.join(pm_dir, fname)
                rel_path = os.path.relpath(fpath, self.njsscan_clone_dir)
                count += self._parse_pattern_matcher(fpath, rel_path)

        # Restore original state
        self.clone_dir = original_clone_dir
        self.name = original_name

        logger.info(f"[nodejsscan] Processed {count} rules")

    def _parse_missing_controls(self, fpath, rel_path):
        """Parse missing_controls.yaml for security control rules."""
        import yaml
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[nodejsscan] Failed to parse {fpath}: {e}")
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
                cwe_clean = str(cwe).upper().replace("CWE-", "")
                cwe_ids = [f"CWE-{cwe_clean}"]

            self.upsert(
                rule_id=f"nodejsscan:{name}",
                title=description[:500] if description else name,
                description=description[:2000],
                severity=SEVERITY_MAP.get(severity_raw, "low"),
                category="missing-control",
                language="javascript",
                cwe_ids=cwe_ids,
                tags=["nodejsscan", "javascript", "nodejs", "sast",
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
        import yaml
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[nodejsscan] Failed to parse {fpath}: {e}")
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

            path_parts = rel_path.split(os.sep)
            category = ""
            if "semantic_grep" in path_parts:
                idx = path_parts.index("semantic_grep")
                if idx + 1 < len(path_parts):
                    category = path_parts[idx + 1]

            self.upsert(
                rule_id=f"nodejsscan:{rid}",
                title=message[:500] if message else rid,
                description=message[:2000],
                severity=SEVERITY_MAP.get(severity_raw, "medium"),
                category=category or "security",
                language="javascript",
                cwe_ids=cwe_ids,
                tags=["nodejsscan", "javascript", "nodejs", "sast",
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
        import yaml
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[nodejsscan] Failed to parse {fpath}: {e}")
            return 0

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
                rule_id=f"nodejsscan:{rid}",
                title=message[:500] if message else rid,
                description=message[:2000],
                severity=SEVERITY_MAP.get(severity_raw, "medium"),
                category="pattern-matcher",
                language="javascript",
                cwe_ids=cwe_ids,
                tags=["nodejsscan", "javascript", "nodejs", "sast",
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