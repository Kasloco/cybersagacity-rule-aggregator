"""Collector for GitLab SAST rules and security scanner configurations.

GitLab SAST runs multiple analyzers (Semgrep, ESLint, Bandit, etc.) but also
has its own security rules and vulnerability detection patterns documented
in the GitLab project. This collector focuses on GitLab-specific security
policies, custom rules, and the SAST scanner configurations that define
which checks run for each language.
"""

import os
import json
import yaml
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class GitLabSASTCollector(BaseCollector):
    name = "gitlab_sast"
    display_name = "GitLab SAST"
    source_type = "github"
    source_url = "https://gitlab.com/gitlab-org/gitlab.git"
    description = (
        "GitLab SAST (Static Application Security Testing). "
        "Multi-language security scanning with custom rule sets for "
        "injection, XSS, SSRF, path traversal, and OWASP Top 10 categories. "
        "Integrates with GitLab CI/CD pipelines."
    )
    logo_url = "https://avatars.githubusercontent.com/u/10669714"

    # GitLab uses gitlab.com not github.com, so we need to handle this
    # The GitPython library can clone from gitlab.com

    def collect_rules(self):
        count = 0

        # GitLab's security rules are in lib/gitlab/ci/templates/Security/
        # and in the gitlab-sast related repos
        # Look for SAST template files and security rule definitions

        # Primary location: lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml
        templates_dir = os.path.join(
            self.clone_dir, "lib", "gitlab", "ci", "templates"
        )

        if os.path.isdir(templates_dir):
            for root, dirs, files in os.walk(templates_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if fname.endswith((".yml", ".yaml")):
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, self.clone_dir)
                        count += self._parse_template(fpath, rel_path)

        # Also look for security rule definitions in qa/ and spec/
        security_dirs = [
            os.path.join(self.clone_dir, "qa", "qa", "ee", "fixtures"),
            os.path.join(self.clone_dir, "ee", "lib", "gitlab", "ci", "templates"),
        ]

        for sdir in security_dirs:
            if os.path.isdir(sdir):
                for root, dirs, files in os.walk(sdir):
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    for fname in files:
                        if fname.endswith((".yml", ".yaml", ".json")):
                            fpath = os.path.join(root, fname)
                            rel_path = os.path.relpath(fpath, self.clone_dir)
                            count += self._parse_security_config(fpath, rel_path)

        # Look for vulnerability rule definitions
        # GitLab maintains vulnerability databases in lib/gitlab/vulnerabilities/
        vuln_dir = os.path.join(self.clone_dir, "lib", "gitlab", "vulnerabilities")
        if os.path.isdir(vuln_dir):
            for root, dirs, files in os.walk(vuln_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if fname.endswith(".rb"):
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, self.clone_dir)
                        count += self._parse_vulnerability_rb(fpath, rel_path)

        logger.info(f"[gitlab_sast] Processed {count} rules")

    def _parse_template(self, fpath, rel_path):
        """Parse a GitLab CI SAST template for security scanner configs."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        fname = os.path.basename(fpath)

        # Only process SAST-related templates
        if "sast" not in fname.lower() and "security" not in rel_path.lower():
            return 0

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            # Not valid YAML, skip
            return 0

        if not isinstance(data, dict):
            return 0

        # Extract scanner configurations
        # GitLab SAST templates define variables and analyzer configs
        scanner_name = fname.replace(".gitlab-ci.yml", "").replace(".yml", "")

        rule_id = f"gitlab-sast:{scanner_name}"

        # Extract relevant variables
        variables = data.get("variables", {})
        sast_variables = {
            k: v for k, v in variables.items()
            if "SAST" in k or "SECURE" in k or "SCAN" in k
        }

        description = f"GitLab SAST template for {scanner_name}"
        if sast_variables:
            description += f". Variables: {json.dumps(sast_variables)[:500]}"

        self.upsert(
            rule_id=rule_id,
            title=f"GitLab SAST: {scanner_name}",
            description=description,
            severity="medium",
            category="sast-config",
            language="yaml",
            cwe_ids=[],
            tags=["gitlab", "sast", "ci-cd", "security"],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="yaml",
            metadata={
                "scanner": scanner_name,
                "variables": sast_variables,
                "template_type": "ci-config",
            },
        )
        count += 1
        return count

    def _parse_security_config(self, fpath, rel_path):
        """Parse security configuration files from GitLab's test/spec fixtures."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        fname = os.path.basename(fpath)

        # Only process files with security-relevant content
        if not any(kw in fname.lower() for kw in
                       ["vulnerability", "sast", "security", "finding"]):
            return 0

        # Try to parse as JSON (vulnerability definitions)
        if fname.endswith(".json"):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "id" in item:
                            vuln_id = item.get("id", "")
                            if not vuln_id:
                                continue

                            severity_map = {
                                "critical": "critical",
                                "high": "high",
                                "medium": "medium",
                                "low": "low",
                                "info": "info",
                            }
                            severity = severity_map.get(
                                item.get("severity", "").lower(), "medium"
                            )

                            self.upsert(
                                rule_id=f"gitlab-sast:vuln-{vuln_id}",
                                title=item.get("name", vuln_id)[:500],
                                description=item.get("description", ""),
                                severity=severity,
                                category=item.get("category", "vulnerability"),
                                language=item.get("language", ""),
                                cwe_ids=[],
                                tags=["gitlab", "sast", "vulnerability"],
                                source_file=rel_path,
                                rule_content=json.dumps(item, indent=2)[:50000],
                                rule_format="json",
                                metadata={
                                    "vuln_id": vuln_id,
                                    "scanner": item.get("scanner", ""),
                                    "confidence": item.get("confidence", ""),
                                },
                            )
                            count += 1
            except json.JSONDecodeError:
                pass

        return count

    def _parse_vulnerability_rb(self, fpath, rel_path):
        """Parse Ruby vulnerability definition files."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        import re

        # Look for vulnerability class definitions
        # Pattern: class X < Y; title "..."
        class_match = re.search(r"class\s+(\w+)", content)
        title_match = re.search(
            r'(?:title|name)\s+["\']([^"\']+)["\']', content
        )

        if not class_match:
            return 0

        class_name = class_match.group(1)
        title = title_match.group(1) if title_match else class_name

        rule_id = f"gitlab-sast:{class_name}"

        self.upsert(
            rule_id=rule_id,
            title=title[:500],
            description=f"GitLab vulnerability class: {class_name}",
            severity="medium",
            category="vulnerability",
            language="ruby",
            cwe_ids=[],
            tags=["gitlab", "sast", "vulnerability", "ruby"],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="ruby",
            metadata={
                "class_name": class_name,
                "type": "vulnerability-class",
            },
        )
        count += 1
        return count