"""Collector for Grype (Anchore) vulnerability matcher rules.

Grype is a vulnerability scanner for container images, filesystems, and SBOMs.
This collector registers the ecosystem matchers and vulnerability severity definitions
that Grype uses to match packages against known vulnerabilities.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class GrypeCollector(BaseCollector):
    name = "grype"
    display_name = "Grype"
    source_type = "github"
    source_url = "https://github.com/anchore/grype.git"
    description = (
        "Grype is a vulnerability scanner for container images, filesystems, "
        "SBOMs, and packages. It matches installed packages against a database "
        "of known vulnerabilities (CVE-based). Supports apk, bitnami, dotnet, "
        "dpkg, golang, java, javascript, python, rpm, ruby, rust, and more."
    )
    logo_url = "https://avatars.githubusercontent.com/u/55451325"

    def collect_rules(self):
        count = 0

        # Parse matchers.go for ecosystem matcher registrations
        matchers_file = os.path.join(self.clone_dir, "grype", "matcher", "matchers.go")
        if os.path.isfile(matchers_file):
            count += self._parse_matchers(matchers_file)

        # Parse severity.go for severity definitions
        severity_file = os.path.join(self.clone_dir, "grype", "vulnerability", "severity.go")
        if os.path.isfile(severity_file):
            count += self._parse_severities(severity_file)

        # Parse each matcher directory for rule patterns
        matcher_dir = os.path.join(self.clone_dir, "grype", "matcher")
        if os.path.isdir(matcher_dir):
            for entry in os.listdir(matcher_dir):
                entry_path = os.path.join(matcher_dir, entry)
                if os.path.isdir(entry_path):
                    for fname in os.listdir(entry_path):
                        if fname.endswith(".go") and not fname.endswith("_test.go"):
                            fpath = os.path.join(entry_path, fname)
                            count += self._parse_matcher_file(fpath, entry)

        logger.info(f"[grype] Processed {count} rules")

    def _parse_matchers(self, fpath):
        """Parse matchers.go for ecosystem matcher registrations."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Pattern: addMatcher(&match.Matcher{Type: "type-name"})
        for m in re.finditer(r'addMatcher\(&match\.Matcher\{Type:\s*"(\w+)"', content):
            ecosystem = m.group(1)
            rule_id = f"grype-matcher-{ecosystem}"
            self.upsert(
                rule_id,
                f"Grype {ecosystem} ecosystem vulnerability matcher",
                severity="info",
                description=f"Vulnerability matcher for the {ecosystem} package ecosystem.",
            )
            count += 1

        return count

    def _parse_severities(self, fpath):
        """Parse severity.go for severity level definitions."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Pattern: Severity{name: "Severity", ...}
        for m in re.finditer(r'Severity\{[^}]*"?(\w+)"?\s*:\s*"(\w+)"', content):
            severity_name = m.group(2)
            rule_id = f"grype-severity-{severity_name.lower()}"
            self.upsert(
                rule_id,
                f"Grype severity level: {severity_name}",
                severity=severity_name.lower(),
                description=f"Severity classification: {severity_name}",
            )
            count += 1

        return count

    def _parse_matcher_file(self, fpath, ecosystem):
        """Parse a matcher Go file for matcher-specific rules."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Look for matcher type definitions and criteria
        for m in re.finditer(r'type:\s*"([\w-]+)"', content, re.IGNORECASE):
            rule_type = m.group(1)
            rule_id = f"grype-{ecosystem}-{rule_type}"
            self.upsert(
                rule_id,
                f"Grype {ecosystem} matcher: {rule_type}",
                severity="info",
                description=f"Ecosystem matcher rule for {ecosystem}: {rule_type}",
            )
            count += 1

        return count