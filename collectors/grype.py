"""Collector for Grype (Anchore) vulnerability matcher rules.

Grype is a vulnerability scanner for container images, filesystems, and SBOMs.
This collector registers the ecosystem matchers (dpkg, python, ruby, etc.) that
Grype uses to match packages against known vulnerabilities.

The matcher types are defined as constants in grype/match/matcher_type.go
and instantiated in grype/matcher/matchers.go.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Mapping from matcher type string to ecosystem display name and description.
MATCHER_INFO = {
    "apk-matcher": ("Alpine (apk)", "Alpine Linux apk package vulnerability matcher"),
    "ruby-gem-matcher": ("Ruby (gem)", "Ruby gem package vulnerability matcher"),
    "dpkg-matcher": ("Debian (dpkg)", "Debian dpkg package vulnerability matcher"),
    "rpm-matcher": ("RPM", "RPM-based package vulnerability matcher"),
    "java-matcher": ("Java (Maven)", "Java/Maven artifact vulnerability matcher"),
    "python-matcher": ("Python (pip)", "Python pip package vulnerability matcher"),
    "dotnet-matcher": (".NET (NuGet)", ".NET/NuGet package vulnerability matcher"),
    "javascript-matcher": ("JavaScript (npm)", "JavaScript/npm package vulnerability matcher"),
    "msrc-matcher": ("Microsoft (MSRC)", "Microsoft Security Response Center patch matcher"),
    "portage-matcher": ("Gentoo (Portage)", "Gentoo Portage package vulnerability matcher"),
    "go-module-matcher": ("Go (module)", "Go module vulnerability matcher"),
    "openvex-matcher": ("OpenVEX", "OpenVEX vulnerability exploitability matcher"),
    "csafvex-matcher": ("CSAF VEX", "CSAF VEX vulnerability exploitability matcher"),
    "rust-matcher": ("Rust (cargo)", "Rust/cargo crate vulnerability matcher"),
    "bitnami-matcher": ("Bitnami", "Bitnami package vulnerability matcher"),
    "pacman-matcher": ("Arch Linux (pacman)", "Arch Linux pacman package vulnerability matcher"),
    "hex-matcher": ("Hex (Elixir)", "Hex/Elixir package vulnerability matcher"),
}


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

        # Parse matcher_type.go for MatcherType constants
        matcher_type_file = os.path.join(
            self.clone_dir, "grype", "match", "matcher_type.go"
        )
        if os.path.isfile(matcher_type_file):
            count += self._parse_matcher_types(matcher_type_file)

        # Parse matchers.go for the actual matcher instantiation calls
        matchers_file = os.path.join(
            self.clone_dir, "grype", "matcher", "matchers.go"
        )
        if os.path.isfile(matchers_file):
            count += self._parse_matcher_constructors(matchers_file)

        logger.info(f"[grype] Processed {count} rules")

    def _parse_matcher_types(self, fpath):
        """Parse matcher_type.go for MatcherType constant definitions.

        The file contains lines like:
            ApkMatcher         MatcherType = "apk-matcher"
        and an AllMatcherTypes slice listing all active matchers.
        """
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Pattern: <Name> MatcherType = "<value>"
        for m in re.finditer(
            r'(\w+)\s+MatcherType\s*=\s*"([\w-]+)"', content
        ):
            const_name = m.group(1)
            matcher_type = m.group(2)

            # Skip UnknownMatcherType
            if "Unknown" in const_name:
                continue

            ecosystem, desc = MATCHER_INFO.get(
                matcher_type,
                (matcher_type.replace("-matcher", ""), f"Vulnerability matcher for {matcher_type}"),
            )

            rule_id = f"grype-matcher-{matcher_type}"
            self.upsert(
                rule_id,
                f"Grype {ecosystem} vulnerability matcher",
                severity="info",
                description=desc,
            )
            count += 1

        return count

    def _parse_matcher_constructors(self, fpath):
        """Parse matchers.go for matcher constructor calls.

        The file contains calls like:
            dpkg.NewDpkgMatcher(mc.Dpkg)
            &apk.Matcher{}
            stock.NewStockMatcher(mc.Stock)

        This is a secondary source — we may have already registered
        matchers from matcher_type.go. Skip duplicates by checking
        seen_rule_ids.
        """
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Pattern: <package>.New<Name>Matcher( or &<package>.Matcher{
        for m in re.finditer(
            r'(?:&(\w+)\.Matcher|(\w+)\.New\w*Matcher)', content
        ):
            pkg = m.group(1) or m.group(2)
            rule_id = f"grype-matcher-{pkg}"

            # Skip if already registered (from matcher_type.go)
            if rule_id in self.seen_rule_ids:
                continue

            ecosystem = pkg.capitalize()
            self.upsert(
                rule_id,
                f"Grype {ecosystem} vulnerability matcher",
                severity="info",
                description=f"Vulnerability matcher for {ecosystem} packages (from {pkg} matcher package)",
            )
            count += 1

        return count