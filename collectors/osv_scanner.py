"""Collector for Google OSV-Scanner rules and checks.

OSV-Scanner is a Software Composition Analysis (SCA) scanner that scans
projects for known vulnerabilities using the OSV.dev database
(https://osv.dev). The tool itself doesn't define "rules" in the
traditional SAST sense — it matches package versions against the OSV
vulnerability database. However, the codebase contains internal
quality/config checks and vulnerability matching logic in pkg/ that
document the scanner's behavior.

This collector parses the Go source in pkg/ for:
  - Lockfile parsers (each parser is a "check" that maps to a language)
  - Remediation / overlay checks
  - Configuration validation rules
  - Any constant-based rule IDs or check names

Where no traditional rules exist, we document the available checks as
rule entries so the aggregator has visibility into OSV-Scanner's
capabilities.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Map parser/lockfile names to languages
LANGUAGE_MAP = {
    "lockfile": "multi",
    "composer": "php",
    "gemfile": "ruby",
    "package-lock": "javascript",
    "yarn": "javascript",
    "pnpm-lock": "javascript",
    "gradle": "java",
    "maven": "java",
    "go": "go",
    "gomod": "go",
    "cargo": "rust",
    "pip": "python",
    "poetry": "python",
    "requirements": "python",
    "nuget": "csharp",
    "csproj": "csharp",
    "alpine": "linux",
    "debian": "linux",
    "dpkg": "linux",
    "rpm": "linux",
    "apk": "alpine",
}


class OSVScannerCollector(BaseCollector):
    name = "osv_scanner"
    display_name = "OSV-Scanner"
    source_type = "github"
    source_url = "https://github.com/google/osv-scanner.git"
    description = (
        "OSV-Scanner is a Software Composition Analysis tool that scans "
        "project dependencies against the OSV.dev vulnerability database. "
        "It supports lockfile parsing across many languages, OS packages, "
        "and Maven/Go/Python projects. Findings are mapped to OSV IDs "
        "which link to CVE and CWE records."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1342004"

    def collect_rules(self):
        """Parse pkg/ Go source for parser definitions and check constants."""
        count = 0

        # Parse lockfile parsers — each is a "check" the scanner can perform
        pkg_dir = os.path.join(self.clone_dir, "pkg")
        if not os.path.isdir(pkg_dir):
            logger.warning("[osv_scanner] pkg/ directory not found")
            return

        # Walk pkg/ for Go files
        for root, dirs, files in os.walk(pkg_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in sorted(files):
                if not fname.endswith(".go") or fname.endswith("_test.go"):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_go_file(fpath, rel_path)

        logger.info(f"[osv_scanner] Processed {count} checks/rules")

    def _parse_go_file(self, fpath, rel_path):
        """Parse a Go file for parser definitions, check constants, and rule-like patterns."""
        count = 0

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # 1) Find lockfile parser definitions
        #    Pattern: func ParseXxx(...) (Lockfile, error)  or
        #             type XxxParser struct { ... }
        parser_matches = re.finditer(
            r'func\s+(?:\([^)]+\)\s+)?(Parse\w+(?:Lockfile|File|Graph)?)\s*\(',
            content,
        )
        for m in parser_matches:
            func_name = m.group(1)
            rule_id = f"osv-scanner:parser:{func_name}"

            # Derive language from the parser name
            name_lower = func_name.lower()
            language = "multi"
            for key, lang in LANGUAGE_MAP.items():
                if key in name_lower:
                    language = lang
                    break

            self.upsert(
                rule_id=rule_id,
                title=f"OSV-Scanner parser: {func_name}"[:500],
                description=(
                    f"Lockfile/dependency parser '{func_name}' in OSV-Scanner. "
                    f"Parses dependency manifests to identify installed packages "
                    f"for vulnerability scanning against OSV.dev."
                ),
                severity="medium",
                category="dependency-parsing",
                language=language,
                cwe_ids=["CWE-1104"],  # Use of Unmaintained Third Party Components
                owasp_ids=["A06:2021"],  # Vulnerable and Outdated Components
                tags=["osv-scanner", "sca", "dependency", "parser", language],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="go",
                metadata={
                    "parser_name": func_name,
                    "language": language,
                    "source": "lockfile-parser",
                },
            )
            count += 1

        # 2) Find any constant-based rule/check IDs
        #    Pattern: const XxxCheck = "..." or RuleXxx = "..."
        const_matches = re.finditer(
            r'const\s+(\w*(?:Check|Rule|Config|Validator)\w*)\s*=\s*"([^"]+)"',
            content,
        )
        for m in const_matches:
            const_name = m.group(1)
            const_val = m.group(2)
            rule_id = f"osv-scanner:{const_val}"

            self.upsert(
                rule_id=rule_id,
                title=f"OSV-Scanner check: {const_name}"[:500],
                description=(
                    f"OSV-Scanner configuration check '{const_name}' "
                    f"(value: {const_val}). Internal validation or quality "
                    f"check used during scanning."
                ),
                severity="low",
                category="configuration",
                language="go",
                cwe_ids=[],
                tags=["osv-scanner", "sca", "config", "check"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="go",
                metadata={
                    "const_name": const_name,
                    "const_value": const_val,
                    "source": "constant",
                },
            )
            count += 1

        # 3) Find vulnerability remediation rules
        #    Pattern: func.*[Rr]emedia or func.*[Aa]dvisory
        if re.search(r"func\s+\w*(?:Remedia|Advisory|Vulnerability|Override)\w*\s*\(", content):
            # This file deals with vulnerability advisory/remediation logic
            fname = os.path.basename(fpath)
            rule_id = f"osv-scanner:advisory:{fname.replace('.go', '')}"

            # Only upsert if not already captured by parser/const patterns
            if rule_id not in self.seen_rule_ids:
                self.upsert(
                    rule_id=rule_id,
                    title=f"OSV-Scanner advisory logic: {fname}"[:500],
                    description=(
                        f"Vulnerability advisory or remediation logic in "
                        f"{fname}. Handles vulnerability matching, "
                        f"remediation suggestions, or advisory overrides "
                        f"during OSV.dev database queries."
                    ),
                    severity="medium",
                    category="vulnerability-advisory",
                    language="go",
                    cwe_ids=[],
                    owasp_ids=["A06:2021"],
                    tags=["osv-scanner", "sca", "advisory", "remediation"],
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="go",
                    metadata={
                        "file": fname,
                        "source": "advisory-logic",
                    },
                )
                count += 1

        return count