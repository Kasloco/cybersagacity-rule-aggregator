"""Collector for Joern code property graph analyzer rules.

Joern is an open-source code analysis platform that builds Code Property
Graphs (CPG) from source code. It supports C/C++, Java, JavaScript, Python,
Kotlin, and binary executables. Rules are defined as Scala scripts or
JSON queries that traverse the CPG to find vulnerability patterns.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class JoernCollector(BaseCollector):
    name = "joern"
    display_name = "Joern"
    source_type = "github"
    source_url = "https://github.com/joernio/joern.git"
    description = (
        "Joern is an open-source code analysis platform for C/C++, Java, "
        "JavaScript, Python, Kotlin, and binary executables. It builds Code "
        "Property Graphs (CPG) and provides query language for vulnerability "
        "research and data flow analysis."
    )
    logo_url = "https://avatars.githubusercontent.com/u/66766098"

    def collect_rules(self):
        count = 0

        # Joern rules may be in various locations
        # Check console/scanners/ for built-in scanners
        scanners_dir = os.path.join(self.clone_dir, "console", "scanners")
        if os.path.isdir(scanners_dir):
            for fname in os.listdir(scanners_dir):
                if fname.endswith(".sc") or fname.endswith(".scala"):
                    fpath = os.path.join(scanners_dir, fname)
                    count += self._parse_scanner(fpath)

        # Check for rules in joern-cli/src/main/resources/
        rules_dir = os.path.join(self.clone_dir, "joern-cli", "src", "main", "resources")
        if os.path.isdir(rules_dir):
            for root, dirs, files in os.walk(rules_dir):
                for fname in files:
                    if fname.endswith(".json") or fname.endswith(".sc"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_rule_file(fpath)

        # Check for query bundles in querydb/
        querydb_dir = os.path.join(self.clone_dir, "querydb", "src", "main", "resources")
        if os.path.isdir(querydb_dir):
            for root, dirs, files in os.walk(querydb_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if fname.endswith(".scala") or fname.endswith(".json"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_rule_file(fpath)

        logger.info(f"[joern] Processed {count} rules")

    def _parse_scanner(self, fpath):
        """Parse a Joern scanner (.sc) file for rule definitions."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        fname = os.path.basename(fpath)
        scanner_name = os.path.splitext(fname)[0]

        # Look for @QueryDef or def rule annotations
        # Pattern: @InputFile def myRule = cpg.method...
        for m in re.finditer(r'(?:@QueryDef|def)\s+(\w+)\s*[:=]', content):
            rule_name = m.group(1)
            rule_id = f"joern-{scanner_name}-{rule_name}"
            self.upsert(
                rule_id,
                f"Joern {scanner_name}: {rule_name}",
                severity="medium",
                description=f"Joern CPG query from {scanner_name} scanner.",
            )
            count += 1

        # If no individual rules found, register the scanner itself
        if count == 0:
            self.upsert(
                f"joern-scanner-{scanner_name}",
                f"Joern {scanner_name} scanner",
                severity="medium",
                description=f"Joern built-in scanner: {scanner_name}",
            )
            count += 1

        return count

    def _parse_rule_file(self, fpath):
        """Parse a Joern rule JSON or Scala file."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        fname = os.path.basename(fpath)
        rule_base = os.path.splitext(fname)[0]

        # For JSON files, look for rule definitions
        if fname.endswith(".json"):
            # Look for "name" or "id" fields
            for m in re.finditer(r'"(?:name|id|title)"\s*:\s*"([^"]+)"', content):
                rule_name = m.group(1)
                rule_id = f"joern-{rule_base}-{rule_name}"
                self.upsert(
                    rule_id,
                    f"Joern: {rule_name}",
                    severity="medium",
                    description=f"Joern CPG query rule: {rule_name}",
                )
                count += 1
            if count == 0:
                self.upsert(
                    f"joern-{rule_base}",
                    f"Joern rule: {rule_base}",
                    severity="medium",
                    description=f"Joern CPG query from {rule_base}",
                )
                count += 1
        elif fname.endswith(".scala"):
            for m in re.finditer(r'def\s+(\w+)\s*[:=]', content):
                rule_name = m.group(1)
                rule_id = f"joern-{rule_base}-{rule_name}"
                self.upsert(
                    rule_id,
                    f"Joern {rule_base}: {rule_name}",
                    severity="medium",
                    description=f"Joern CPG query from {rule_base}",
                )
                count += 1
            if count == 0:
                self.upsert(
                    f"joern-{rule_base}",
                    f"Joern rule: {rule_base}",
                    severity="medium",
                    description=f"Joern CPG query from {rule_base}",
                )
                count += 1

        return count