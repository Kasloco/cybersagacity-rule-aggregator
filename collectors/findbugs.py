"""Collector for FindBugs (legacy Java bug pattern analyzer).

FindBugs is the predecessor to SpotBugs. It uses static analysis to find
bugs in Java code. Although archived/legacy, Chris Near's spreadsheet
marks it as "Yes" for SATriage support. Rules are defined as XML bug
pattern descriptions in the findbugs repository.

This collector extracts bug pattern definitions from the XML files that
ship with FindBugs. Each bug pattern has a unique abbreviation (e.g., NP,
BC, DLS), a category, and a description.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class FindBugsCollector(BaseCollector):
    name = "findbugs"
    display_name = "FindBugs"
    source_type = "github"
    source_url = "https://github.com/findbugsproject/findbugs.git"
    description = (
        "FindBugs is a Java static analysis tool that looks for bugs in "
        "Java code. It is the predecessor to SpotBugs. Uses XML-defined "
        "bug patterns with abbreviations like NP (null pointer), BC (bad "
        "cast), DLS (dead local store), etc. Archived/legacy but still "
        "referenced in SATriage."
    )
    logo_url = "https://avatars.githubusercontent.com/u/3739502"

    def collect_rules(self):
        count = 0

        # FindBugs bug patterns are in findbugs/etc/findbugs.xml or
        # findbugs/src/xml/bugpatterns.xml
        xml_candidates = [
            os.path.join(self.clone_dir, "findbugs", "etc", "findbugs.xml"),
            os.path.join(self.clone_dir, "findbugs", "etc", "bugpatterns.xml"),
            os.path.join(self.clone_dir, "findbugs", "src", "xml", "bugpatterns.xml"),
            os.path.join(self.clone_dir, "etc", "findbugs.xml"),
            os.path.join(self.clone_dir, "etc", "bugpatterns.xml"),
        ]

        for xml_path in xml_candidates:
            if os.path.isfile(xml_path):
                count += self._parse_xml(xml_path)

        # Also check for BugPattern annotations in Java source
        java_dir = os.path.join(self.clone_dir, "findbugs", "src", "java")
        if os.path.isdir(java_dir):
            for root, dirs, files in os.walk(java_dir):
                for fname in files:
                    if fname.endswith(".java"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_java(fpath)

        # If no XML found, try searching recursively
        if count == 0:
            for root, dirs, files in os.walk(self.clone_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if fname == "findbugs.xml" or fname == "bugpatterns.xml":
                        fpath = os.path.join(root, fname)
                        count += self._parse_xml(fpath)

        logger.info(f"[findbugs] Processed {count} rules")

    def _parse_xml(self, fpath):
        """Parse FindBugs XML bug pattern definitions."""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception as e:
            logger.warning(f"[findbugs] Could not parse {fpath}: {e}")
            return 0

        count = 0

        # Bug patterns are defined as <BugPattern> elements
        for elem in root.iter():
            if "BugPattern" in elem.tag:
                abbrev = elem.get("abbrev") or elem.get("abbreviation")
                code = elem.get("code") or elem.get("type")
                category = elem.get("category")
                details = elem.findtext("Details") if elem.find("Details") is not None else None

                # Build rule ID from abbreviation and code
                rule_id = code or abbrev
                if not rule_id:
                    continue

                title = elem.get("shortDescription") or rule_id

                self.upsert(
                    rule_id,
                    title,
                    severity="medium",
                    description=f"FindBugs {category or ''} bug pattern: {title}",
                    metadata={
                        "abbrev": abbrev or "",
                        "category": category or "",
                        "details": (details[:500] if details else ""),
                    },
                )
                count += 1

        return count

    def _parse_java(self, fpath):
        """Parse Java files for @BugPattern-like annotations."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        fname = os.path.basename(fpath).replace(".java", "")

        # Look for bug pattern definitions in comments or annotations
        # Pattern: @BugPattern or bugPattern definitions
        for m in re.finditer(r'(?:@BugPattern|BugPattern)\s*\([^)]*abbrev\s*=\s*"(\w+)"', content):
            abbrev = m.group(1)
            rule_id = f"FB-{abbrev}"
            self.upsert(
                rule_id,
                f"FindBugs {abbrev} pattern",
                severity="medium",
                description=f"FindBugs bug pattern: {abbrev}",
            )
            count += 1

        return count