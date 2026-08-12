"""Collector for SpotBugs (FindBugs successor) rules."""

import os
import xml.etree.ElementTree as ET
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class SpotBugsCollector(BaseCollector):
    name = "spotbugs"
    display_name = "SpotBugs"
    source_type = "github"
    source_url = "https://github.com/spotbugs/spotbugs.git"
    description = (
        "SpotBugs is the successor to FindBugs, a static analysis tool for Java. "
        "400+ bug patterns covering correctness, bad practice, performance, "
        "malicious code, security, and style."
    )
    logo_url = "https://avatars.githubusercontent.com/u/11835910"

    # SpotBugs categories that map to security-relevant findings.
    HIGH_CATEGORIES = {"SECURITY", "MALICIOUS_CODE"}
    LOW_CATEGORIES = {"STYLE", "I18N", "EXPERIMENTAL"}

    # Bug-type substrings that indicate high-severity patterns.
    HIGH_PATTERNS = [
        "SQL_INJECTION",
        "COMMAND_INJECTION",
        "LDAP_INJECTION",
        "XPATH_INJECTION",
        "INJECTION",
        "XXE",
        "DESERIALIZATION",
        "SSRF",
        "XSS",
        "CRYPTO",
        "CIPHER",
        "HARDCODE",
        "HARD_CODE",
        "PASSWORD",
    ]

    # Bug-type substrings that indicate low-severity patterns.
    LOW_PATTERNS = ["INFO", "LOG", "NOPMD", "NO_PMD"]

    def collect_rules(self):
        count = 0
        # SpotBugs defines patterns in etc/findbugs.xml and messages.xml files
        # scattered across the repository (e.g. spotbugs/src/main/resources,
        # eclipse-plugin, etc.).
        for root, dirs, files in os.walk(self.clone_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if fname in ("findbugs.xml", "messages.xml", "messages_*.xml"):
                    fpath = os.path.join(root, fname)
                    if fname == "findbugs.xml":
                        # findbugs.xml contains BugPattern elements with type
                        # and category but no descriptions; we still parse it
                        # to build a type→category map.
                        continue
                    # messages*.xml contains BugPattern elements with
                    # ShortDescription, Details, and LongDescription.
                    if fname.startswith("messages") and fname.endswith(".xml"):
                        count += self._parse_messages_xml(fpath)

        logger.info(f"[spotbugs] Processed {count} bug patterns")

    def _parse_messages_xml(self, fpath):
        """Parse messages*.xml which contains bug pattern descriptions."""
        count = 0
        rel_path = os.path.relpath(fpath, self.clone_dir)

        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception as e:
            logger.debug(f"[spotbugs] Failed to parse {fpath}: {e}")
            return 0

        # Build a type→category map from findbugs.xml in the same directory
        # (or the nearest parent etc/ dir) so we can enrich BugPattern entries
        # that lack a category attribute in messages.xml.
        category_map = self._load_category_map(fpath)

        for pattern in root.findall(".//BugPattern"):
            bug_type = pattern.get("type", "")
            if not bug_type:
                continue

            short_desc_el = pattern.find("ShortDescription")
            details_el = pattern.find("Details")
            long_desc_el = pattern.find("LongDescription")

            title = (
                short_desc_el.text
                if short_desc_el is not None and short_desc_el.text
                else bug_type
            )

            description = ""
            if details_el is not None and details_el.text:
                description = details_el.text.strip()[:2000]
            elif long_desc_el is not None and long_desc_el.text:
                description = long_desc_el.text.strip()[:2000]

            # Category: prefer the attribute on the BugPattern element;
            # fall back to the findbugs.xml map; finally default to
            # "CORRECTNESS" which is the most common SpotBugs category.
            category = (
                pattern.get("category")
                or category_map.get(bug_type)
                or "CORRECTNESS"
            )

            severity = self._map_severity(bug_type, category)

            # Preserve vendor-native fields in metadata.
            metadata = {
                "category": category,
                "type": bug_type,
                "short_description": title,
            }
            if long_desc_el is not None and long_desc_el.text:
                metadata["long_description"] = long_desc_el.text.strip()[:500]

            self.upsert(
                rule_id=bug_type,
                title=title[:500],
                description=description,
                severity=severity,
                category=category,
                language="java",
                cwe_ids=[],
                tags=["spotbugs", "java", "sast", category.lower()],
                source_file=rel_path,
                rule_content=ET.tostring(pattern, encoding="unicode")[:50000],
                rule_format="xml",
                metadata=metadata,
            )
            count += 1

        return count

    def _load_category_map(self, messages_fpath):
        """Load a type→category mapping from the nearest findbugs.xml.

        SpotBugs stores category information in findbugs.xml (BugPattern
        elements with ``type`` and ``category`` attributes) while the
        human-readable descriptions live in messages.xml.  We walk up from
        the messages.xml file to find a co-located findbugs.xml and build
        a lookup table.
        """
        category_map = {}
        parent = os.path.dirname(messages_fpath)
        for _ in range(5):  # search up to 5 levels up
            candidate = os.path.join(parent, "findbugs.xml")
            if os.path.isfile(candidate):
                try:
                    tree = ET.parse(candidate)
                    root = tree.getroot()
                    for bp in root.findall(".//BugPattern"):
                        btype = bp.get("type", "")
                        bcat = bp.get("category", "")
                        if btype and bcat:
                            category_map[btype] = bcat
                except Exception:
                    pass
                break
            new_parent = os.path.dirname(parent)
            if new_parent == parent:
                break
            parent = new_parent
        return category_map

    def _map_severity(self, bug_type, category):
        """Map a SpotBugs bug type + category to a severity level.

        - injection / crypto / XSS / hardcode-password patterns → high
        - info / logging patterns → low
        - low-priority categories (STYLE, I18N, EXPERIMENTAL) → low
        - high-priority categories (SECURITY, MALICIOUS_CODE) → high
        - everything else → medium
        """
        upper = bug_type.upper()

        # Pattern-based overrides take priority.
        for p in self.HIGH_PATTERNS:
            if p in upper:
                return "high"
        for p in self.LOW_PATTERNS:
            if p in upper:
                return "low"

        # Category-based fallback.
        if category in self.HIGH_CATEGORIES:
            return "high"
        if category in self.LOW_CATEGORIES:
            return "low"

        return "medium"