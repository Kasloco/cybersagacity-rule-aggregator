"""Collector for FindSecBugs (SpotBugs security plugin) rules."""

import os
import xml.etree.ElementTree as ET
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class FindSecBugsCollector(BaseCollector):
    name = "findsecbugs"
    display_name = "FindSecBugs"
    source_type = "github"
    source_url = "https://github.com/find-sec-bugs/find-sec-bugs.git"
    description = "SpotBugs security plugin for Java/Scala/Groovy. 140+ bug patterns covering injection, XSS, crypto, deserialization, and SSRF mapped to CWEs."
    logo_url = "https://avatars.githubusercontent.com/u/7321744"

    def collect_rules(self):
        count = 0
        # FindSecBugs defines patterns in XML files within the plugin
        for root, dirs, files in os.walk(self.clone_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if fname in ("findbugs.xml", "messages.xml"):
                    fpath = os.path.join(root, fname)
                    if fname == "messages.xml":
                        count += self._parse_messages_xml(fpath)

        logger.info(f"[findsecbugs] Processed {count} bug patterns")

    def _parse_messages_xml(self, fpath):
        """Parse messages.xml which contains bug pattern descriptions."""
        count = 0
        rel_path = os.path.relpath(fpath, self.clone_dir)

        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception as e:
            logger.debug(f"[findsecbugs] Failed to parse {fpath}: {e}")
            return 0

        for pattern in root.findall(".//BugPattern"):
            bug_type = pattern.get("type", "")
            if not bug_type:
                continue

            short_desc_el = pattern.find("ShortDescription")
            details_el = pattern.find("Details")
            long_desc_el = pattern.find("LongDescription")

            title = short_desc_el.text if short_desc_el is not None and short_desc_el.text else bug_type
            description = ""
            if details_el is not None and details_el.text:
                description = details_el.text.strip()[:2000]
            elif long_desc_el is not None and long_desc_el.text:
                description = long_desc_el.text.strip()[:2000]

            # Extract CWE from the pattern type or description
            cwe_ids = []
            category = pattern.get("category", "SECURITY")

            # Map common FindSecBugs categories to severity
            severity = "medium"
            high_patterns = ["SQL_INJECTION", "COMMAND_INJECTION", "LDAP_INJECTION",
                           "XPATH_INJECTION", "XXE", "DESERIALIZATION", "SSRF"]
            if any(p in bug_type.upper() for p in high_patterns):
                severity = "high"
            elif "XSS" in bug_type.upper():
                severity = "high"
            elif "CRYPTO" in bug_type.upper() or "CIPHER" in bug_type.upper():
                severity = "medium"
            elif "INFO" in bug_type.upper() or "LOG" in bug_type.upper():
                severity = "low"

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    full_content = f.read()
            except Exception:
                full_content = ""

            self.upsert(
                rule_id=bug_type,
                title=title[:500],
                description=description,
                severity=severity,
                category=category,
                language="java",
                cwe_ids=cwe_ids,
                tags=["spotbugs", "java", "sast", category.lower()],
                source_file=rel_path,
                rule_content=ET.tostring(pattern, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={"category": category, "type": bug_type},
            )
            count += 1

        return count
