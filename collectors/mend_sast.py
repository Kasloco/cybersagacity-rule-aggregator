"""Collector for Mend SAST (formerly WhiteSource) rules.

Mend (formerly WhiteSource) is a commercial SAST scanner. Chris Near's
spreadsheet marks Mend SAST as "No importer" and Mend Application Security
Platform as "Yes/No". The rules are not in a public GitHub repo.

This collector uses a file-based import approach. Set the
MEND_RULES_DIR environment variable to point to a directory containing
Mend rule exports (JSON, XML, or SARIF format).
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class MendCollector(BaseCollector):
    name = "mend_sast"
    display_name = "Mend SAST"
    source_type = "file"
    source_url = "https://www.mend.io/"
    description = (
        "Mend SAST (formerly WhiteSource) is a commercial static application "
        "security testing scanner. Supports C#, C/C++, Go, Java, JavaScript, "
        "TypeScript, Kotlin, PHP, Python, Ruby, Rust, VB.NET and more. Rules "
        "are imported from JSON/XML/SARIF exports via MEND_RULES_DIR."
    )
    logo_url = "https://avatars.githubusercontent.com/u/20115796"

    def collect_rules(self):
        count = 0
        rules_dir = os.environ.get("MEND_RULES_DIR", "")

        if not rules_dir or not os.path.isdir(rules_dir):
            logger.info("[mend_sast] No MEND_RULES_DIR set; skipping file import")
            return

        for fname in os.listdir(rules_dir):
            fpath = os.path.join(rules_dir, fname)
            if fname.endswith(".json"):
                count += self._parse_json(fpath)
            elif fname.endswith(".xml"):
                count += self._parse_xml(fpath)
            elif fname.endswith(".sarif"):
                count += self._parse_sarif(fpath)

        logger.info(f"[mend_sast] Processed {count} rules")

    def _parse_json(self, fpath):
        """Parse Mend JSON rule export."""
        import json
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
        except Exception:
            return 0

        count = 0
        rules = data if isinstance(data, list) else data.get("rules", data.get("vulnerabilities", []))
        for rule in rules:
            if isinstance(rule, dict):
                rule_id = rule.get("id") or rule.get("name") or rule.get("vulnerability")
                name = rule.get("name") or rule.get("title") or rule_id
                severity = rule.get("severity", "medium")
                cwe = rule.get("cwe") or rule.get("cweId")

                if rule_id:
                    self.upsert(
                        str(rule_id),
                        str(name),
                        severity=str(severity).lower(),
                        cwe_ids=f"CWE-{cwe}" if cwe else "",
                        description=str(name),
                    )
                    count += 1
        return count

    def _parse_xml(self, fpath):
        """Parse Mend XML rule export."""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception:
            return 0

        count = 0
        for elem in root.iter():
            tag = elem.tag.lower()
            if "rule" in tag or "vulnerability" in tag:
                rule_id = elem.get("id") or elem.get("name") or elem.findtext("id")
                name = elem.get("name") or elem.findtext("name") or rule_id
                cwe = elem.get("cweId") or elem.findtext("cweId")
                severity = elem.get("severity") or elem.findtext("severity")

                if rule_id:
                    self.upsert(
                        str(rule_id),
                        str(name),
                        severity=str(severity).lower() if severity else "medium",
                        cwe_ids=f"CWE-{cwe}" if cwe else "",
                    )
                    count += 1
        return count

    def _parse_sarif(self, fpath):
        """Parse SARIF format rule export."""
        import json
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
        except Exception:
            return 0

        count = 0
        for run in data.get("runs", []):
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id")
                if rule_id:
                    self.upsert(
                        str(rule_id),
                        str(rule.get("name", rule_id)),
                        severity="medium",
                        description=rule.get("fullDescription", {}).get("text", ""),
                    )
                    count += 1
        return count