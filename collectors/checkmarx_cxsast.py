"""Collector for Checkmarx CxSAST v9 rules.

Checkmarx CxSAST v9 is a commercial SAST scanner. Chris Near's spreadsheet
marks it as "Yes" for SATriage support. The rules are not in a public
GitHub repo, but Checkmarx publishes rule documentation and some rule
definitions in their support portal.

This collector uses a file-based import approach. Set the
CXSAST_RULES_DIR environment variable to point to a directory containing
CxSAST rule exports (XML, JSON, or SARIF format). The BaseCollector.sync()
method skips clone/pull for source_type != "github", so this works
without a repo.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class CheckmarxCxSASTCollector(BaseCollector):
    name = "checkmarx_cxsast"
    display_name = "Checkmarx CxSAST v9"
    source_type = "file"
    source_url = "https://checkmarx.com/support/portal"
    description = (
        "Checkmarx CxSAST v9 is a commercial static application security "
        "testing (SAST) scanner. Supports Java, JavaScript, TypeScript, "
        "C#, C/C++, Go, PHP, Ruby, Python, Swift, Kotlin, and more. Rules "
        "are imported from XML/JSON/SARIF exports via CXSAST_RULES_DIR."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1809556"

    def collect_rules(self):
        count = 0
        rules_dir = os.environ.get("CXSAST_RULES_DIR", "")

        if not rules_dir or not os.path.isdir(rules_dir):
            logger.info("[checkmarx_cxsast] No CXSAST_RULES_DIR set; skipping file import")
            return

        for fname in os.listdir(rules_dir):
            fpath = os.path.join(rules_dir, fname)
            if fname.endswith(".xml"):
                count += self._parse_xml(fpath)
            elif fname.endswith(".json"):
                count += self._parse_json(fpath)
            elif fname.endswith(".sarif"):
                count += self._parse_sarif(fpath)

        logger.info(f"[checkmarx_cxsast] Processed {count} rules")

    def _parse_xml(self, fpath):
        """Parse Checkmarx XML rule export."""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception:
            return 0

        count = 0
        for elem in root.iter():
            tag = elem.tag.lower()
            if "rule" in tag or "query" in tag:
                rule_id = elem.get("id") or elem.get("name") or elem.findtext("id")
                name = elem.get("name") or elem.findtext("name") or elem.text
                cwe = elem.get("cweId") or elem.findtext("cweId")
                severity = elem.get("severity") or elem.findtext("severity")

                if rule_id and name:
                    self.upsert(
                        str(rule_id),
                        str(name),
                        severity=str(severity).lower() if severity else "medium",
                        cwe_ids=f"CWE-{cwe}" if cwe else "",
                        description=str(name),
                    )
                    count += 1
        return count

    def _parse_json(self, fpath):
        """Parse Checkmarx JSON rule export."""
        import json
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
        except Exception:
            return 0

        count = 0
        rules = data if isinstance(data, list) else data.get("rules", data.get("queries", []))
        for rule in rules:
            if isinstance(rule, dict):
                rule_id = rule.get("id") or rule.get("name") or rule.get("queryId")
                name = rule.get("name") or rule.get("queryName") or rule_id
                cwe = rule.get("cweId") or rule.get("cwe")
                severity = rule.get("severity", "medium")
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
                name = rule.get("name") or rule_id
                if rule_id:
                    cwe_ids = ""
                    for tag in rule.get("tags", []):
                        m = re.match(r'cwe-(\d+)', tag, re.IGNORECASE)
                        if m:
                            cwe_ids = f"CWE-{m.group(1)}"
                            break
                    self.upsert(
                        str(rule_id),
                        str(name),
                        severity="medium",
                        cwe_ids=cwe_ids,
                        description=rule.get("fullDescription", {}).get("text", ""),
                    )
                    count += 1
        return count