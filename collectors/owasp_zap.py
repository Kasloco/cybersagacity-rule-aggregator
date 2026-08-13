"""Collector for OWASP ZAP DAST scanner rules.

OWASP ZAP (Zed Attack Proxy) is a free, open-source DAST scanner for web
applications. Rules include passive scanners (passive scan rules) and active
scanners (active scan rules) that test for common web vulnerabilities.
Rules are defined in add-ons as XML files or Java/Python scripts.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class OWASPZapCollector(BaseCollector):
    name = "owasp_zap"
    display_name = "OWASP ZAP"
    source_type = "github"
    source_url = "https://github.com/zaproxy/zaproxy.git"
    description = (
        "OWASP ZAP is a free, open-source web application security scanner. "
        "It provides passive and active scanning for web vulnerabilities including "
        "XSS, SQL injection, path traversal, and more. Supports HTTP/HTTPS, "
        "OpenAPI, SOAP, GraphQL, and other web/API technologies."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6201939"

    def collect_rules(self):
        count = 0

        # ZAP rules are in zaproxy/src/main/dist/xml/ as XML files
        xml_dir = os.path.join(self.clone_dir, "zaproxy", "src", "main", "dist", "xml")
        if os.path.isdir(xml_dir):
            for fname in os.listdir(xml_dir):
                if fname.endswith(".xml"):
                    fpath = os.path.join(xml_dir, fname)
                    count += self._parse_xml_rules(fpath)

        # Also check for scanner rules in source
        scanner_dir = os.path.join(self.clone_dir, "zaproxy", "src", "main", "java", "org")
        if os.path.isdir(scanner_dir):
            for root, dirs, files in os.walk(scanner_dir):
                for fname in files:
                    if fname.endswith(".java") and "Scanner" in fname:
                        fpath = os.path.join(root, fname)
                        count += self._parse_java_scanner(fpath)

        # Check for add-on rules
        addons_dir = os.path.join(self.clone_dir, "zap-extensions")
        if os.path.isdir(addons_dir):
            for root, dirs, files in os.walk(addons_dir):
                for fname in files:
                    if fname.endswith(".xml"):
                        fpath = os.path.join(root, fname)
                        count += self._parse_xml_rules(fpath)

        logger.info(f"[owasp_zap] Processed {count} rules")

    def _parse_xml_rules(self, fpath):
        """Parse ZAP XML rule files (e.g., zap.properties.xml, config.xml)."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        import xml.etree.ElementTree as ET

        try:
            root = ET.parse(fpath).getroot()
        except Exception:
            return 0

        # Look for scanner/rule entries
        for elem in root.iter():
            tag = elem.tag.lower()

            # Handle <scanner> or <rule> or <scanners> elements
            if any(t in tag for t in ["scanner", "rule", "scan"]):
                rule_id = elem.get("id") or elem.findtext("id")
                name = elem.get("name") or elem.findtext("name") or elem.text
                cwe = elem.get("cweid") or elem.findtext("cweid") or elem.get("cwe")
                severity = elem.get("level") or elem.findtext("level")
                desc = elem.get("desc") or elem.findtext("desc") or elem.get("description")

                if rule_id and name:
                    r_id = f"zap-{rule_id}"
                    self.upsert(
                        r_id,
                        name,
                        severity=severity.lower() if severity else "medium",
                        cwe_ids=f"CWE-{cwe}" if cwe else "",
                        description=desc[:500] if desc else None,
                        metadata={
                            "scan_type": elem.get("type", ""),
                            "wasc": elem.get("wascid") or elem.findtext("wascid") or "",
                        },
                    )
                    count += 1

        # If no structured rules found, look for plugin IDs
        if count == 0:
            for m in re.finditer(r'(?:id|pluginid)\s*[=:]\s*["\']?(\d+)', content, re.IGNORECASE):
                rule_id = f"zap-{m.group(1)}"
                self.upsert(
                    rule_id,
                    f"ZAP scanner rule {m.group(1)}",
                    severity="medium",
                    description=f"OWASP ZAP scanner rule ID {m.group(1)}",
                )
                count += 1

        return count

    def _parse_java_scanner(self, fpath):
        """Parse a ZAP Java scanner file for rule definitions."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0
        fname = os.path.basename(fpath).replace(".java", "")

        # Look for plugin ID definitions
        for m in re.finditer(r'pluginId\s*=\s*(\d+)', content):
            rule_id = f"zap-{m.group(1)}"
            self.upsert(
                rule_id,
                f"ZAP {fname}",
                severity="medium",
                description=f"OWASP ZAP scanner: {fname}",
            )
            count += 1

        # Look for @PluginId annotation
        for m in re.finditer(r'@PluginId\s*\(\s*(\d+)\s*\)', content):
            rule_id = f"zap-{m.group(1)}"
            self.upsert(
                rule_id,
                f"ZAP {fname} (plugin {m.group(1)})",
                severity="medium",
                description=f"OWASP ZAP active/passive scanner: {fname}",
            )
            count += 1

        return count