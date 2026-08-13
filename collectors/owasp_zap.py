"""Collector for OWASP ZAP scanner rules.

OWASP ZAP (Zed Attack Proxy) is a free, open-source DAST scanner for web
applications. Rules include passive and active scanners.

The zaproxy repo contains:
  - Built-in Java scanner classes (ScriptsActiveScanner, ScriptsPassiveScanner,
    StatsPassiveScanner, RegexAutoTagScanner) with hard-coded plugin IDs.
  - config.xml with passive auto-tag scanner definitions.
  - Example XML scan reports that enumerate built-in scan rule IDs with
    names, CWE IDs, WASC IDs, risk levels, descriptions, solutions, and
    references.
  - Integration test result files listing rule IDs and names.

Most ZAP scan rules live in add-ons (zaproxy/zap-extensions), but the core
repo contains a representative set that we collect here.
"""

import os
import re
import glob
import logging
import xml.etree.ElementTree as ET

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Risk code → severity mapping (from Alert.java: RISK_INFO=0, RISK_LOW=1,
# RISK_MEDIUM=2, RISK_HIGH=3)
_RISK_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


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

        # 1) Parse built-in Java scanner classes for plugin IDs
        count += self._parse_java_scanners()

        # 2) Parse config.xml passive auto-tag scanners
        count += self._parse_config_xml()

        # 3) Parse example XML reports (richest source of rule metadata)
        count += self._parse_example_reports()

        # 4) Parse integration test result files for rule IDs and names
        count += self._parse_test_results()

        # 5) Parse Messages.properties for scanner rule name strings
        count += self._parse_messages_properties()

        logger.info(f"[owasp_zap] Processed {count} rules")

    # ------------------------------------------------------------------
    # Built-in Java scanner classes
    # ------------------------------------------------------------------

    def _parse_java_scanners(self):
        """Find Java classes implementing Plugin/PluginPassiveScanner and
        extract their IDs, names, risk, CWE, and WASC from the source."""
        count = 0
        java_root = os.path.join(
            self.clone_dir, "zap", "src", "main", "java"
        )
        if not os.path.isdir(java_root):
            return 0

        # Classes that extend scanner base classes
        scanner_patterns = [
            r"class\s+\w+\s+extends\s+AbstractAppParamPlugin",
            r"class\s+\w+\s+extends\s+AbstractAppPlugin",
            r"class\s+\w+\s+extends\s+AbstractHostPlugin",
            r"class\s+\w+\s+extends\s+AbstractPlugin",
            r"class\s+\w+\s+extends\s+PluginPassiveScanner",
            r"class\s+\w+\s+implements\s+Plugin\b",
        ]

        for root, dirs, files in os.walk(java_root):
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                is_scanner = any(
                    re.search(p, content) for p in scanner_patterns
                )
                if not is_scanner:
                    continue

                class_name = fname.replace(".java", "")
                rel_path = os.path.relpath(fpath, self.clone_dir)

                # Extract plugin ID (getId or getPluginId)
                plugin_id = None
                m = re.search(
                    r"public\s+int\s+get(?:Plugin)?Id\s*\(\s*\)\s*\{\s*return\s+(\d+)",
                    content,
                )
                if m:
                    plugin_id = m.group(1)

                # Extract name (from getName returning Constant.messages.getString)
                name = class_name
                m = re.search(
                    r'public\s+String\s+getName\s*\(\s*\)\s*\{\s*'
                    r'(?:return\s+Constant\.messages\.getString\(\s*"([^"]+)"\))?',
                    content,
                )
                if m and m.group(1):
                    # Look up in Messages.properties later; for now use the key
                    name = m.group(1)

                # Extract risk level
                risk = "medium"
                m = re.search(
                    r"public\s+int\s+getRisk\s*\(\s*\)\s*\{\s*"
                    r"return\s+Alert\.RISK_(\w+)",
                    content,
                )
                if m:
                    risk_name = m.group(1).upper()
                    risk = {
                        "INFO": "info",
                        "LOW": "low",
                        "MEDIUM": "medium",
                        "HIGH": "high",
                    }.get(risk_name, "medium")

                # Extract CWE ID
                cwe_id = ""
                m = re.search(
                    r"public\s+int\s+getCweId\s*\(\s*\)\s*\{\s*return\s+(\d+)",
                    content,
                )
                if m and m.group(1) != "0":
                    cwe_id = f"CWE-{m.group(1)}"

                # Extract WASC ID
                wasc_id = ""
                m = re.search(
                    r"public\s+int\s+getWascId\s*\(\s*\)\s*\{\s*return\s+(\d+)",
                    content,
                )
                if m and m.group(1) != "0":
                    wasc_id = m.group(1)

                # Extract description
                desc = ""
                m = re.search(
                    r'public\s+String\s+getDescription\s*\(\s*\)\s*\{\s*'
                    r'return\s+"([^"]+)"',
                    content,
                )
                if m:
                    desc = m.group(1)
                elif m and m.group(1) == "N/A":
                    desc = f"OWASP ZAP built-in scanner: {class_name}"

                if plugin_id:
                    rule_id = f"zap-{plugin_id}"
                    self.upsert(
                        rule_id,
                        name if not name.startswith("ascan.") and not name.startswith("pscan.")
                        else class_name,
                        severity=risk,
                        cwe_ids=[cwe_id] if cwe_id else [],
                        category="dast",
                        language="java",
                        description=desc or f"OWASP ZAP scanner: {class_name}",
                        tags=["zap", "scanner", "built-in"],
                        source_file=rel_path,
                        rule_content=content[:50000],
                        rule_format="java",
                        metadata={
                            "plugin_id": plugin_id,
                            "class_name": class_name,
                            "wasc_id": wasc_id,
                            "scan_type": "active" if "ascan" in rel_path else "passive",
                        },
                    )
                    count += 1

        return count

    # ------------------------------------------------------------------
    # config.xml — passive auto-tag scanners
    # ------------------------------------------------------------------

    def _parse_config_xml(self):
        """Parse the config.xml file for passive auto-tag scanner definitions."""
        fpath = os.path.join(
            self.clone_dir,
            "zap", "src", "main", "resources",
            "org", "zaproxy", "zap", "resources", "config.xml",
        )
        if not os.path.isfile(fpath):
            return 0

        try:
            tree = ET.parse(fpath)
        except ET.ParseError:
            return 0

        root = tree.getroot()
        count = 0

        for scanner in root.iter("scanner"):
            name_elem = scanner.find("name")
            if name_elem is None or not name_elem.text:
                continue

            scanner_name = name_elem.text.strip()
            stype = scanner.findtext("type", "")
            config = scanner.findtext("config", "")
            enabled = scanner.findtext("enabled", "true")
            res_body = scanner.findtext("resBodyRegex", "")
            res_head = scanner.findtext("resHeadRegex", "")
            req_url = scanner.findtext("reqUrlRegex", "")

            rule_id = f"zap-autotag-{scanner_name}"
            desc_parts = [f"ZAP passive auto-tag scanner: {scanner_name}"]
            if stype:
                desc_parts.append(f"Type: {stype}")
            if config:
                desc_parts.append(f"Tag: {config}")
            if res_body:
                desc_parts.append(f"Response body regex: {res_body}")
            if res_head:
                desc_parts.append(f"Response header regex: {res_head}")
            if req_url:
                desc_parts.append(f"Request URL regex: {req_url}")

            self.upsert(
                rule_id,
                f"Auto-Tag Scanner: {scanner_name}",
                severity="info",
                category="passive-scan",
                language="xml",
                cwe_ids=[],
                tags=["zap", "passive", "auto-tag", stype.lower() if stype else ""],
                source_file=os.path.relpath(fpath, self.clone_dir),
                rule_content=ET.tostring(scanner, encoding="unicode"),
                rule_format="xml",
                metadata={
                    "scanner_name": scanner_name,
                    "type": stype,
                    "config_tag": config,
                    "enabled": enabled == "true",
                },
            )
            count += 1

        return count

    # ------------------------------------------------------------------
    # Example XML reports — richest source of rule metadata
    # ------------------------------------------------------------------

    def _parse_example_reports(self):
        """Parse example ZAP XML reports for alert/rule definitions with
        full metadata (plugin ID, name, risk, CWE, WASC, description,
        solution, reference)."""
        count = 0
        seen_ids = set()

        report_files = glob.glob(
            os.path.join(self.clone_dir, "examples", "*.xml")
        )
        # Also check docker integration test results
        report_files += glob.glob(
            os.path.join(
                self.clone_dir, "docker", "integration_tests", "results", "*.out"
            )
        )

        for fpath in report_files:
            if fpath.endswith(".xml"):
                count += self._parse_xml_report(fpath, seen_ids)
            elif fpath.endswith(".out"):
                count += self._parse_out_file(fpath, seen_ids)

        return count

    def _parse_xml_report(self, fpath, seen_ids):
        """Parse a single ZAP XML report file."""
        count = 0
        try:
            tree = ET.parse(fpath)
        except ET.ParseError:
            return 0

        root = tree.getroot()
        rel_path = os.path.relpath(fpath, self.clone_dir)

        for alertitem in root.iter("alertitem"):
            plugin_id = alertitem.findtext("pluginid", "")
            if not plugin_id:
                continue

            alert_name = alertitem.findtext("alert", "")
            riskcode = alertitem.findtext("riskcode", "0")
            desc = alertitem.findtext("desc", "")
            solution = alertitem.findtext("solution", "")
            reference = alertitem.findtext("reference", "")
            cweid = alertitem.findtext("cweid", "")
            wascid = alertitem.findtext("wascid", "")

            rule_id = f"zap-{plugin_id}"

            # Skip duplicates across multiple reports
            if plugin_id in seen_ids:
                continue
            seen_ids.add(plugin_id)

            severity = _RISK_MAP.get(riskcode, "medium")

            cwe_ids = [f"CWE-{cweid}"] if cweid and cweid != "0" else []

            # Clean HTML entities from description
            desc_clean = re.sub(r"<[^>]+>", "", desc).strip() if desc else ""
            desc_final = desc_clean[:2000] if desc_clean else alert_name

            # Build metadata
            metadata = {
                "plugin_id": plugin_id,
                "wasc_id": wascid if wascid and wascid != "0" else "",
                "riskcode": riskcode,
                "solution": solution[:500] if solution else "",
                "reference": reference[:500] if reference else "",
            }

            self.upsert(
                rule_id,
                alert_name or f"ZAP Rule {plugin_id}",
                severity=severity,
                cwe_ids=cwe_ids,
                category="dast",
                language="",
                description=desc_final,
                tags=["zap", "scanner"],
                source_file=rel_path,
                rule_content=desc[:50000],
                rule_format="xml",
                metadata=metadata,
            )
            count += 1

        return count

    def _parse_out_file(self, fpath, seen_ids):
        """Parse ZAP integration test .out result files for rule IDs/names."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        rel_path = os.path.relpath(fpath, self.clone_dir)

        # Lines like:
        #   WARN-NEW: Re-examine Cache-control Directives [10015] x X
        #   FAIL-NEW: X-Content-Type-Options Header Missing [10021] x X
        #   INFO: Strict-Transport-Security Header Not Set [10035] x X
        #   IGNORE: Storable and Cacheable Content [10049] x X
        pattern = re.compile(
            r"(?:WARN|FAIL|INFO|IGNORE)(?:-NEW|-INPROG)?\s*:\s*(.+?)\s*\[(\d+)\]"
        )

        for m in pattern.finditer(content):
            name = m.group(1).strip()
            plugin_id = m.group(2).strip()

            if plugin_id in seen_ids:
                continue
            seen_ids.add(plugin_id)

            rule_id = f"zap-{plugin_id}"

            # Determine severity from the prefix
            line_start = content[: m.start()].rsplit("\n", 1)[-1] if "\n" in content[: m.start()] else ""
            if "FAIL" in line_start:
                severity = "high"
            elif "WARN" in line_start:
                severity = "medium"
            elif "INFO" in line_start:
                severity = "info"
            else:
                severity = "low"

            self.upsert(
                rule_id,
                name,
                severity=severity,
                cwe_ids=[],
                category="dast",
                language="",
                description=f"ZAP scanner rule: {name} (plugin ID {plugin_id})",
                tags=["zap", "scanner", "passive"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="text",
                metadata={
                    "plugin_id": plugin_id,
                    "source": "integration_test_result",
                },
            )
            count += 1

        return count

    # ------------------------------------------------------------------
    # Integration test results (.out files)
    # ------------------------------------------------------------------

    def _parse_test_results(self):
        """Parse .out test result files for rule IDs and names."""
        # Already handled in _parse_example_reports via glob
        return 0

    # ------------------------------------------------------------------
    # Messages.properties — scanner rule name strings
    # ------------------------------------------------------------------

    def _parse_messages_properties(self):
        """Parse Messages.properties for scanner-related i18n keys and
        register any that reference rule IDs not already seen."""
        fpath = os.path.join(
            self.clone_dir,
            "zap", "src", "main", "resources",
            "org", "zaproxy", "zap", "resources", "Messages.properties",
        )
        if not os.path.isfile(fpath):
            return 0

        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        rel_path = os.path.relpath(fpath, self.clone_dir)
        count = 0

        # Parse scanner category names
        for m in re.finditer(
            r"^scanner\.category\.(\w+)\s*=\s*(.+)$", content, re.MULTILINE
        ):
            cat_key = m.group(1)
            cat_name = m.group(2).strip()
            rule_id = f"zap-category-{cat_key}"

            self.upsert(
                rule_id,
                f"Scanner Category: {cat_name}",
                severity="info",
                category="scanner-category",
                language="java",
                cwe_ids=[],
                description=f"ZAP scanner category: {cat_name}",
                tags=["zap", "category"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="properties",
                metadata={
                    "category_key": cat_key,
                    "category_name": cat_name,
                },
            )
            count += 1

        # Parse scanner rule titles from ascan.scripts and pscan.scripts
        script_keys = [
            ("ascan.scripts.activescanner.title", "Active Script Scanner", "50000", "active"),
            ("pscan.scripts.passivescanner.title", "Passive Script Scanner", "50001", "passive"),
            ("pscan.stats.passivescanner.title", "Stats Passive Scanner", "50003", "passive"),
        ]

        for key, default_name, plugin_id, scan_type in script_keys:
            m = re.search(
                rf"^{re.escape(key)}\s*=\s*(.+)$", content, re.MULTILINE
            )
            if m:
                name = m.group(1).strip()
                rule_id = f"zap-{plugin_id}"
                # Only add if not already seen
                if rule_id not in self.seen_rule_ids:
                    self.upsert(
                        rule_id,
                        name,
                        severity="info",
                        category="dast",
                        language="java",
                        cwe_ids=[],
                        description=f"ZAP {scan_type} scanner: {name}",
                        tags=["zap", "scanner", scan_type],
                        source_file=rel_path,
                        rule_content=content[:50000],
                        rule_format="properties",
                        metadata={
                            "plugin_id": plugin_id,
                            "i18n_key": key,
                            "scan_type": scan_type,
                        },
                    )
                    count += 1

        return count