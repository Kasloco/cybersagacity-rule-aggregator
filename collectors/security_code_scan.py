"""Collector for SecurityCodeScan (.NET security analyzer) rules.

SecurityCodeScan is a Roslyn-based diagnostic analyzer for C# and VB.NET.
Rules use SCSxxxx codes and are defined in:
  - SecurityCodeScan/Analyzers/*.cs — analyzer classes with DiagnosticId constants
  - SecurityCodeScan/Config/Messages.yml — rule titles, descriptions, and CWE mappings

The Messages.yml file is the authoritative source for rule metadata (title,
description, CWE). The analyzer .cs files define which diagnostic IDs exist.
We parse both to get the complete picture.
"""

import os
import re
import logging

import yaml

from .base import BaseCollector

logger = logging.getLogger(__name__)


class SecurityCodeScanCollector(BaseCollector):
    name = "security_code_scan"
    display_name = "SecurityCodeScan"
    source_type = "github"
    source_url = "https://github.com/security-code-scan/security-code-scan.git"
    description = (
        "SecurityCodeScan is a .NET static analysis tool that detects "
        "security vulnerabilities including SQL injection, XSS, command "
        "injection, XXE, weak crypto, insecure cookies, path traversal, "
        "open redirect, LDAP injection, unsafe deserialization, and more. "
        "Rules use SCSxxxx codes and are mapped to CWEs."
    )
    logo_url = "https://avatars.githubusercontent.com/u/33061329"

    def collect_rules(self):
        count = 0

        # Parse Messages.yml for rule metadata (title, description, CWE)
        messages = self._parse_messages_yml()

        # Parse analyzer .cs files for diagnostic IDs
        analyzer_ids = self._parse_analyzer_files()

        # If we have messages, use them; otherwise use analyzer IDs
        all_ids = set(messages.keys()) | set(analyzer_ids.keys())

        for scs_id in sorted(all_ids):
            msg_info = messages.get(scs_id, {})
            analyzer_info = analyzer_ids.get(scs_id, {})

            title = msg_info.get("title", f"SecurityCodeScan {scs_id}")
            description = msg_info.get("description", title)
            cwe = msg_info.get("cwe")
            source_file = analyzer_info.get("source_file",
                                            "SecurityCodeScan/Config/Messages.yml")

            cwe_ids = []
            if cwe:
                cwe_ids = [f"CWE-{cwe}"]

            # Determine category from the rule
            category = self._derive_category(scs_id, title, analyzer_info)

            # SecurityCodeScan uses Warning severity by default
            severity = "medium"

            self.upsert(
                rule_id=scs_id,
                title=title[:500],
                description=description[:2000],
                severity=severity,
                category=category,
                language="csharp",
                cwe_ids=cwe_ids,
                tags=["security-code-scan", "csharp", "dotnet", "sast",
                      "roslyn", category],
                source_file=source_file,
                rule_content=str(msg_info)[:50000],
                rule_format="text",
                metadata={
                    "scs_id": scs_id,
                    "cwe": cwe,
                    "cwe_url": msg_info.get("cwe_url", ""),
                    "analyzer_file": analyzer_info.get("source_file", ""),
                    "analyzer_class": analyzer_info.get("class_name", ""),
                },
            )
            count += 1

        logger.info(f"[security_code_scan] Processed {count} rules")

    def _parse_messages_yml(self):
        """Parse SecurityCodeScan/Config/Messages.yml for rule metadata.

        Format:
          SCSxxxx:
            title: "..."
            description: "..."
            cwe: 123
            cwe_url: https://cwe.mitre.org/...
        """
        messages = {}
        fpath = os.path.join(self.clone_dir, "SecurityCodeScan", "Config",
                             "Messages.yml")
        if not os.path.isfile(fpath):
            logger.warning("[security_code_scan] Messages.yml not found")
            return messages

        try:
            with open(fpath, "r", encoding="utf-8-sig") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"[security_code_scan] Failed to parse Messages.yml: {e}")
            return messages

        if not data:
            return messages

        for scs_id, info in data.items():
            if not isinstance(info, dict):
                continue
            messages[scs_id] = {
                "title": info.get("title", ""),
                "description": info.get("description", ""),
                "cwe": info.get("cwe"),
                "cwe_url": info.get("cwe_url", ""),
            }

        return messages

    def _parse_analyzer_files(self):
        """Parse SecurityCodeScan/Analyzers/*.cs for DiagnosticId definitions.

        Pattern: public const string DiagnosticIdXxx = "SCSxxxx";
        """
        analyzers = {}
        analyzers_dir = os.path.join(self.clone_dir, "SecurityCodeScan",
                                     "Analyzers")
        if not os.path.isdir(analyzers_dir):
            return analyzers

        for fname in os.listdir(analyzers_dir):
            if not fname.endswith(".cs"):
                continue
            fpath = os.path.join(analyzers_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)

            try:
                with open(fpath, "r", encoding="utf-8-sig") as f:
                    content = f.read()
            except Exception:
                continue

            # Find DiagnosticId definitions
            for m in re.finditer(
                r'DiagnosticId\w*\s*=\s*"(SCS\d+)"', content
            ):
                scs_id = m.group(1)
                if scs_id not in analyzers:
                    # Extract class name
                    class_match = re.search(r'class\s+(\w+)', content)
                    class_name = class_match.group(1) if class_match else fname

                    analyzers[scs_id] = {
                        "source_file": rel_path,
                        "class_name": class_name,
                    }

        # Also check Taint subdirectory
        taint_dir = os.path.join(analyzers_dir, "Taint")
        if os.path.isdir(taint_dir):
            for fname in os.listdir(taint_dir):
                if not fname.endswith(".cs"):
                    continue
                fpath = os.path.join(taint_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                try:
                    with open(fpath, "r", encoding="utf-8-sig") as f:
                        content = f.read()
                except Exception:
                    continue

                for m in re.finditer(
                    r'DiagnosticId\w*\s*=\s*"(SCS\d+)"', content
                ):
                    scs_id = m.group(1)
                    if scs_id not in analyzers:
                        class_match = re.search(r'class\s+(\w+)', content)
                        class_name = class_match.group(1) if class_match else fname

                        analyzers[scs_id] = {
                            "source_file": rel_path,
                            "class_name": class_name,
                        }

        return analyzers

    @staticmethod
    def _derive_category(scs_id, title, analyzer_info):
        """Derive a security category from the rule title and ID."""
        title_lower = title.lower()
        if "sql injection" in title_lower:
            return "injection"
        elif "xss" in title_lower or "cross-site scripting" in title_lower:
            return "xss"
        elif "command injection" in title_lower:
            return "command-injection"
        elif "xxe" in title_lower or "xml" in title_lower:
            return "xxe"
        elif "cookie" in title_lower:
            return "cookie"
        elif "crypto" in title_lower or "cipher" in title_lower or "hash" in title_lower:
            return "crypto"
        elif "certificate" in title_lower:
            return "certificate"
        elif "path traversal" in title_lower:
            return "path-traversal"
        elif "redirect" in title_lower:
            return "open-redirect"
        elif "ldap" in title_lower:
            return "ldap-injection"
        elif "deserialization" in title_lower:
            return "deserialization"
        elif "csrf" in title_lower or "request forgery" in title_lower:
            return "csrf"
        elif "password" in title_lower:
            return "password"
        elif "request validation" in title_lower:
            return "request-validation"
        elif "authorization" in title_lower:
            return "authorization"
        elif "view state" in title_lower:
            return "view-state"
        elif "random" in title_lower:
            return "weak-random"
        elif "xslt" in title_lower:
            return "xslt"
        elif "compilation" in title_lower:
            return "compilation"
        elif "debug" in title_lower:
            return "debug"
        elif "output cache" in title_lower:
            return "cache"
        elif "event validation" in title_lower:
            return "event-validation"
        return "security"