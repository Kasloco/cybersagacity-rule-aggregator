"""Collector for PMD static analysis rules (XML rulesets)."""

import os
import xml.etree.ElementTree as ET
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class PMDCollector(BaseCollector):
    name = "pmd"
    display_name = "PMD"
    source_type = "github"
    source_url = "https://github.com/pmd/pmd.git"
    description = "Multi-language static analysis tool with extensible rule sets. Covers code style, best practices, error-prone patterns, performance, and security for Java, JS, Apex, and more."
    logo_url = "https://avatars.githubusercontent.com/u/3024025"

    def collect_rules(self):
        count = 0
        # PMD rules are in XML rulesets under pmd-*/src/main/resources/
        for root, dirs, files in os.walk(self.clone_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "test"]
            for fname in files:
                if not fname.endswith(".xml"):
                    continue
                # Only process files in category directories
                if "/category/" not in root.replace("\\", "/"):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_ruleset(fpath, rel_path)

        logger.info(f"[pmd] Processed {count} rules")

    def _parse_ruleset(self, fpath, rel_path):
        count = 0
        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception:
            return 0

        ns = {"pmd": "http://pmd.sourceforge.net/ruleset/2.0.0"}

        # Try with namespace first, then without
        rules = root.findall(".//pmd:rule", ns)
        if not rules:
            rules = root.findall(".//rule")

        for rule in rules:
            name = rule.get("name", "")
            if not name or rule.get("ref"):  # Skip rule references
                continue

            rule_class = rule.get("class", "")
            language_attr = rule.get("language", "")

            # Derive language from path
            language = language_attr
            if not language:
                if "pmd-java" in rel_path:
                    language = "java"
                elif "pmd-javascript" in rel_path or "pmd-ecmascript" in rel_path:
                    language = "javascript"
                elif "pmd-python" in rel_path:
                    language = "python"
                elif "pmd-apex" in rel_path:
                    language = "apex"

            # Extract description
            desc_el = rule.find("pmd:description", ns) or rule.find("description")
            description = ""
            if desc_el is not None and desc_el.text:
                description = desc_el.text.strip()[:2000]

            # Extract priority -> severity
            priority_el = rule.find("pmd:priority", ns) or rule.find("priority")
            priority = 3
            if priority_el is not None and priority_el.text:
                try:
                    priority = int(priority_el.text.strip())
                except ValueError:
                    pass

            severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
            severity = severity_map.get(priority, "medium")

            # Category from filename
            category = os.path.splitext(os.path.basename(rel_path))[0]

            rule_id = f"pmd-{language}-{name}" if language else f"pmd-{name}"

            tags = ["pmd", "sast"]
            if language:
                tags.append(language)
            if "security" in category.lower():
                tags.append("security")

            self.upsert(
                rule_id=rule_id,
                title=f"{name}",
                description=description,
                severity=severity,
                category=category,
                language=language,
                tags=tags,
                source_file=rel_path,
                rule_content=ET.tostring(rule, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={"class": rule_class, "priority": priority},
            )
            count += 1

        return count
