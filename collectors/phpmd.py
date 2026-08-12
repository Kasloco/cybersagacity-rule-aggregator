"""Collector for PHPMD (PHP Mess Detector) rules."""

import os
import xml.etree.ElementTree as ET
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class PHPMDCollector(BaseCollector):
    name = "phpmd"
    display_name = "PHPMD"
    source_type = "github"
    source_url = "https://github.com/phpmd/phpmd.git"
    description = (
        "PHP Mess Detector. Detects code smells, unused code, "
        "naming conventions, controversial patterns, design issues, "
        "and cleanup problems in PHP code."
    )
    logo_url = "https://avatars.githubusercontent.com/u/2548781"

    def collect_rules(self):
        count = 0

        # PHPMD rulesets are XML files under src/main/resources/rulesets/
        rulesets_dir = os.path.join(
            self.clone_dir, "src", "main", "resources", "rulesets"
        )

        if not os.path.isdir(rulesets_dir):
            # Fallback: walk for any ruleset XML files
            for root, dirs, files in os.walk(self.clone_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if fname.endswith(".xml") and "ruleset" in fname.lower():
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, self.clone_dir)
                        count += self._parse_ruleset(fpath, rel_path)
        else:
            for fname in os.listdir(rulesets_dir):
                if not fname.endswith(".xml"):
                    continue
                fpath = os.path.join(rulesets_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_ruleset(fpath, rel_path)

        logger.info(f"[phpmd] Processed {count} rules")

    def _parse_ruleset(self, fpath, rel_path):
        count = 0
        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception as e:
            logger.debug(f"[phpmd] Failed to parse {fpath}: {e}")
            return 0

        # PHPMD rulesets use a namespace — try both with and without
        ns = {"phpmd": "https://phpmd.org/xml/ruleset/1.0.0"}
        rules = root.findall(".//phpmd:rule", ns)
        if not rules:
            rules = root.findall(".//rule")

        # Category from filename (e.g., cleancode.xml -> cleancode)
        category = os.path.splitext(os.path.basename(rel_path))[0]

        for rule in rules:
            name = rule.get("name", "")
            if not name or rule.get("ref"):
                continue

            # Description
            desc_el = rule.find("phpmd:description", ns) or rule.find("description")
            description = ""
            if desc_el is not None and desc_el.text:
                description = desc_el.text.strip()[:2000]

            # PHPMD uses priority 1-5 (1=highest)
            priority_el = rule.find("phpmd:priority", ns) or rule.find("priority")
            priority = 3
            if priority_el is not None and priority_el.text:
                try:
                    priority = int(priority_el.text.strip())
                except ValueError:
                    pass

            severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
            severity = severity_map.get(priority, "medium")

            # Properties (may contain violation details)
            properties = {}
            props_el = rule.find("phpmd:properties", ns) or rule.find("properties")
            if props_el is not None:
                for prop in props_el.findall("phpmd:property", ns) or props_el.findall("property"):
                    pname = prop.get("name", "")
                    pval = prop.get("value", "")
                    if pname:
                        properties[pname] = pval

            # Examples (code snippets)
            examples = []
            example_els = rule.findall(".//phpmd:example", ns) or rule.findall(".//example")
            for ex in example_els:
                if ex.text:
                    examples.append(ex.text.strip()[:500])

            rule_id = f"phpmd-{category}-{name}"

            tags = ["phpmd", "php", "sast", category]
            if "clean" in category:
                tags.append("clean-code")
            elif "unused" in category:
                tags.append("unused-code")
            elif "design" in category:
                tags.append("design")

            self.upsert(
                rule_id=rule_id,
                title=name,
                description=description,
                severity=severity,
                category=category,
                language="php",
                cwe_ids=[],
                tags=tags,
                source_file=rel_path,
                rule_content=ET.tostring(rule, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={
                    "priority": priority,
                    "properties": properties,
                    "examples": examples,
                },
            )
            count += 1

        return count