"""Collector for PHP_CodeSniffer (squizlabs) rules."""

import os
import xml.etree.ElementTree as ET
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class PHPCodeSnifferCollector(BaseCollector):
    name = "php_codesniffer"
    display_name = "PHP_CodeSniffer"
    source_type = "github"
    source_url = "https://github.com/squizlabs/PHP_CodeSniffer.git"
    description = (
        "PHP_CodeSniffer detects violations of coding standards (PSR1, PSR2, "
        "PSR12, PEAR, Squiz, Zend) and includes PHPCBF auto-fixer. "
        "Rules are defined as Sniffs organized by standards."
    )
    logo_url = "https://avatars.githubusercontent.com/u/6106090"

    def collect_rules(self):
        count = 0

        # PHP_CodeSniffer stores sniffs in src/Standards/*/Sniffs/*/*.php
        # Rules are registered via docblock @codingStandardsIgnoreStart annotations
        # The machine-readable rule list is in src/Standards/*/ruleset.xml files
        standards_dir = os.path.join(self.clone_dir, "src", "Standards")

        if not os.path.isdir(standards_dir):
            logger.warning("[php_codesniffer] Standards directory not found")
            return

        # Walk each standard's Sniffs directory
        for standard_name in os.listdir(standards_dir):
            standard_path = os.path.join(standards_dir, standard_name)
            if not os.path.isdir(standard_path):
                continue

            sniffs_dir = os.path.join(standard_path, "Sniffs")
            if not os.path.isdir(sniffs_dir):
                continue

            for root, dirs, files in os.walk(sniffs_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if not fname.endswith("Sniff.php"):
                        continue

                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, self.clone_dir)
                    count += self._parse_sniff_file(
                        fpath, rel_path, standard_name
                    )

        # Also parse ruleset.xml files for rule metadata
        for standard_name in os.listdir(standards_dir):
            standard_path = os.path.join(standards_dir, standard_name)
            ruleset_file = os.path.join(standard_path, "ruleset.xml")
            if os.path.isfile(ruleset_file):
                rel_path = os.path.relpath(ruleset_file, self.clone_dir)
                count += self._parse_ruleset_xml(
                    ruleset_file, rel_path, standard_name
                )

        logger.info(f"[php_codesniffer] Processed {count} rules")

    def _parse_sniff_file(self, fpath, rel_path, standard_name):
        """Parse a PHP sniff file for rule metadata."""
        count = 0

        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract sniff class name and error messages from PHP code
        # Sniff files define error messages via addError()/addWarning() calls
        import re

        # Get the sniff category from the directory name
        category = os.path.basename(os.path.dirname(fpath))
        sniff_name = fname = os.path.basename(fpath).replace("Sniff.php", "")

        # Build rule ID: Standard.Category.SniffName
        rule_id = f"{standard_name}.{category}.{sniff_name}"

        # Extract error/warning messages from the PHP code
        # Look for $phpcsFile->addError('...', ...) and addWarning('...', ...)
        error_msgs = re.findall(
            r"addError\s*\(\s*['\"]([^'\"]+)['\"]", content
        )
        warning_msgs = re.findall(
            r"addWarning\s*\(\s*['\"]([^'\"]+)['\"]", content
        )

        # Determine severity: if it has errors, it's medium; warnings only = low
        if error_msgs:
            severity = "medium"
            title = error_msgs[0][:200] if error_msgs else sniff_name
        elif warning_msgs:
            severity = "low"
            title = warning_msgs[0][:200] if warning_msgs else sniff_name
        else:
            severity = "info"
            title = sniff_name

        # Extract docblock description
        docblock_match = re.search(r"/\*\*\s*\n(.*?)\*/", content, re.DOTALL)
        description = ""
        if docblock_match:
            docblock = docblock_match.group(1)
            # Clean up * prefixes
            lines = [
                line.strip().lstrip("*").strip()
                for line in docblock.split("\n")
                if line.strip() and not line.strip().startswith("@")
            ]
            description = " ".join(lines)[:2000]

        # All messages for context
        all_messages = error_msgs + warning_msgs

        self.upsert(
            rule_id=rule_id,
            title=title,
            description=description or f"{standard_name} {category} {sniff_name} sniff",
            severity=severity,
            category=category.lower(),
            language="php",
            cwe_ids=[],
            tags=["phpcs", "php", "sast", standard_name.lower(), category.lower()],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="php",
            metadata={
                "standard": standard_name,
                "category": category,
                "sniff": sniff_name,
                "error_messages": error_msgs[:10],
                "warning_messages": warning_msgs[:10],
            },
        )
        count += 1
        return count

    def _parse_ruleset_xml(self, fpath, rel_path, standard_name):
        """Parse ruleset.xml for rule references and metadata."""
        count = 0
        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception:
            return 0

        # ruleset.xml may contain <rule> elements with descriptions
        for rule in root.findall(".//rule"):
            ref = rule.get("ref", "")
            if not ref:
                continue

            # Skip if this is just a reference to an already-collected sniff
            # We only want rules with additional metadata
            desc_el = rule.find("description")
            if desc_el is None or not desc_el.text:
                continue

            rule_id = f"phpcs-ruleset-{standard_name}-{ref.replace('.', '-').replace('/', '-')}"

            description = desc_el.text.strip()[:2000]

            self.upsert(
                rule_id=rule_id,
                title=ref,
                description=description,
                severity="info",
                category="ruleset",
                language="php",
                cwe_ids=[],
                tags=["phpcs", "php", "ruleset", standard_name.lower()],
                source_file=rel_path,
                rule_content=ET.tostring(rule, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={
                    "standard": standard_name,
                    "ref": ref,
                    "type": "ruleset-reference",
                },
            )
            count += 1

        return count