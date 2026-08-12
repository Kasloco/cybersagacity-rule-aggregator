"""Collector for Deque AXE accessibility rules.

AXE is an accessibility testing engine by Deque Systems. The open-source
axe-core repo on GitHub contains all rule definitions as JSON-like objects
in JavaScript files, with each rule having an ID, tags (wcag/section508/etc),
selector, and metadata.
"""

import os
import re
import json
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class DequeAXECollector(BaseCollector):
    name = "deque_axe"
    display_name = "Deque AXE"
    source_type = "github"
    source_url = "https://github.com/dequelabs/axe-core.git"
    description = (
        "Deque AXE accessibility testing engine. "
        "200+ rules for WCAG 2.0/2.1/2.2, Section 508, and ACT (Accessibility "
        "Conformance Testing) rules. Detects ARIA issues, color contrast, "
        "keyboard navigation, form labeling, and semantic HTML problems."
    )
    logo_url = "https://avatars.githubusercontent.com/u/16566117"

    def collect_rules(self):
        count = 0

        # axe-core stores rules in lib/rules/ as individual .js files
        # Each rule file exports an object with id, selector, tags, metadata
        rules_dir = os.path.join(self.clone_dir, "lib", "rules")

        if os.path.isdir(rules_dir):
            for fname in os.listdir(rules_dir):
                if not fname.endswith(".js") or fname.startswith("_"):
                    continue
                fpath = os.path.join(rules_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_rule_file(fpath, rel_path)

        # Also check for JSON rule files in newer axe-core versions
        json_rules_dir = os.path.join(self.clone_dir, "lib", "rules", "json")
        if os.path.isdir(json_rules_dir):
            for fname in os.listdir(json_rules_dir):
                if not fname.endswith(".json"):
                    continue
                fpath = os.path.join(json_rules_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_json_rule(fpath, rel_path)

        # Check doc/rule-descriptions.md for additional metadata
        desc_file = os.path.join(self.clone_dir, "doc", "rule-descriptions.md")
        descriptions = {}
        if os.path.isfile(desc_file):
            try:
                with open(desc_file, "r", encoding="utf-8") as f:
                    for line in f:
                        # Format: | rule-id | description | ...
                        match = re.match(r"^\|\s*([a-z0-9-]+)\s*\|(.+)", line)
                        if match:
                            descriptions[match.group(1)] = match.group(2).strip()
            except Exception:
                pass

        logger.info(f"[deque_axe] Processed {count} rules")

    def _parse_rule_file(self, fpath, rel_path):
        """Parse a single axe-core rule JS file."""
        count = 0

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract the rule ID from filename
        rule_id = os.path.basename(fpath).replace(".js", "")

        # Extract the exported object properties
        # axe-core rule files look like: exports.id = 'button-name'; exports.selector = ...
        # or: { id: 'button-name', selector: '...', tags: [...] }

        # Try to find id, tags, metadata
        id_match = re.search(
            r"(?:exports\.id|id)\s*[:=]\s*['\"]([^'\"]+)['\"]", content
        )
        actual_id = id_match.group(1) if id_match else rule_id

        # Extract tags (accessibility standards)
        tags = []
        tags_match = re.search(
            r"(?:exports\.tags|tags)\s*[:=]\s*\[([^\]]+)\]", content
        )
        if tags_match:
            tag_str = tags_match.group(1)
            tags = re.findall(r"['\"]([^'\"]+)['\"]", tag_str)

        # Extract selector
        selector_match = re.search(
            r"(?:exports\.selector|selector)\s*[:=]\s*['\"]([^'\"]+)['\"]",
            content,
        )
        selector = selector_match.group(1) if selector_match else ""

        # Extract metadata (impact, help, description)
        impact_match = re.search(
            r"(?:impact)\s*[:=]\s*['\"]([^'\"]+)['\"]", content
        )
        impact = impact_match.group(1) if impact_match else "minor"

        help_match = re.search(
            r"(?:help)\s*[:=]\s*['\"]([^'\"]+)['\"]", content
        )
        help_text = help_match.group(1) if help_match else actual_id

        desc_match = re.search(
            r"(?:description)\s*[:=]\s*['\"]([^'\"]+)['\"]", content
        )
        description = desc_match.group(1) if desc_match else ""

        # Map impact to severity
        severity_map = {
            "critical": "critical",
            "serious": "high",
            "moderate": "medium",
            "minor": "low",
        }
        severity = severity_map.get(impact, "medium")

        # Determine category from tags
        category = "accessibility"
        if any("wcag" in t for t in tags):
            category = "wcag"
        elif any("section508" in t for t in tags):
            category = "section508"
        elif any("act" in t.lower() for t in tags):
            category = "act"

        # Build tag list including standard tags
        all_tags = ["axe", "accessibility", "a11y"] + tags

        self.upsert(
            rule_id=f"axe:{actual_id}",
            title=help_text[:500],
            description=description or help_text,
            severity=severity,
            category=category,
            language="html",
            cwe_ids=[],  # AXE doesn't use CWE
            tags=all_tags,
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="javascript",
            metadata={
                "axe_id": actual_id,
                "impact": impact,
                "selector": selector,
                "tags": tags,
            },
        )
        count += 1
        return count

    def _parse_json_rule(self, fpath, rel_path):
        """Parse a JSON rule definition (newer axe-core format)."""
        count = 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return 0

        if not isinstance(data, dict):
            return 0

        rule_id = data.get("id", os.path.basename(fpath).replace(".json", ""))
        tags = data.get("tags", [])
        impact = data.get("impact", "minor")
        help_text = data.get("help", rule_id)
        description = data.get("description", "")
        selector = data.get("selector", "")

        severity_map = {
            "critical": "critical",
            "serious": "high",
            "moderate": "medium",
            "minor": "low",
        }
        severity = severity_map.get(impact, "medium")

        category = "accessibility"
        if any("wcag" in t for t in tags):
            category = "wcag"

        all_tags = ["axe", "accessibility", "a11y"] + tags

        self.upsert(
            rule_id=f"axe:{rule_id}",
            title=help_text[:500],
            description=description or help_text,
            severity=severity,
            category=category,
            language="html",
            cwe_ids=[],
            tags=all_tags,
            source_file=rel_path,
            rule_content=json.dumps(data, indent=2)[:50000],
            rule_format="json",
            metadata={
                "axe_id": rule_id,
                "impact": impact,
                "selector": selector,
                "tags": tags,
            },
        )
        count += 1
        return count