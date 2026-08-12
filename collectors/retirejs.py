"""Collector for Retire.js JavaScript vulnerability scanner rules.

Retire.js maintains a repository of known-vulnerable JavaScript components in
``repository/`` as JSON files. The primary file is ``jsrepository.json`` (or
``jsrepository-master.json`` with the newer format) containing component
definitions keyed by component name, each with:

  - ``vulnerabilities``: array of vulnerability objects with:
    - ``below`` / ``atOrAbove``: version range constraints
    - ``severity``: low / medium / high / critical
    - ``cwe``: array of CWE strings (e.g. ``["CWE-79"]``)
    - ``identifiers``: object with summary, CVE, bug, githubID
    - ``info``: array of reference URLs
  - ``extractors``: detection patterns (func, filename, filecontent, hashes)
  - ``licenses``: license information (optional)

The collector parses the master repository JSON and creates one rule per
component-vulnerability pair, preserving all vendor-native metadata including
version ranges, CWE mappings, CVE identifiers, and detection extractors.
"""

import os
import re
import json
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Map Retire.js severity to our five-tier system
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
}

# Extract CWE number from "CWE-79" format
RE_CWE_NUM = re.compile(r'CWE-(\d+)')


class RetireJsCollector(BaseCollector):
    name = "retirejs"
    display_name = "Retire.js"
    source_type = "github"
    source_url = "https://github.com/RetireJS/retire.js.git"
    description = (
        "JavaScript vulnerability scanner detecting known-vulnerable JS "
        "components. Repository of 70+ components (jQuery, Angular, YUI, etc.) "
        "with version ranges, CVE mappings, CWE classifications, and detection "
        "patterns for function calls, filenames, file content, and hashes."
    )
    logo_url = "https://avatars.githubusercontent.com/u/89895220"

    def collect_rules(self):
        count = 0
        repo_dir = os.path.join(self.clone_dir, "repository")
        if not os.path.isdir(repo_dir):
            logger.warning(f"[retirejs] repository/ directory not found")
            return

        # Primary repository files, in priority order
        # jsrepository.json is the canonical compiled format
        # jsrepository-master.json is the newer format with ranges
        repo_files = [
            "jsrepository.json",
            "jsrepository-master.json",
        ]

        # Track components we've already processed to avoid duplicates
        # when both files exist
        seen_components = set()

        for repo_filename in repo_files:
            fpath = os.path.join(repo_dir, repo_filename)
            if not os.path.exists(fpath):
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except Exception as e:
                logger.warning(f"[retirejs] Failed to parse {repo_filename}: {e}")
                continue

            count += self._parse_repository(data, fpath, seen_components)

        # Also parse npmrepository.json for npm-specific vulnerabilities
        npm_path = os.path.join(repo_dir, "npmrepository.json")
        if os.path.exists(npm_path):
            try:
                with open(npm_path, "r", encoding="utf-8", errors="replace") as f:
                    npm_data = json.load(f)
                count += self._parse_repository(npm_data, npm_path, seen_components)
            except Exception as e:
                logger.debug(f"[retirejs] Failed to parse npmrepository.json: {e}")

        logger.info(f"[retirejs] Processed {count} vulnerability rules")

    def _parse_repository(self, data, fpath, seen_components):
        """Parse a repository JSON file and upsert rules."""
        rel_path = os.path.relpath(fpath, self.clone_dir)
        count = 0

        if not isinstance(data, dict):
            return 0

        # Handle both formats: direct component dict or {advisories: {...}}
        if "advisories" in data and isinstance(data["advisories"], dict):
            components = data["advisories"]
        else:
            components = data

        for component_name, component_data in components.items():
            if not isinstance(component_data, dict):
                continue

            # Skip components we've already processed from another file
            if component_name in seen_components:
                continue

            vulnerabilities = component_data.get("vulnerabilities", [])
            extractors = component_data.get("extractors", {})
            licenses = component_data.get("licenses", [])
            bowername = component_data.get("bowername", [])
            npmname = component_data.get("npmname", "")

            for vuln_idx, vuln in enumerate(vulnerabilities):
                if not isinstance(vuln, dict):
                    continue

                # Handle both formats:
                # Old format: vuln has direct below/atOrAbove/severity/identifiers
                # New format (master): vuln has ranges[], summary, identifiers
                ranges = vuln.get("ranges", [])
                if ranges:
                    # New format — flatten ranges
                    for range_obj in ranges:
                        rule_count = self._upsert_vulnerability(
                            component_name=component_name,
                            component_data=component_data,
                            vuln=vuln,
                            range_obj=range_obj,
                            vuln_idx=vuln_idx,
                            rel_path=rel_path,
                            extractors=extractors,
                            licenses=licenses,
                            bowername=bowername,
                            npmname=npmname,
                        )
                        count += rule_count
                else:
                    # Old format — vuln itself has the range info
                    count += self._upsert_vulnerability(
                        component_name=component_name,
                        component_data=component_data,
                        vuln=vuln,
                        range_obj=vuln,
                        vuln_idx=vuln_idx,
                        rel_path=rel_path,
                        extractors=extractors,
                        licenses=licenses,
                        bowername=bowername,
                        npmname=npmname,
                    )

            seen_components.add(component_name)

        return count

    def _upsert_vulnerability(self, component_name, component_data, vuln, range_obj,
                              vuln_idx, rel_path, extractors, licenses, bowername, npmname):
        """Upsert a single vulnerability rule."""
        below = range_obj.get("below", "")
        at_or_above = range_obj.get("atOrAbove", "")
        severity_raw = vuln.get("severity", "medium").lower()
        severity = SEVERITY_MAP.get(severity_raw, "medium")

        # Extract identifiers
        identifiers = vuln.get("identifiers", {})
        if not isinstance(identifiers, dict):
            identifiers = {}

        # In new format, summary is top-level on vuln; in old format, it's in identifiers
        summary = vuln.get("summary", "") or identifiers.get("summary", "")
        details = vuln.get("details", "")
        cve_list = identifiers.get("CVE", [])
        if not isinstance(cve_list, list):
            cve_list = [cve_list] if cve_list else []
        github_id = identifiers.get("githubID", "")
        bug_id = identifiers.get("bug", "")
        info_urls = vuln.get("info", [])
        if not isinstance(info_urls, list):
            info_urls = [info_urls] if info_urls else []

        # Extract CWE IDs as integers
        cwe_strings = vuln.get("cwe", [])
        if not isinstance(cwe_strings, list):
            cwe_strings = [cwe_strings] if cwe_strings else []
        cwe_ids = []
        for cwe_str in cwe_strings:
            m = RE_CWE_NUM.search(str(cwe_str))
            if m:
                cwe_ids.append(int(m.group(1)))

        # Build rule ID: component-vulnIdx or component-CVE
        if cve_list:
            rule_id = f"{component_name}-{cve_list[0]}"
        else:
            rule_id = f"{component_name}-vuln-{vuln_idx}"

        # Clean rule_id
        rule_id = re.sub(r'[^a-zA-Z0-9_\-.]', '-', rule_id)[:200]

        # Build title
        if summary:
            title = f"{component_name}: {summary}"
        else:
            version_range = ""
            if at_or_above and below:
                version_range = f" ({at_or_above} - {below})"
            elif below:
                version_range = f" (< {below})"
            elif at_or_above:
                version_range = f" (>= {at_or_above})"
            title = f"{component_name} vulnerability{version_range}"

        # Build description
        desc_parts = []
        if summary:
            desc_parts.append(summary)
        if details:
            desc_parts.append(details)
        version_info = []
        if at_or_above:
            version_info.append(f"atOrAbove: {at_or_above}")
        if below:
            version_info.append(f"below: {below}")
        if version_info:
            desc_parts.append(f"Version range: {', '.join(version_info)}")
        if cve_list:
            desc_parts.append(f"CVE: {', '.join(cve_list)}")
        if cwe_strings:
            desc_parts.append(f"CWE: {', '.join(cwe_strings)}")
        if github_id:
            desc_parts.append(f"GitHub Advisory: {github_id}")
        if info_urls:
            desc_parts.append(f"References: {'; '.join(info_urls[:5])}")
        description = " | ".join(desc_parts)[:2000]

        # Build metadata preserving all vendor-native fields
        metadata = {
            "component": component_name,
            "vulnerability_index": vuln_idx,
            "below": below,
            "atOrAbove": at_or_above,
            "severity": severity_raw,
            "cwe": cwe_strings,
            "cve": cve_list,
            "github_id": github_id,
            "bug": bug_id,
            "summary": summary,
            "details": details[:500] if details else "",
            "info": info_urls,
            "extractors": {
                k: v for k, v in extractors.items()
                if k != "hashes"  # Exclude hashes to keep metadata small
            },
            "licenses": licenses,
            "bowername": bowername,
            "npmname": npmname,
        }

        # Build tags
        tags = ["retirejs", "javascript", "sca", "vulnerability"]
        if cve_list:
            tags.append("cve")
        if cwe_ids:
            tags.append("cwe")
        if npmname:
            tags.append("npm")

        self.upsert(
            rule_id=rule_id,
            title=title[:500],
            description=description,
            severity=severity,
            category="vulnerability",
            language="javascript",
            cwe_ids=cwe_ids,
            tags=tags,
            source_file=rel_path,
            rule_content=json.dumps(vuln, indent=2)[:50000],
            rule_format="json",
            metadata=metadata,
        )
        return 1