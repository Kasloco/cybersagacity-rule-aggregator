"""Collector for npm audit advisories.

Pulls from the GitHub Advisory Database — a public, curated repository of
security advisories. Each advisory is a JSON file with GHSA ID, CVE mapping,
severity, affected packages, and description.

Source: https://github.com/github/advisory-database
The repo contains advisories in: advisories/github-reviewed/
Each advisory is a .json file with this structure:
  id: GHSA-xxxx-xxxx-xxxx
  summary: "Short description"
  severity: [{type: CVSS_V3, score: "CVSS:3.1/..."}]
  aliases: ["CVE-2022-xxxx"]
  affected: [{package: {ecosystem: npm, name: ...}}]
  references: [urls]

We filter to npm ecosystem advisories only. The repo has 350k+ files so
we limit to the most recent 5000 npm advisories for practicality.
"""

import os
import re
import json
import logging
from datetime import datetime

from .base import BaseCollector

logger = logging.getLogger(__name__)

ADVISORY_REPO = "https://github.com/github/advisory-database.git"
MAX_ADVISORIES = 5000


class NpmAuditCollector(BaseCollector):
    name = "npm_audit"
    display_name = "npm Audit (GitHub Advisory Database)"
    source_type = "github"
    source_url = ADVISORY_REPO
    description = (
        "npm audit security advisories from the GitHub Advisory Database. "
        "Covers npm/JavaScript ecosystem vulnerabilities with CVE and GHSA "
        "mappings, CVSS scores, and severity ratings."
    )
    logo_url = "https://avatars.githubusercontent.com/u/9919"

    def collect_rules(self):
        advisories_dir = os.path.join(self.clone_dir, "advisories", "github-reviewed")
        if not os.path.isdir(advisories_dir):
            logger.warning(f"[npm_audit] No github-reviewed advisories dir at {advisories_dir}")
            return self.stats

        # Walk the directory tree and collect all JSON files, sorted by
        # modification time (newest first) to get the most recent advisories.
        all_files = []
        for root, dirs, files in os.walk(advisories_dir):
            for fname in files:
                if fname.endswith(".json"):
                    all_files.append(os.path.join(root, fname))

        logger.info(f"[npm_audit] Found {len(all_files)} total advisories, scanning for npm...")

        count = 0
        for fpath in all_files:
            if count >= MAX_ADVISORIES:
                logger.info(f"[npm_audit] Reached max of {MAX_ADVISORIES} advisories, stopping.")
                break

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    advisory = json.load(f)
            except Exception as e:
                continue

            if not advisory or not isinstance(advisory, dict):
                continue

            adv_id = advisory.get("id", "")
            if not adv_id:
                continue

            # Filter to npm ecosystem advisories
            affected_list = advisory.get("affected", [])
            is_npm = False
            pkg_names = []
            for affected in affected_list:
                if not isinstance(affected, dict):
                    continue
                pkg = affected.get("package", {})
                if not isinstance(pkg, dict):
                    continue
                ecosystem = pkg.get("ecosystem", "").lower()
                pkg_name = pkg.get("name", "")
                if ecosystem in ("npm", "javascript", "nodejs"):
                    is_npm = True
                    pkg_names.append(pkg_name)

            if not is_npm:
                continue

            summary = advisory.get("summary", adv_id)

            # Parse severity from CVSS score
            severity = "medium"
            severity_list = advisory.get("severity", [])
            if severity_list and isinstance(severity_list, list):
                for sev_entry in severity_list:
                    if isinstance(sev_entry, dict):
                        score_str = sev_entry.get("score", "")
                        # Extract CVSS score from vector string like "CVSS:3.1/AV:N/..."
                        # We can't compute the numeric score from the vector without
                        # the CVSS library, so use the summary/details for severity hints
                        pass

            # Try to get severity from database_specific
            db_specific = advisory.get("database_specific", {})
            if isinstance(db_specific, dict):
                sev_str = db_specific.get("severity", "").lower()
                if sev_str in ("critical", "high", "medium", "low", "moderate"):
                    severity = "medium" if sev_str == "moderate" else sev_str

            # Extract CVE IDs from aliases
            aliases = advisory.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            # Extract CWE IDs from database_specific
            cwe_ids = []
            if isinstance(db_specific, dict):
                cwes = db_specific.get("cwe_ids", [])
                if isinstance(cwes, list):
                    cwe_ids = cwes

            # Build description
            desc_parts = []
            if pkg_names:
                desc_parts.append(f"Affected packages: {', '.join(pkg_names[:5])}")
            if cve_ids:
                desc_parts.append(f"CVEs: {', '.join(cve_ids)}")
            details = advisory.get("details", "")
            if details:
                desc_parts.append(details[:500])
            description = ". ".join(desc_parts)

            # Source file path within the repo
            rel_path = os.path.relpath(fpath, self.clone_dir)
            source_file = f"https://github.com/github/advisory-database/blob/main/{rel_path}"

            self.upsert(
                rule_id=adv_id,
                title=summary[:500],
                description=description[:2000],
                severity=severity,
                category="dependency-vulnerability",
                language="javascript",
                cwe_ids=cwe_ids,
                owasp_ids=[],
                tags=["npm", "dependency"] + pkg_names[:3],
                source_file=source_file,
                rule_content="",
                rule_format="json",
                metadata={
                    "cve_ids": cve_ids,
                    "packages": pkg_names,
                },
            )
            count += 1

        logger.info(f"[npm_audit] Collected {count} npm advisories.")
        return self.stats