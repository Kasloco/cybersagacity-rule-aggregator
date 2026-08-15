"""Collector for npm audit advisories.

Pulls from the GitHub Advisory Database — a public, curated repository of
security advisories. Each advisory is a YAML file with GHSA ID, CVE mapping,
severity, affected packages, and description.

Source: https://github.com/github/advisory-database
The repo contains advisories in: advisories/github-reviewed/ and advisories/unreviewed/
Each advisory is a .yml file with this structure:
  id: GHSA-xxxx-xxxx-xxxx
  summary: "Short description"
  severity: critical|high|medium|low|moderate
  cvss: {score, vectorString}
  cwe_ids: [CWE-xxx]
  packages: [{ecosystem: npm, name: ...}]
  references: [urls]
"""

import os
import re
import logging
import yaml
from datetime import datetime

from .base import BaseCollector

logger = logging.getLogger(__name__)

ADVISORY_REPO = "https://github.com/github/advisory-database.git"


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

        count = 0
        for root, dirs, files in os.walk(advisories_dir):
            for fname in files:
                if not fname.endswith(".yml") and not fname.endswith(".yaml"):
                    continue

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        advisory = yaml.safe_load(f)
                except Exception as e:
                    logger.debug(f"[npm_audit] Failed to parse {fname}: {e}")
                    continue

                if not advisory or not isinstance(advisory, dict):
                    continue

                adv_id = advisory.get("id", "")
                if not adv_id:
                    continue

                # Filter to npm ecosystem advisories
                packages = advisory.get("packages", [])
                is_npm = False
                pkg_names = []
                for pkg in packages:
                    if isinstance(pkg, dict):
                        ecosystem = pkg.get("ecosystem", "").lower()
                        pkg_name = pkg.get("name", "")
                        if ecosystem in ("npm", "javascript", "nodejs"):
                            is_npm = True
                            pkg_names.append(pkg_name)

                if not is_npm:
                    continue

                summary = advisory.get("summary", adv_id)
                severity = (advisory.get("severity") or "medium").lower()
                if severity == "moderate":
                    severity = "medium"

                # Extract CVE IDs from aliases or database_specific
                cwe_ids = advisory.get("cwe_ids", [])
                aliases = advisory.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]

                # Build description
                desc_parts = []
                if pkg_names:
                    desc_parts.append(f"Affected packages: {', '.join(pkg_names[:5])}")
                cvss = advisory.get("cvss", {})
                if isinstance(cvss, dict) and cvss.get("score"):
                    desc_parts.append(f"CVSS: {cvss['score']}")
                if cve_ids:
                    desc_parts.append(f"CVEs: {', '.join(cve_ids)}")
                description = ". ".join(desc_parts)

                # Source file path within the repo
                rel_path = os.path.relpath(fpath, self.clone_dir)

                # URL to view the advisory
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
                    rule_format="yaml",
                    metadata={
                        "cve_ids": cve_ids,
                        "packages": pkg_names,
                        "cvss": cvss if isinstance(cvss, dict) else {},
                    },
                )
                count += 1

        logger.info(f"[npm_audit] Collected {count} npm advisories.")
        return self.stats