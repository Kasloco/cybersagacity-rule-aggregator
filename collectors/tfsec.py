"""Collector for Tfsec (Aqua Security) Terraform/IaC security rules.

Tfsec itself is a thin CLI wrapper around defsec, which delegates all rule
definitions to the trivy-policies repository (https://github.com/aquasecurity/trivy-policies).
The actual rules live in ``checks/`` as Rego files with METADATA comment blocks
containing:

  - title, description
  - custom.id (e.g. ``DS-0006``)
  - custom.long_id (e.g. ``docker-no-ssh-port``)
  - custom.aliases (e.g. ``AVD-DS-0004``, ``DS004``)
  - custom.severity (CRITICAL / HIGH / MEDIUM / LOW)
  - custom.recommended_action
  - related_resources (links)

We clone trivy-policies and parse the metadata from every non-test ``.rego``
file under ``checks/``.  The tfsec repo itself only contains a legacy ID map
(``internal/pkg/legacy/map.go``) which we also parse to enrich the metadata
with legacy short-form IDs (``AWS005``, ``GCP010``, etc.).
"""

import os
import re
import logging

import git

from .base import BaseCollector, CLONE_BASE

logger = logging.getLogger(__name__)

# Trivy-policies clone URL — tfsec rules are defined here
TRIVY_POLICIES_URL = "https://github.com/aquasecurity/trivy-policies.git"

# Map trivy-policies severity to our five-tier system
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}

# Regex patterns for parsing METADATA comment blocks in Rego files
RE_TITLE = re.compile(r'#\s+title:\s*"(.*?)"')
RE_DESCRIPTION = re.compile(r'#\s+description:\s*"(.*?)"')
RE_CUSTOM_ID = re.compile(r'#\s+id:\s*(\S+)')
RE_LONG_ID = re.compile(r'#\s+long_id:\s*(\S+)')
RE_SEVERITY = re.compile(r'#\s+severity:\s*(\S+)')
RE_RECOMMENDED_ACTION = re.compile(r'#\s+recommended_action:\s*"(.*?)"', re.DOTALL)
RE_AVD_ALIAS = re.compile(r'#\s+-\s*(AVD-[A-Z]+-\d+)')
RE_RELATED_RESOURCE = re.compile(r'#\s+-\s*(https?://\S+)')

# Regex for parsing the legacy ID map in tfsec's internal/pkg/legacy/map.go
RE_LEGACY_ENTRY = re.compile(r'"(AWS\d+|AZU\d+|GCP\d+|GEN\d+)"\s*:\s*"(.*?)"')


class TfsecCollector(BaseCollector):
    name = "tfsec"
    display_name = "Tfsec (Aqua Security)"
    source_type = "github"
    source_url = "https://github.com/aquasecurity/tfsec.git"
    description = (
        "Terraform and IaC security scanner (now part of Aqua Security). "
        "Checks for misconfigurations in AWS, Azure, GCP, Kubernetes, Docker, "
        "and other cloud providers. Rules defined as Rego policies in trivy-policies."
    )
    logo_url = "https://avatars.githubusercontent.com/u/25220000"

    def __init__(self):
        super().__init__()
        # Secondary clone for trivy-policies where the actual rules live
        self._policies_dir = os.path.join(CLONE_BASE, f"{self.name}-policies")

    def _clone_policies(self):
        """Clone or pull the trivy-policies repo containing the Rego rules."""
        os.makedirs(CLONE_BASE, exist_ok=True)
        if os.path.exists(os.path.join(self._policies_dir, ".git")):
            logger.info("[tfsec] Pulling trivy-policies...")
            repo = git.Repo(self._policies_dir)
            repo.remotes.origin.pull()
        else:
            logger.info("[tfsec] Cloning trivy-policies...")
            git.Repo.clone_from(
                TRIVY_POLICIES_URL, self._policies_dir,
                depth=1, single_branch=True,
            )

    def collect_rules(self):
        # Clone the secondary trivy-policies repo
        self._clone_policies()

        # Build legacy ID map from tfsec's legacy/map.go
        legacy_map = self._parse_legacy_map()
        # Reverse: long_id -> [legacy_ids]
        long_to_legacy = {}
        for legacy_id, long_id in legacy_map.items():
            long_to_legacy.setdefault(long_id, []).append(legacy_id)

        count = 0
        checks_dir = os.path.join(self._policies_dir, "checks")
        if not os.path.isdir(checks_dir):
            logger.warning(f"[tfsec] checks/ directory not found in {self._policies_dir}")
            return

        for root, dirs, files in os.walk(checks_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".rego"):
                    continue
                if fname.endswith("_test.rego"):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self._policies_dir)
                rule = self._parse_rego_metadata(fpath, rel_path)
                if rule is None:
                    continue

                # Enrich with legacy IDs
                long_id = rule.get("long_id", "")
                if long_id in long_to_legacy:
                    rule["aliases"].extend(long_to_legacy[long_id])

                # Derive category from path: checks/cloud/aws/... -> aws
                parts = rel_path.split(os.sep)
                category = "general"
                if len(parts) >= 3:
                    if parts[1] == "cloud" and len(parts) >= 3:
                        category = parts[2]
                    else:
                        category = parts[1]

                # Use AVD ID as the canonical rule_id (most stable identifier)
                rule_id = rule.get("avd_id") or rule.get("custom_id") or rule.get("long_id") or fname.replace(".rego", "")

                self.upsert(
                    rule_id=rule_id,
                    title=rule.get("title", rule_id)[:500],
                    description=rule.get("description", ""),
                    severity=rule.get("severity", "medium"),
                    category=category,
                    language="terraform",
                    cwe_ids=[],
                    tags=rule.get("aliases", []) + ["tfsec", "terraform", "iac", category],
                    source_file=rel_path,
                    rule_content=rule.get("content", "")[:50000],
                    rule_format="go",
                    metadata={
                        "custom_id": rule.get("custom_id", ""),
                        "long_id": rule.get("long_id", ""),
                        "avd_id": rule.get("avd_id", ""),
                        "aliases": rule.get("aliases", []),
                        "severity": rule.get("raw_severity", ""),
                        "recommended_action": rule.get("recommended_action", ""),
                        "links": rule.get("links", []),
                        "source": "trivy-policies",
                    },
                )
                count += 1

        logger.info(f"[tfsec] Processed {count} rules")

    def _parse_rego_metadata(self, fpath, rel_path):
        """Parse METADATA comment block from a Rego file."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return None

        # Extract METADATA block (from '# METADATA' to 'package' or first non-comment line)
        meta_match = re.search(
            r'# METADATA\n(.*?)(?=\npackage |\nimport )',
            content, re.DOTALL,
        )
        if not meta_match:
            return None

        meta = meta_match.group(1)

        title_m = RE_TITLE.search(meta)
        desc_m = RE_DESCRIPTION.search(meta)
        custom_id_m = RE_CUSTOM_ID.search(meta)
        long_id_m = RE_LONG_ID.search(meta)
        sev_m = RE_SEVERITY.search(meta)
        action_m = RE_RECOMMENDED_ACTION.search(meta)
        avd_m = RE_AVD_ALIAS.search(meta)
        related_m = RE_RELATED_RESOURCE.findall(meta)

        raw_severity = sev_m.group(1).upper() if sev_m else "MEDIUM"
        severity = SEVERITY_MAP.get(raw_severity, "medium")

        avd_id = avd_m.group(1) if avd_m else ""

        # Collect all aliases from the metadata
        aliases = []
        if avd_id:
            aliases.append(avd_id)
        custom_id = custom_id_m.group(1) if custom_id_m else ""
        if custom_id and custom_id not in aliases:
            aliases.append(custom_id)

        title = title_m.group(1) if title_m else ""
        description = desc_m.group(1) if desc_m else ""
        long_id = long_id_m.group(1) if long_id_m else ""

        # If no title found, derive from long_id
        if not title and long_id:
            title = long_id.replace("-", " ").title()

        recommended_action = ""
        if action_m:
            recommended_action = action_m.group(1).strip()

        return {
            "title": title,
            "description": description,
            "custom_id": custom_id,
            "long_id": long_id,
            "avd_id": avd_id,
            "aliases": aliases,
            "severity": severity,
            "raw_severity": raw_severity,
            "recommended_action": recommended_action,
            "links": related_m,
            "content": content,
        }

    def _parse_legacy_map(self):
        """Parse tfsec's legacy ID map from internal/pkg/legacy/map.go."""
        legacy_map = {}
        map_path = os.path.join(self.clone_dir, "internal/pkg/legacy/map.go")
        if not os.path.exists(map_path):
            return legacy_map

        try:
            with open(map_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for m in RE_LEGACY_ENTRY.finditer(content):
                legacy_map[m.group(1)] = m.group(2)
        except Exception as e:
            logger.debug(f"[tfsec] Failed to parse legacy map: {e}")

        return legacy_map