"""Collector for Checkmarx KICS (IaC Security) queries."""

import os
import json
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class CheckmarxKICSCollector(BaseCollector):
    name = "checkmarx_kics"
    display_name = "Checkmarx KICS"
    source_type = "github"
    source_url = "https://github.com/Checkmarx/kics.git"
    description = "Infrastructure as Code security queries from Checkmarx. Covers Terraform, Kubernetes, Docker, Ansible, CloudFormation, and more using Rego policies."
    logo_url = "https://avatars.githubusercontent.com/u/13873881"

    def collect_rules(self):
        count = 0
        queries_dir = os.path.join(self.clone_dir, "assets", "queries")
        if not os.path.isdir(queries_dir):
            logger.warning(f"[checkmarx_kics] queries dir not found at {queries_dir}")
            return

        for root, dirs, files in os.walk(queries_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            # KICS queries have a metadata.json in each query directory
            if "metadata.json" not in files:
                continue

            meta_path = os.path.join(root, "metadata.json")
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                continue

            rule_id = meta.get("id", "")
            if not rule_id:
                continue

            # Find the Rego query file
            rego_content = ""
            rego_file = ""
            for fname in files:
                if fname.endswith(".rego"):
                    rego_path = os.path.join(root, fname)
                    rego_file = os.path.relpath(rego_path, self.clone_dir)
                    try:
                        with open(rego_path, "r", encoding="utf-8", errors="replace") as f:
                            rego_content = f.read()
                    except Exception:
                        pass
                    break

            severity = meta.get("severity", "MEDIUM").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            rel_path = os.path.relpath(root, self.clone_dir)
            parts = rel_path.replace("assets/queries/", "").split(os.sep)
            platform = parts[0] if parts else ""
            category = meta.get("category", platform)

            cwe_raw = meta.get("cwe", "")
            cwe_ids = [cwe_raw] if cwe_raw else []

            self.upsert(
                rule_id=rule_id,
                title=meta.get("queryName", rule_id)[:500],
                description=meta.get("descriptionText", ""),
                severity=severity,
                category=category,
                language=platform,
                cwe_ids=cwe_ids,
                tags=[platform, meta.get("platform", "")],
                source_file=rego_file or os.path.relpath(meta_path, self.clone_dir),
                rule_content=rego_content[:50000],
                rule_format="rego",
                metadata=meta,
            )
            count += 1

        logger.info(f"[checkmarx_kics] Processed {count} queries")
