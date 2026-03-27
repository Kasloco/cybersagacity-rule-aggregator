"""Collector for ProjectDiscovery Nuclei templates (YAML)."""

import os
import yaml
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class NucleiCollector(BaseCollector):
    name = "nuclei"
    display_name = "Nuclei (ProjectDiscovery)"
    source_type = "github"
    source_url = "https://github.com/projectdiscovery/nuclei-templates.git"
    description = "7000+ community-contributed vulnerability detection templates for web applications, network services, cloud misconfigs, CVEs, and exposed panels."
    logo_url = "https://avatars.githubusercontent.com/u/50994705"

    def collect_rules(self):
        count = 0
        for root, dirs, files in os.walk(self.clone_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith((".yaml", ".yml")):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    doc = yaml.safe_load(content)
                except Exception:
                    continue

                if not isinstance(doc, dict) or "id" not in doc:
                    continue

                info = doc.get("info", {})
                if not isinstance(info, dict):
                    continue

                rule_id = doc["id"]
                title = info.get("name", rule_id)
                severity = SEVERITY_MAP.get(
                    str(info.get("severity", "info")).lower(), "info"
                )

                tags_raw = info.get("tags", "")
                tags = [t.strip() for t in tags_raw.split(",")] if isinstance(tags_raw, str) else tags_raw or []

                classification = info.get("classification", {}) or {}
                cwe_ids = classification.get("cwe-id", []) or []
                if isinstance(cwe_ids, (str, int)):
                    cwe_ids = [str(cwe_ids)]

                # Derive category from directory
                parts = rel_path.split(os.sep)
                category = parts[0] if parts else ""

                metadata = {
                    "author": info.get("author", ""),
                    "reference": info.get("reference", []),
                    "classification": classification,
                }

                self.upsert(
                    rule_id=rule_id,
                    title=title[:500],
                    description=info.get("description", ""),
                    severity=severity,
                    category=category,
                    language="",  # Nuclei templates are language-agnostic
                    cwe_ids=[str(c) for c in cwe_ids],
                    tags=tags,
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="yaml",
                    metadata=metadata,
                )
                count += 1

        logger.info(f"[nuclei] Processed {count} templates")
