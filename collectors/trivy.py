"""Collector for Trivy misconfiguration checks (Rego policies)."""

import os
import json
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class TrivyCollector(BaseCollector):
    name = "trivy"
    display_name = "Trivy (Aqua Security)"
    source_type = "github"
    source_url = "https://github.com/aquasecurity/trivy-checks.git"
    description = "IaC misconfiguration checks for Terraform, Kubernetes, Docker, CloudFormation, and more. Powered by Rego policies from Aqua Security."
    logo_url = "https://avatars.githubusercontent.com/u/25220000"

    def collect_rules(self):
        count = 0
        checks_dir = os.path.join(self.clone_dir, "checks")
        if not os.path.isdir(checks_dir):
            checks_dir = self.clone_dir

        for root, dirs, files in os.walk(checks_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".rego"):
                    continue
                if fname.endswith("_test.rego"):
                    # Test fixtures declare the same package as the real check,
                    # which would collide on rule_id and flip-flop content.
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                # Try to find companion JSON/YAML metadata
                metadata = self._find_metadata(fpath)

                # Parse rule ID from package declaration
                rule_id = fname.replace(".rego", "")
                for line in content.split("\n"):
                    if line.startswith("package "):
                        rule_id = line.split("package ")[-1].strip()
                        break

                title = metadata.get("title", rule_id)
                severity = metadata.get("severity", "medium").lower()
                if severity not in ("critical", "high", "medium", "low", "info"):
                    severity = "medium"

                # Derive category from path
                parts = rel_path.split(os.sep)
                category = parts[1] if len(parts) > 1 else parts[0]

                avd_id = metadata.get("avd_id", "")
                tags = metadata.get("tags", [])
                if avd_id:
                    tags.append(avd_id)

                self.upsert(
                    rule_id=rule_id,
                    title=title[:500],
                    description=metadata.get("description", ""),
                    severity=severity,
                    category=category,
                    language="rego",
                    cwe_ids=metadata.get("cwe", []),
                    tags=tags,
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="rego",
                    metadata=metadata,
                )
                count += 1

        logger.info(f"[trivy] Processed {count} checks")

    def _find_metadata(self, rego_path):
        """Look for JSON or YAML metadata alongside the .rego file."""
        base = os.path.splitext(rego_path)[0]
        for ext in (".json", ".yaml", ".yml"):
            meta_path = base + ext
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as f:
                        if ext == ".json":
                            return json.load(f)
                        else:
                            import yaml
                            return yaml.safe_load(f)
                except Exception:
                    pass

        # Try to extract metadata from Rego annotations
        metadata = {}
        try:
            with open(rego_path, "r") as f:
                content = f.read()
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("# title:"):
                    metadata["title"] = line.split(":", 1)[1].strip()
                elif line.startswith("# description:"):
                    metadata["description"] = line.split(":", 1)[1].strip()
                elif line.startswith("# severity:"):
                    metadata["severity"] = line.split(":", 1)[1].strip()
                elif line.startswith("# avd_id:"):
                    metadata["avd_id"] = line.split(":", 1)[1].strip()
        except Exception:
            pass

        return metadata
