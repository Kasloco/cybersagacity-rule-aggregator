"""Collector for Falco runtime security rules (YAML)."""

import os
import re
import yaml
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class FalcoCollector(BaseCollector):
    name = "falco"
    display_name = "Falco (CNCF)"
    source_type = "github"
    source_url = "https://github.com/falcosecurity/rules.git"
    description = "CNCF runtime security rules for detecting anomalous activity in containers and hosts — privilege escalation, shell spawns, file tampering, and network anomalies."
    logo_url = "https://avatars.githubusercontent.com/u/48585932"

    def collect_rules(self):
        count = 0
        rules_dir = os.path.join(self.clone_dir, "rules")
        if not os.path.isdir(rules_dir):
            rules_dir = self.clone_dir

        for root, dirs, files in os.walk(rules_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith((".yaml", ".yml")):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    docs = list(yaml.safe_load_all(content))
                except Exception:
                    continue

                # Flatten: Falco files can be a list of dicts or multi-doc YAML
                items = []
                for doc in docs:
                    if isinstance(doc, list):
                        items.extend(doc)
                    elif isinstance(doc, dict):
                        items.append(doc)

                for doc in items:
                    if not isinstance(doc, dict):
                        continue

                    # Falco rules have a 'rule' key (macros have 'macro', lists have 'list')
                    if "rule" not in doc:
                        continue

                    rule_name = doc["rule"]
                    rule_id = re.sub(r"[^a-zA-Z0-9_-]", "_", rule_name.lower())

                    priority = str(doc.get("priority", "WARNING")).upper()
                    severity_map = {
                        "EMERGENCY": "critical",
                        "ALERT": "critical",
                        "CRITICAL": "critical",
                        "ERROR": "high",
                        "WARNING": "medium",
                        "NOTICE": "low",
                        "INFORMATIONAL": "info",
                        "DEBUG": "info",
                    }
                    severity = severity_map.get(priority, "medium")

                    tags = doc.get("tags", [])
                    if isinstance(tags, str):
                        tags = [tags]

                    category = "runtime-security"
                    for tag in tags:
                        if tag in ("container", "network", "process", "filesystem"):
                            category = f"runtime-{tag}"
                            break

                    self.upsert(
                        rule_id=rule_id,
                        title=rule_name,
                        description=doc.get("desc", ""),
                        severity=severity,
                        category=category,
                        language="",
                        tags=tags,
                        source_file=rel_path,
                        rule_content=yaml.dump(doc, default_flow_style=False),
                        rule_format="yaml",
                        metadata={
                            "condition": doc.get("condition", ""),
                            "output": doc.get("output", ""),
                            "priority": priority,
                            "enabled": doc.get("enabled", True),
                        },
                    )
                    count += 1

        logger.info(f"[falco] Processed {count} rules")
