"""Collector for gitleaks (secrets scanner) rules.

gitleaks is a secret detection tool that scans git repos, files, and stdin
for leaked credentials, API keys, tokens, and other sensitive data. Rules
(detectors) are defined in config/gitleaks.toml as TOML [[rules]] entries
with id, description, regex, keywords, and optional entropy.
"""

import os
import logging

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore

from .base import BaseCollector

logger = logging.getLogger(__name__)


class GitleaksCollector(BaseCollector):
    name = "gitleaks"
    display_name = "gitleaks"
    source_type = "github"
    source_url = "https://github.com/gitleaks/gitleaks.git"
    description = (
        "gitleaks is a secret detection tool that scans for leaked "
        "credentials, API keys, tokens, certificates, and other sensitive "
        "data. Rules cover 200+ service providers including AWS, GitHub, "
        "Google, Azure, Stripe, Slack, Twilio, and more."
    )
    logo_url = "https://avatars.githubusercontent.com/u/50987005"

    def collect_rules(self):
        count = 0

        # Primary config: config/gitleaks.toml
        config_path = os.path.join(self.clone_dir, "config", "gitleaks.toml")
        if not os.path.isfile(config_path):
            # Try root .gitleaks.toml
            config_path = os.path.join(self.clone_dir, ".gitleaks.toml")
            if not os.path.isfile(config_path):
                logger.warning("[gitleaks] config/gitleaks.toml not found")
                return

        rel_path = os.path.relpath(config_path, self.clone_dir)

        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            logger.warning(f"[gitleaks] Failed to parse {config_path}: {e}")
            return

        rules = data.get("rules", [])
        logger.info(f"[gitleaks] Found {len(rules)} rules in config")

        for rule in rules:
            rid = rule.get("id", "")
            if not rid:
                continue

            description = rule.get("description", "")
            regex_pattern = rule.get("regex", "")
            keywords = rule.get("keywords", [])
            entropy = rule.get("entropy")
            path_pattern = rule.get("path", "")
            secret_group = rule.get("secretGroup")
            allowlists = rule.get("allowlists", [])

            # gitleaks doesn't have explicit severity levels — all rules
            # detect secrets, so we map based on entropy if available
            if entropy is not None and entropy >= 4.0:
                severity = "high"
            elif entropy is not None and entropy >= 2.0:
                severity = "medium"
            else:
                severity = "medium"

            # Derive category from the rule ID (service name)
            category = self._derive_category(rid)

            # Build tags
            tags = ["gitleaks", "secrets", "credential-detection", category]
            if entropy is not None:
                tags.append(f"entropy-{entropy}")

            self.upsert(
                rule_id=f"gitleaks:{rid}",
                title=description[:500] if description else rid,
                description=description[:2000],
                severity=severity,
                category="secrets",
                language="",  # language-agnostic — secrets can be in any file
                cwe_ids=["CWE-798"],  # Use of Hard-coded Credentials
                tags=tags,
                source_file=rel_path,
                rule_content=str({
                    "id": rid,
                    "regex": regex_pattern,
                    "keywords": keywords,
                    "entropy": entropy,
                    "path": path_pattern,
                    "secretGroup": secret_group,
                    "allowlists": allowlists,
                })[:50000],
                rule_format="toml",
                metadata={
                    "gitleaks_id": rid,
                    "regex": regex_pattern,
                    "keywords": keywords,
                    "entropy": entropy,
                    "path": path_pattern,
                    "secret_group": secret_group,
                    "has_allowlist": len(allowlists) > 0,
                    "category": category,
                },
            )
            count += 1

        logger.info(f"[gitleaks] Processed {count} rules")

    @staticmethod
    def _derive_category(rid):
        """Derive a service/category name from the gitleaks rule ID."""
        # Rule IDs are like "aws-access-token", "github-token", etc.
        # Extract the first segment as the category
        parts = rid.split("-")
        return parts[0] if parts else "general"