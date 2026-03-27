"""Collector for ESLint security plugin rules."""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class ESLintSecurityCollector(BaseCollector):
    name = "eslint_security"
    display_name = "ESLint Security"
    source_type = "github"
    source_url = "https://github.com/eslint-community/eslint-plugin-security.git"
    description = "ESLint plugin for Node.js security. Detects eval usage, child_process injection, non-literal require/RegExp, prototype pollution, and timing attacks."
    logo_url = "https://avatars.githubusercontent.com/u/6019716"

    def collect_rules(self):
        count = 0
        rules_dir = os.path.join(self.clone_dir, "rules")
        if not os.path.isdir(rules_dir):
            # Try lib/rules
            rules_dir = os.path.join(self.clone_dir, "lib", "rules")
        if not os.path.isdir(rules_dir):
            logger.warning(f"[eslint_security] rules dir not found")
            return

        for fname in os.listdir(rules_dir):
            if not fname.endswith(".js"):
                continue

            fpath = os.path.join(rules_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            rule_name = fname.replace(".js", "")
            rule_id = f"security/{rule_name}"

            # Try to extract description from meta
            description = ""
            desc_match = re.search(r'description\s*[:=]\s*["\']([^"\']+)["\']', content)
            if desc_match:
                description = desc_match.group(1)

            # Try to extract from docs
            doc_path = os.path.join(self.clone_dir, "docs", "rules", f"{rule_name}.md")
            if os.path.exists(doc_path):
                try:
                    with open(doc_path, "r") as f:
                        doc_content = f.read()
                    # First paragraph after title
                    lines = doc_content.split("\n")
                    for i, line in enumerate(lines):
                        if line.startswith("#"):
                            for j in range(i + 1, min(i + 10, len(lines))):
                                if lines[j].strip():
                                    description = lines[j].strip()
                                    break
                            break
                except Exception:
                    pass

            # Severity based on rule type
            high_severity = ["detect-eval-with-expression", "detect-child-process",
                           "detect-non-literal-require", "detect-possible-timing-attacks"]
            severity = "high" if rule_name in high_severity else "medium"

            title = rule_name.replace("detect-", "").replace("-", " ").title()
            if rule_name.startswith("detect-"):
                title = f"Detect {title}"

            self.upsert(
                rule_id=rule_id,
                title=title[:500],
                description=description or f"ESLint security rule: {rule_name}",
                severity=severity,
                category="javascript-security",
                language="javascript",
                tags=["eslint", "javascript", "nodejs", "sast"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="javascript",
                metadata={"plugin": "eslint-plugin-security"},
            )
            count += 1

        logger.info(f"[eslint_security] Processed {count} rules")
