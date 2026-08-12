"""Collector for Bandit Python security linter rules."""

import os
import re
import ast
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class BanditCollector(BaseCollector):
    name = "bandit"
    display_name = "Bandit (PyCQA)"
    source_type = "github"
    source_url = "https://github.com/PyCQA/bandit.git"
    description = "Python security linter. Detects common security issues like hardcoded passwords, use of eval/exec, weak crypto, shell injection, and insecure deserialization."
    logo_url = "https://avatars.githubusercontent.com/u/8749848"

    def collect_rules(self):
        count = 0
        plugins_dir = os.path.join(self.clone_dir, "bandit", "plugins")
        if not os.path.isdir(plugins_dir):
            logger.warning(f"[bandit] plugins dir not found")
            return

        for fname in os.listdir(plugins_dir):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue

            fpath = os.path.join(plugins_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            # Extract test IDs and descriptions from docstrings and decorators
            rules = self._parse_plugin(content, fname)
            for rule in rules:
                self.upsert(
                    rule_id=rule["id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    category="python-security",
                    language="python",
                    cwe_ids=rule.get("cwe_ids", []),
                    tags=["bandit", "python", "sast"],
                    source_file=rel_path,
                    rule_content=content[:50000],
                    rule_format="python",
                    metadata={
                        "test_id": rule["id"],
                        "native_severity": rule.get("native_severity", ""),
                    },
                )
                count += 1

        logger.info(f"[bandit] Processed {count} rules")

    def _parse_plugin(self, content, filename):
        """Extract rule metadata from a Bandit plugin file."""
        rules = []

        # Find @test_id decorators or checks.register patterns
        test_ids = re.findall(r"@checks\.register\(.*?['\"]([A-Z]\d{3})['\"]", content)
        if not test_ids:
            test_ids = re.findall(r"test_id\s*=\s*['\"]([A-Z]\d{3})['\"]", content)
        if not test_ids:
            test_ids = re.findall(r"['\"]([B]\d{3})['\"]", content)

        # Get module docstring for description
        try:
            tree = ast.parse(content)
            module_doc = ast.get_docstring(tree) or ""
        except Exception:
            module_doc = ""

        # Get function names and their docstrings
        func_docs = {}
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    doc = ast.get_docstring(node) or ""
                    func_docs[node.name] = doc
        except Exception:
            pass

        seen = set()
        for tid in test_ids:
            if tid in seen:
                continue
            seen.add(tid)

            # Parse native severity from bandit.Issue(severity=bandit.HIGH/MEDIUM/LOW)
            # Bandit plugins declare severity in the return statement, not in decorators
            native_severity = "MEDIUM"  # default
            sev_match = re.search(
                r"severity\s*=\s*bandit\.(HIGH|MEDIUM|LOW)", content
            )
            if not sev_match:
                # Fallback: bare bandit.HIGH/MEDIUM/LOW without severity= prefix
                sev_match = re.search(
                    r"bandit\.(HIGH|MEDIUM|LOW)", content
                )
            if sev_match:
                native_severity = sev_match.group(1).upper()

            severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            severity = severity_map.get(native_severity, "medium")

            # Parse CWE from checks.register or BanditMeta
            cwe_ids = []
            cwe_match = re.search(r"cwe\s*=\s*['\"]?(CWE-?\d+)", content, re.IGNORECASE)
            if cwe_match:
                cwe_num = re.search(r"\d+", cwe_match.group(1))
                if cwe_num:
                    cwe_ids = [f"CWE-{cwe_num.group()}"]

            title = f"Bandit {tid}: {filename.replace('.py', '').replace('_', ' ').title()}"
            description = module_doc[:1000] if module_doc else f"Bandit security check {tid}"

            rules.append({
                "id": tid,
                "title": title,
                "description": description,
                "severity": severity,
                "cwe_ids": cwe_ids,
                "native_severity": native_severity,
            })

        # If no test IDs found but file has content, create a single rule
        if not rules and module_doc:
            rule_id = f"bandit_{filename.replace('.py', '')}"
            rules.append({
                "id": rule_id,
                "title": filename.replace(".py", "").replace("_", " ").title(),
                "description": module_doc[:1000],
                "severity": "medium",
                "cwe_ids": [],
            })

        return rules
