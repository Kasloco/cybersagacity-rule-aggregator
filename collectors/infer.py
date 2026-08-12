"""Collector for Facebook/Meta Infer static analyzer rules.

Infer is a static analysis tool for Java, C/C++, Objective-C, and C#.
Rules are defined as OCaml register calls in infer/src/base/IssueType.ml.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Infer severity to aggregator severity mapping
SEVERITY_MAP = {
    "Error": "high",
    "Warning": "medium",
    "Info": "low",
    "Advice": "low",
    "Like": "high",
}


class InferCollector(BaseCollector):
    name = "infer"
    display_name = "Infer (Meta)"
    source_type = "github"
    source_url = "https://github.com/facebook/infer.git"
    description = (
        "Facebook Infer is a static analysis tool detecting null pointer "
        "dereferences, memory leaks, resource leaks, concurrency issues, "
        "and other bugs in Java, C/C++, Objective-C, and C#."
    )
    logo_url = "https://avatars.githubusercontent.com/u/69631"

    def collect_rules(self):
        count = 0

        # Rules are in infer/src/base/IssueType.ml
        issue_type_file = os.path.join(
            self.clone_dir, "infer", "src", "base", "IssueType.ml"
        )

        if os.path.isfile(issue_type_file):
            count += self._parse_issue_types(issue_type_file)
        else:
            # Try alternate paths
            for alt in [
                os.path.join(self.clone_dir, "src", "base", "IssueType.ml"),
                os.path.join(self.clone_dir, "infer", "src", "IR", "IssueType.ml"),
            ]:
                if os.path.isfile(alt):
                    count += self._parse_issue_types(alt)
                    break

        # Also check for documentation files
        docs_dir = os.path.join(
            self.clone_dir, "infer", "src", "base", "documentation", "issues"
        )
        if os.path.isdir(docs_dir):
            count += self._parse_doc_files(docs_dir, count)

        logger.info(f"[infer] Processed {count} rules")

    def _parse_issue_types(self, fpath):
        """Parse IssueType.ml for register calls."""
        count = 0

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        rel_path = os.path.relpath(fpath, self.clone_dir)

        # Pattern: let var = register ~id:"ID" ~hum:"Human Name" Severity ...
        # or: register ~category:CatName ~id:"ID" ~hum:"Human Name" Severity ...
        register_pattern = re.compile(
            r'(?:let\s+\w+\s*=\s*)?register\w*\s+'
            r'(?:~category:(\w+)\s+)?'
            r'~id:"([^"]+)"\s+'
            r'(?:~hum:"([^"]+)"\s+)?'
            r'(\w+)',  # severity (Error, Warning, Info, Advice)
            re.MULTILINE,
        )

        seen_ids = set()

        for match in register_pattern.finditer(content):
            category = match.group(1) or "NoCategory"
            rule_id_raw = match.group(2)
            human_name = match.group(3) or rule_id_raw
            severity_raw = match.group(4)

            if rule_id_raw in seen_ids:
                continue
            seen_ids.add(rule_id_raw)

            severity = SEVERITY_MAP.get(severity_raw, "medium")

            # Try to find documentation reference
            doc_match = re.search(
                r'\[%blob\s+"[^"]*' + re.escape(rule_id_raw) + r'\.md"\]',
                content
            )

            self.upsert(
                rule_id=f"infer:{rule_id_raw}",
                title=human_name[:500],
                description=f"Infer issue type: {human_name}",
                severity=severity,
                category=category.lower().replace("category", ""),
                language="c",
                cwe_ids=[],
                tags=["infer", "facebook", "sast", category.lower()],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="ocaml",
                metadata={
                    "infer_id": rule_id_raw,
                    "severity": severity_raw,
                    "category": category,
                    "has_docs": bool(doc_match),
                },
            )
            count += 1

        return count

    def _parse_doc_files(self, docs_dir, existing_count):
        """Parse documentation .md files for additional descriptions."""
        count = 0

        for fname in os.listdir(docs_dir):
            if not fname.endswith(".md"):
                continue

            rule_id = fname.replace(".md", "")
            fpath = os.path.join(docs_dir, fname)

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            # Only create a new rule if we didn't already capture it
            # from IssueType.ml
            if existing_count > 0:
                continue

            # If IssueType.ml parsing found 0 rules, use docs as fallback
            description = content.strip()[:2000]
            rel_path = os.path.relpath(fpath, self.clone_dir)

            self.upsert(
                rule_id=f"infer:{rule_id}",
                title=rule_id.replace("_", " ").title()[:500],
                description=description,
                severity="medium",
                category="infer",
                language="c",
                cwe_ids=[],
                tags=["infer", "facebook", "sast"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="markdown",
                metadata={
                    "infer_id": rule_id,
                    "source": "documentation",
                },
            )
            count += 1

        return count