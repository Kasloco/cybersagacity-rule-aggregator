"""Collector for GitHub CodeQL security queries.

CodeQL is GitHub's semantic code analysis engine. Security queries are
defined as .ql files in ql/src/ with metadata comments containing:
  - @id: unique rule identifier
  - @name: human-readable name
  - @description: detailed description
  - @kind: problem | path-problem | metric | etc.
  - @security-severity: 1.0-10.0 (for security queries)
  - @tags: optional tags (e.g., security, external/cwe/cwe-xxx)
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# CodeQL severity from @security-severity (0-10 CVSS-like score)
def severity_from_score(score_str):
    try:
        score = float(score_str)
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"
    except (ValueError, TypeError):
        return "info"


class CodeQLCollector(BaseCollector):
    name = "codeql"
    display_name = "GitHub CodeQL"
    source_type = "github"
    source_url = "https://github.com/github/codeql.git"
    description = (
        "GitHub CodeQL is a semantic code analysis engine that treats code "
        "as data. Security queries detect vulnerabilities across C/C++, C#, "
        "Go, Java, JavaScript, Python, Ruby, Rust, and Swift. Rules are .ql "
        "files with metadata annotations for CWE mappings and severity."
    )
    logo_url = "https://avatars.githubusercontent.com/u/53879551"

    def clone_or_pull(self):
        """Override to use sparse checkout — CodeQL is 500MB+ but we only need ql/src/."""
        import subprocess
        os.makedirs(os.path.dirname(self.clone_dir), exist_ok=True)
        if os.path.exists(os.path.join(self.clone_dir, ".git")):
            logger.info(f"[{self.name}] Pulling latest changes...")
            subprocess.run(["git", "-C", self.clone_dir, "pull"], check=True)
        else:
            logger.info(f"[{self.name}] Cloning {self.source_url} (sparse: ql/src only)...")
            # Clone with no checkout, then sparse checkout only ql/src/
            subprocess.run([
                "git", "clone", "--depth=1", "--single-branch",
                "--filter=blob:none", "--no-checkout",
                self.source_url, self.clone_dir,
            ], check=True)
            subprocess.run(["git", "-C", self.clone_dir, "sparse-checkout", "init", "--cone"], check=True)
            subprocess.run(["git", "-C", self.clone_dir, "sparse-checkout", "set", "ql/src"], check=True)
            subprocess.run(["git", "-C", self.clone_dir, "checkout"], check=True)
        import git as gitpython
        return gitpython.Repo(self.clone_dir)

    def collect_rules(self):
        count = 0

        # CodeQL repo structure: <lang>/ql/src/Security/CWE-xxx/RuleName.ql
        # Languages: cpp, csharp, go, java, javascript, python, ruby, swift
        # Also check ql/src/ for any top-level structure
        for root, dirs, files in os.walk(self.clone_dir):
            # Skip test, downgrades, and hidden directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("test", "downgrades", "node_modules")]
            for fname in files:
                if not fname.endswith(".ql"):
                    continue
                # Only include .ql files under Security/ directories
                if "/Security/" not in root and "/security/" not in root.lower():
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_ql_file(fpath, rel_path)

        logger.info(f"[codeql] Processed {count} rules")

    def _parse_ql_file(self, fpath, rel_path):
        """Parse a .ql file for metadata comments."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        # Extract metadata from the comment block before the query
        # Pattern: /**
        #          * @name Some Rule Name
        #          * @description Description text
        #          * @id lang/rule-id
        #          * @kind problem
        #          * @security-severity 8.2
        #          * @tags security external/cwe/cwe-79
        #          */
        metadata = {}

        # Find the metadata block
        meta_block = re.search(
            r'/\*\*\s*\n(.*?)\*/',
            content,
            re.DOTALL,
        )
        if not meta_block:
            return 0

        for line in meta_block.group(1).split("\n"):
            line = line.strip().lstrip("* ").strip()
            m = re.match(r'@(\w[\w-]*)\s+(.*)', line)
            if m:
                key = m.group(1)
                val = m.group(2).strip()
                if key not in metadata:
                    metadata[key] = val

        if not metadata.get("id"):
            return 0

        rule_id = metadata["id"]
        title = metadata.get("name", rule_id)
        description = metadata.get("description", "")

        # Extract severity from @security-severity
        severity = "info"
        sec_sev = metadata.get("security-severity")
        if sec_sev:
            severity = severity_from_score(sec_sev)

        # Extract CWE mappings from @tags
        cwe_ids = []
        tags = metadata.get("tags", "")
        for cwe_match in re.finditer(r'cwe-(\d+)', tags):
            cwe_ids.append(f"CWE-{cwe_match.group(1)}")
        cwe_str = ", ".join(cwe_ids) if cwe_ids else ""

        self.upsert(
            rule_id,
            title,
            severity=severity,
            cwe_ids=cwe_str,
            description=description[:500] if description else None,
            metadata={
                "kind": metadata.get("kind", ""),
                "security_severity": sec_sev or "",
                "path": rel_path,
            },
        )
        return 1