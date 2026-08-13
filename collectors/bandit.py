"""Collector for Bandit Python security linter rules."""

import os
import re
import ast
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Map bandit's issue.Cwe enum names to CWE numbers (from bandit/core/issue.py)
CWE_MAP = {
    "NOTSET": 0,
    "IMPROPER_INPUT_VALIDATION": 20,
    "PATH_TRAVERSAL": 22,
    "OS_COMMAND_INJECTION": 78,
    "XSS": 79,
    "BASIC_XSS": 80,
    "SQL_INJECTION": 89,
    "CODE_INJECTION": 94,
    "IMPROPER_WILDCARD_NEUTRALIZATION": 155,
    "HARD_CODED_PASSWORD": 259,
    "IMPROPER_ACCESS_CONTROL": 284,
    "IMPROPER_CERT_VALIDATION": 295,
    "CLEARTEXT_TRANSMISSION": 319,
    "INADEQUATE_ENCRYPTION_STRENGTH": 326,
    "BROKEN_CRYPTO": 327,
    "INSUFFICIENT_RANDOM_VALUES": 330,
    "INSECURE_TEMP_FILE": 377,
    "UNCONTROLLED_RESOURCE_CONSUMPTION": 400,
    "DOWNLOAD_OF_CODE_WITHOUT_INTEGRITY_CHECK": 494,
    "DESERIALIZATION_OF_UNTRUSTED_DATA": 502,
    "MULTIPLE_BINDS": 605,
    "IMPROPER_CHECK_OF_EXCEPT_COND": 703,
    "INCORRECT_PERMISSION_ASSIGNMENT": 732,
    "INAPPROPRIATE_ENCODING_FOR_OUTPUT_CONTEXT": 838,
}

SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class BanditCollector(BaseCollector):
    name = "bandit"
    display_name = "Bandit (PyCQA)"
    source_type = "github"
    source_url = "https://github.com/PyCQA/bandit.git"
    description = "Python security linter. Detects common security issues like hardcoded passwords, use of eval/exec, weak crypto, shell injection, and insecure deserialization."
    logo_url = "https://avatars.githubusercontent.com/u/8749848"

    def collect_rules(self):
        count = 0

        # --- 1. Plugin tests (bandit/plugins/*.py) ---
        plugins_dir = os.path.join(self.clone_dir, "bandit", "plugins")
        if os.path.isdir(plugins_dir):
            for fname in sorted(os.listdir(plugins_dir)):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                fpath = os.path.join(plugins_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue
                for rule in self._parse_plugin(content, fname):
                    self._upsert_rule(rule, rel_path, content)
                    count += 1
        else:
            logger.warning("[bandit] plugins dir not found")

        # --- 2. Blacklist tests (bandit/blacklists/calls.py & imports.py) ---
        blacklists_dir = os.path.join(self.clone_dir, "bandit", "blacklists")
        if os.path.isdir(blacklists_dir):
            for fname in sorted(os.listdir(blacklists_dir)):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                fpath = os.path.join(blacklists_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue
                for rule in self._parse_blacklist(content, fname):
                    self._upsert_rule(rule, rel_path, content)
                    count += 1

        # --- 3. Removed plugins documented only in .rst files ---
        # Only parse .rst files for IDs not already found from Python source.
        # Most .rst files are just doc mirrors of existing plugins; only removed
        # plugins (e.g. B109, B111) exist solely as .rst with no .py source.
        docs_dir = os.path.join(self.clone_dir, "doc", "source", "plugins")
        if os.path.isdir(docs_dir):
            # Collect .rst files and extract their B-IDs; only keep ones not
            # already covered by plugins/ or blacklists/.
            existing_ids = set()
            # Re-scan plugin and blacklist dirs to build the ID set
            if os.path.isdir(plugins_dir):
                for fname in os.listdir(plugins_dir):
                    if fname.endswith(".py") and not fname.startswith("_"):
                        try:
                            with open(os.path.join(plugins_dir, fname), "r", encoding="utf-8") as f:
                                src = f.read()
                            existing_ids.update(re.findall(r"'(B\d{3})'|\"(B\d{3})\"", src))
                        except Exception:
                            pass
            existing_ids = {bid for pair in existing_ids for bid in pair if bid}

            for fname in sorted(os.listdir(docs_dir)):
                if not fname.endswith(".rst") or fname.startswith("_"):
                    continue
                fpath = os.path.join(docs_dir, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue
                for rule in self._parse_rst_plugin(content, fname):
                    if rule["id"] in existing_ids:
                        continue
                    self._upsert_rule(rule, rel_path, content)
                    count += 1

        logger.info(f"[bandit] Processed {count} rules")

    def _upsert_rule(self, rule, rel_path, content):
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

    # -- plugin parsing -----------------------------------------------------

    def _parse_plugin(self, content, filename):
        """Extract rule metadata from a Bandit plugin file using AST.

        Each plugin file may define one or more test functions decorated with
        @test.test_id("Bxxx").  The B-ID, title, severity and CWE are extracted
        per-function when possible, falling back to module-level docstring info.
        """
        rules = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return rules

        module_doc = ast.get_docstring(tree) or ""

        # Pre-extract CWE references from the entire file content (issue.Cwe.XXX)
        file_cwe_names = re.findall(r"issue\.Cwe\.([A-Z_]+)", content)

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            # Look for @test.test_id("Bxxx") decorator
            bid = None
            for dec in node.decorator_list:
                dec_src = ast.dump(dec)
                m = re.search(r"'(B\d{3})'", dec_src)
                if not m:
                    m = re.search(r'"(B\d{3})"', dec_src)
                if m:
                    bid = m.group(1)
                    break
            if not bid:
                continue

            func_doc = ast.get_docstring(node) or ""

            # --- title ---
            # Try **Bxxx: Title** in function docstring first
            title = None
            m = re.search(r"\*\*" + re.escape(bid) + r":\s*(.+?)\*\*", func_doc)
            if m:
                title = m.group(1).strip()
            if not title:
                # Try module docstring: "Bxxx: Title" followed by underline
                m = re.search(
                    re.escape(bid) + r":\s*(.+)", module_doc
                )
                if m:
                    title = m.group(1).strip()
            if not title:
                title = node.name.replace("_", " ").title()

            # --- description ---
            description = func_doc[:1000] if func_doc else module_doc[:1000]
            if not description:
                description = f"Bandit security check {bid}"

            # --- severity ---
            native_severity = self._extract_severity_from_node(node)
            if not native_severity:
                native_severity = "MEDIUM"
            severity = SEVERITY_MAP.get(native_severity, "medium")

            # --- CWE ---
            cwe_ids = self._extract_cwe_from_content(content)
            if not cwe_ids:
                # Fall back to CWE numbers mentioned in docstrings
                cwe_nums = re.findall(r"CWE-(\d+)", func_doc or module_doc)
                cwe_ids = [f"CWE-{n}" for n in dict.fromkeys(cwe_nums)]

            rules.append({
                "id": bid,
                "title": f"{bid}: {title}" if not title.startswith(bid) else title,
                "description": description,
                "severity": severity,
                "cwe_ids": cwe_ids,
                "native_severity": native_severity,
            })

        # Fallback: if AST didn't find any test_ids, try regex on module docstring
        if not rules and module_doc:
            m = re.search(r"(B\d{3}):\s*(.+)", module_doc)
            if m:
                bid = m.group(1)
                title = m.group(2).strip()
                cwe_nums = re.findall(r"CWE-(\d+)", module_doc)
                cwe_ids = [f"CWE-{n}" for n in dict.fromkeys(cwe_nums)]
                native_severity = self._extract_severity_from_content(content)
                rules.append({
                    "id": bid,
                    "title": f"{bid}: {title}",
                    "description": module_doc[:1000],
                    "severity": SEVERITY_MAP.get(native_severity or "MEDIUM", "medium"),
                    "cwe_ids": cwe_ids,
                    "native_severity": native_severity or "MEDIUM",
                })

        return rules

    def _extract_severity_from_node(self, func_node):
        """Look for severity=bandit.HIGH/MEDIUM/LOW within a function body."""
        try:
            src = ast.unparse(func_node)
        except Exception:
            return None
        m = re.search(r"severity\s*=\s*bandit\.(HIGH|MEDIUM|LOW)", src)
        if m:
            return m.group(1)
        # Some helpers use bare bandit.LOW / bandit.HIGH returns
        m = re.search(r"return\s+bandit\.(HIGH|MEDIUM|LOW)", src)
        if m:
            return m.group(1)
        return None

    def _extract_severity_from_content(self, content):
        m = re.search(r"severity\s*=\s*bandit\.(HIGH|MEDIUM|LOW)", content)
        if m:
            return m.group(1)
        m = re.search(r"bandit\.(HIGH|MEDIUM|LOW)", content)
        if m:
            return m.group(1)
        return None

    def _extract_cwe_from_content(self, content):
        """Extract CWE IDs from issue.Cwe.XXX references in source code."""
        cwe_names = re.findall(r"issue\.Cwe\.([A-Z_]+)", content)
        cwe_nums = []
        for name in cwe_names:
            num = CWE_MAP.get(name)
            if num and num != 0:
                cwe_nums.append(str(num))
        # Deduplicate preserving order
        seen = set()
        result = []
        for n in cwe_nums:
            if n not in seen:
                seen.add(n)
                result.append(f"CWE-{n}")
        return result

    # -- blacklist parsing --------------------------------------------------

    def _parse_blacklist(self, content, filename):
        """Extract rule metadata from a Bandit blacklist file.

        Blacklist files define rules via utils.build_conf_dict(name, "Bxxx",
        issue.Cwe.XXX, [...], "message", "SEVERITY") calls inside gen_blacklist().
        """
        rules = []

        # Pattern: utils.build_conf_dict( "name", "Bxxx", issue.Cwe.XXX, ... )
        # We parse with AST for accuracy.
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return rules

        module_doc = ast.get_docstring(tree) or ""

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Match utils.build_conf_dict(...) or build_conf_dict(...)
            func = node.func
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id
            else:
                continue
            if func_name != "build_conf_dict":
                continue
            if not node.args or len(node.args) < 3:
                continue

            # arg 0: name (str), arg 1: B-ID (str), arg 2: cwe (issue.Cwe.XXX)
            try:
                name = ast.literal_eval(node.args[0])
                bid = ast.literal_eval(node.args[1])
            except Exception:
                continue
            if not re.match(r"B\d{3}", bid):
                continue

            # CWE
            cwe_ids = []
            cwe_arg = node.args[2]
            cwe_src = ast.dump(cwe_arg)
            cwe_names = re.findall(r"([A-Z_]+)", cwe_src)
            for cname in cwe_names:
                num = CWE_MAP.get(cname)
                if num and num != 0:
                    cwe_ids.append(f"CWE-{num}")
            # Deduplicate
            cwe_ids = list(dict.fromkeys(cwe_ids))

            # Message (arg 4) — may contain {name} placeholder
            message = ""
            if len(node.args) >= 5:
                try:
                    message = ast.literal_eval(node.args[4])
                except Exception:
                    pass
            if not message:
                # Search module docstring for this B-ID
                m = re.search(
                    re.escape(bid) + r":\s*(\w+)", module_doc
                )
                if m:
                    message = m.group(1)

            # Severity (arg 5, optional, default MEDIUM)
            native_severity = "MEDIUM"
            if len(node.args) >= 6:
                try:
                    native_severity = ast.literal_eval(node.args[5]).upper()
                except Exception:
                    pass

            # Build a description from the module docstring section for this B-ID
            description = message.replace("{name}", name)
            # Try to find a richer description in the module docstring
            if module_doc:
                # Pattern: "Bxxx: name\n----\n\ndescription text"
                pattern = re.escape(bid) + r":\s*\n[-]+\n\n(.+?)(?=\n\nB\d{3}:|\n\n$|\Z)"
                m = re.search(pattern, module_doc, re.DOTALL)
                if m:
                    description = m.group(1).strip()[:1000]

            title = f"{bid}: {name}"

            rules.append({
                "id": bid,
                "title": title,
                "description": description,
                "severity": SEVERITY_MAP.get(native_severity, "medium"),
                "cwe_ids": cwe_ids,
                "native_severity": native_severity,
            })

        # Also extract removed/skipped IDs that only exist in the module docstring.
        # These are documented as "has been removed" but still listed in bandit docs.
        found_ids = {r["id"] for r in rules}
        if module_doc:
            # Find all Bxxx: name sections in the docstring
            doc_sections = re.finditer(
                r"(B\d{3}):\s*(\S+).*?(?=\nB\d{3}:|\Z)",
                module_doc,
                re.DOTALL,
            )
            for m in doc_sections:
                bid = m.group(1)
                name = m.group(2)
                if bid in found_ids:
                    continue
                section_text = m.group(0).strip()[:1000]
                # Extract CWE numbers from the docstring section
                cwe_nums = re.findall(r"CWE-(\d+)", section_text)
                cwe_ids = [f"CWE-{n}" for n in dict.fromkeys(cwe_nums)]
                # Try to extract severity from table rows in the section
                native_severity = "MEDIUM"
                sev_m = re.search(r"\|\s*(High|Medium|Low)\s*\|", section_text, re.IGNORECASE)
                if sev_m:
                    native_severity = sev_m.group(1).upper()
                # Get description (text between header line and the table)
                desc_m = re.search(
                    r"B\d{3}:\s*\S+\n[-]+\n\n(.+?)(?=\n\n|\+-----|\Z)",
                    section_text,
                    re.DOTALL,
                )
                description = desc_m.group(1).strip()[:1000] if desc_m else section_text
                rules.append({
                    "id": bid,
                    "title": f"{bid}: {name}",
                    "description": description,
                    "severity": SEVERITY_MAP.get(native_severity, "medium"),
                    "cwe_ids": cwe_ids,
                    "native_severity": native_severity,
                })

        return rules

    # -- rst doc parsing ----------------------------------------------------

    def _parse_rst_plugin(self, content, filename):
        """Extract rule metadata from a Bandit .rst documentation file.

        Some plugins have been removed from the source code but their .rst docs
        remain (e.g. B109, B111).  We parse these to capture their metadata.
        """
        rules = []

        # Pattern: "Bxxx: name" followed by underline of dashes
        m = re.search(r"(B\d{3}):\s*(\S+)\s*\n-+\n", content)
        if not m:
            return rules

        bid = m.group(1)
        name = m.group(2)

        # Get the full title: "Bxxx: Test for ..."
        title_m = re.search(
            re.escape(bid) + r":\s*(.+?)(?:\n\n|\Z)",
            content[m.end():],
            re.DOTALL,
        )
        title_text = title_m.group(1).strip() if title_m else name

        # Description: text after the title, up to Config Options or Example
        desc_m = re.search(
            r"(?:This plugin has been removed\.\s*)?(.+?)(?=\*\*Config|\n:Example:|\Z)",
            content[m.end():],
            re.DOTALL,
        )
        description = desc_m.group(1).strip()[:1000] if desc_m else title_text

        # CWE — look for CWE-xxx in the doc
        cwe_nums = re.findall(r"CWE-(\d+)", content)
        cwe_ids = [f"CWE-{n}" for n in dict.fromkeys(cwe_nums)]

        # Severity from example section
        native_severity = "MEDIUM"
        sev_m = re.search(r"Severity:\s*(High|Medium|Low)", content, re.IGNORECASE)
        if sev_m:
            native_severity = sev_m.group(1).upper()

        rules.append({
            "id": bid,
            "title": f"{bid}: {title_text}",
            "description": description,
            "severity": SEVERITY_MAP.get(native_severity, "medium"),
            "cwe_ids": cwe_ids,
            "native_severity": native_severity,
        })

        return rules
