"""Collector for PHPCS Security Audit rules.

phpcs-security-audit is a set of PHP_CodeSniffer sniffs for detecting
security issues in PHP code. Rules are defined as PHP sniff classes in
Security/Sniffs/ with addError()/addWarning() calls that include rule codes
like 'NoEvals', 'ErrSystemExec', 'WarnFilesystem', etc.

Rule IDs follow the pattern: Security.<Category>.<SniffName>.<Code>
e.g., Security.BadFunctions.NoEvalsSniff.NoEvals
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class PhpcsSecurityAuditCollector(BaseCollector):
    name = "phpcs_security_audit"
    display_name = "PHPCS Security Audit"
    source_type = "github"
    source_url = "https://github.com/FloeDesignTechnologies/phpcs-security-audit.git"
    description = (
        "PHP_CodeSniffer security ruleset that detects dangerous PHP "
        "functions, insecure crypto, SQL injection, XSS, command injection, "
        "path traversal, RFI, and CVE-specific issues. Sniffs are organized "
        "by category: BadFunctions, Misc, CVE, Drupal7."
    )
    logo_url = "https://avatars.githubusercontent.com/u/9277557"

    def collect_rules(self):
        count = 0

        sniffs_dir = os.path.join(self.clone_dir, "Security", "Sniffs")
        if not os.path.isdir(sniffs_dir):
            logger.warning("[phpcs_security_audit] Sniffs directory not found")
            return

        for root, dirs, files in os.walk(sniffs_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in sorted(files):
                if not fname.endswith("Sniff.php"):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_sniff_file(fpath, rel_path)

        logger.info(f"[phpcs_security_audit] Processed {count} rules")

    def _parse_sniff_file(self, fpath, rel_path):
        """Parse a PHP sniff file for rule definitions.

        Each sniff calls addError() / addWarning() with a message and a
        rule code (the third argument). Multiple calls in one file can
        share or have different codes. We collect all unique codes.

        Messages may be:
          - String literals: addError('msg', $ptr, 'Code')
          - Variables: $msg = 'msg'; addError($msg, $ptr, 'Code')
          - Concatenated: addError('msg' . $var, $ptr, 'Code')
        """
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        count = 0

        # Extract the sniff category from the directory path
        # e.g., Security/Sniffs/BadFunctions/NoEvalsSniff.php -> BadFunctions
        parts = rel_path.split(os.sep)
        sniff_name = os.path.basename(fpath).replace("Sniff.php", "")
        category = ""
        if "Sniffs" in parts:
            idx = parts.index("Sniffs")
            if idx + 1 < len(parts):
                category = parts[idx + 1]

        # Collect variable assignments for message resolution
        var_msgs = {}
        for m in re.finditer(
            r"\$(\w+)\s*=\s*'([^']*(?:\\'[^']*)*)'", content
        ):
            var_msgs[m.group(1)] = m.group(2).replace("\\'", "'")

        # Find all addError and addWarning calls with their codes
        seen_codes = set()

        # Pattern: addError('message', $ptr, 'Code')
        for m in re.finditer(
            r"addError\s*\(\s*'([^']*(?:\\'[^']*)*)'\s*,\s*\$\w+\s*,\s*'([^']+)'",
            content,
        ):
            msg = m.group(1).replace("\\'", "'")
            code = m.group(2)
            if code not in seen_codes:
                seen_codes.add(code)
                self._upsert_rule(code, msg, "error", category,
                                  sniff_name, rel_path, content)
                count += 1

        # Pattern: addError($var, $ptr, 'Code') — resolve variable
        for m in re.finditer(
            r"addError\s*\(\s*\$(\w+)\s*,\s*\$\w+\s*,\s*'([^']+)'",
            content,
        ):
            var_name = m.group(1)
            code = m.group(2)
            if code in seen_codes:
                continue
            msg = var_msgs.get(var_name, "")
            seen_codes.add(code)
            self._upsert_rule(code, msg, "error", category,
                              sniff_name, rel_path, content)
            count += 1

        # Pattern: addError($var . 'suffix', $ptr, 'Code') — concatenated
        for m in re.finditer(
            r"addError\s*\(\s*\$(\w+)\s*\.\s*'([^']*)'\s*,\s*\$\w+\s*,\s*'([^']+)'",
            content,
        ):
            var_name = m.group(1)
            suffix = m.group(2)
            code = m.group(3)
            if code in seen_codes:
                continue
            msg = var_msgs.get(var_name, "") + suffix
            seen_codes.add(code)
            self._upsert_rule(code, msg, "error", category,
                              sniff_name, rel_path, content)
            count += 1

        # Pattern: addWarning('message', $ptr, 'Code')
        for m in re.finditer(
            r"addWarning\s*\(\s*'([^']*(?:\\'[^']*)*)'\s*,\s*\$\w+\s*,\s*'([^']+)'",
            content,
        ):
            msg = m.group(1).replace("\\'", "'")
            code = m.group(2)
            if code in seen_codes:
                continue
            seen_codes.add(code)
            self._upsert_rule(code, msg, "warning", category,
                              sniff_name, rel_path, content)
            count += 1

        # Pattern: addWarning($var, $ptr, 'Code') — resolve variable
        for m in re.finditer(
            r"addWarning\s*\(\s*\$(\w+)\s*,\s*\$\w+\s*,\s*'([^']+)'",
            content,
        ):
            var_name = m.group(1)
            code = m.group(2)
            if code in seen_codes:
                continue
            msg = var_msgs.get(var_name, "")
            seen_codes.add(code)
            self._upsert_rule(code, msg, "warning", category,
                              sniff_name, rel_path, content)
            count += 1

        # Pattern: addWarning($var . 'suffix', $ptr, 'Code') — concatenated
        for m in re.finditer(
            r"addWarning\s*\(\s*\$(\w+)\s*\.\s*'([^']*)'\s*,\s*\$\w+\s*,\s*'([^']+)'",
            content,
        ):
            var_name = m.group(1)
            suffix = m.group(2)
            code = m.group(3)
            if code in seen_codes:
                continue
            msg = var_msgs.get(var_name, "") + suffix
            seen_codes.add(code)
            self._upsert_rule(code, msg, "warning", category,
                              sniff_name, rel_path, content)
            count += 1

        return count

    def _upsert_rule(self, code, msg, rule_type, category,
                     sniff_name, rel_path, content):
        """Upsert a single rule with the given code and message."""
        # Build full rule ID: Security.Category.SniffName.Code
        rule_id = f"Security.{category}.{sniff_name}.{code}" if category else \
                  f"Security.{sniff_name}.{code}"

        # Determine severity
        if rule_type == "error":
            severity = "high"
        else:
            severity = "medium"

        # Use the message as title, or fall back to the code
        title = msg if msg else f"PHPCS Security Audit: {code}"
        if len(title) > 500:
            title = title[:500]

        # Extract docblock description
        docblock_match = re.search(r"/\*\*\s*\n(.*?)\*/", content, re.DOTALL)
        description = ""
        if docblock_match:
            docblock = docblock_match.group(1)
            lines = [
                line.strip().lstrip("*").strip()
                for line in docblock.split("\n")
                if line.strip() and not line.strip().startswith("@")
                and not line.strip().startswith("*/")
            ]
            description = " ".join(lines)[:2000]

        if not description:
            description = msg if msg else f"PHPCS Security Audit rule: {code}"

        self.upsert(
            rule_id=rule_id,
            title=title,
            description=description[:2000],
            severity=severity,
            category=category.lower() if category else "security",
            language="php",
            cwe_ids=[],
            tags=["phpcs-security-audit", "php", "sast", "phpcs",
                  category.lower() if category else "general",
                  rule_type],
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="php",
            metadata={
                "sniff_name": sniff_name,
                "category": category,
                "rule_code": code,
                "rule_type": rule_type,
                "message": msg,
            },
        )