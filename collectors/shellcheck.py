"""Collector for ShellCheck shell script linter rules."""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# ShellCheck severity mapping:
#   error   → high   (ShellCheck will exit with non-zero for these)
#   warning → medium (most common)
#   info    → low    (style/suggestions)
#   style   → low    (cosmetic)
SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "style": "low",
}

# Haskell files that contain ShellCheck check definitions with code numbers.
CHECK_FILES = [
    "src/ShellCheck/Analytics.hs",
    "src/ShellCheck/Checks/Commands.hs",
    "src/ShellCheck/Checks/ShellSupport.hs",
]

# Regex for ShellCheck's warn/err function calls that include a numeric code
# and a quoted message.  The calls look like:
#   warn id 2048 "Use \"$@\" (with quotes) to prevent whitespace problems."
#   err id 2066 "Since you double quoted this, it will not word split, ..."
#   errWithFix id 2265 "Use && for logical AND. ..."
#   warnWithFix id 2191 "The = here is literal. ..."
#
# Some calls span multiple lines, so we search a window of lines after each
# function keyword.
_WARN_FUNC_RE = re.compile(
    r'\b(errWithFix|warnWithFix|warnWithFixes|errWithFixes|err|warn)\b'
)
_NUM_RE = re.compile(r'\b(\d{3,4})\b')
_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


class ShellCheckCollector(BaseCollector):
    name = "shellcheck"
    display_name = "ShellCheck"
    source_type = "github"
    source_url = "https://github.com/koalaman/shellcheck.git"
    description = (
        "Static analysis and linter for shell scripts (sh, bash, dash, ksh). "
        "Detects quoting issues, word splitting, unsafe expansions, "
        "POSIX compatibility problems, common bugs, and style issues. "
        "Hundreds of checks identified by SC codes (SC1000–SC2300+)."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1142903"

    def collect_rules(self):
        count = 0
        checks = {}

        for rel_path in CHECK_FILES:
            fpath = os.path.join(self.clone_dir, rel_path)
            if not os.path.isfile(fpath):
                continue
            file_checks = self._parse_haskell_file(fpath, rel_path)
            for sc_code, entry in file_checks.items():
                if sc_code not in checks or len(entry["message"]) > len(checks[sc_code]["message"]):
                    checks[sc_code] = entry

        # Upsert all collected checks
        for sc_code, entry in sorted(checks.items()):
            severity = SEVERITY_MAP.get(entry["severity"], "low")
            message = entry["message"]

            self.upsert(
                rule_id=sc_code,
                title=f"ShellCheck {sc_code}: {message}"[:500],
                description=message,
                severity=severity,
                category=entry["severity"],  # native ShellCheck severity
                language="shell",
                cwe_ids=[],
                tags=["shellcheck", "shell", "bash", "sh", "linter",
                      entry["severity"]],
                source_file=entry["source_file"],
                rule_content="",
                rule_format="haskell",
                metadata={
                    "code": sc_code,
                    "severity_native": entry["severity"],
                    "function": entry["function"],
                    "source_line": entry["line"],
                    "source_file": entry["source_file"],
                },
            )
            count += 1

        logger.info(f"[shellcheck] Processed {count} checks")

    def _parse_haskell_file(self, fpath, rel_path):
        """Parse a Haskell source file for ShellCheck check definitions.

        ShellCheck checks are emitted via ``warn``, ``err``, ``errWithFix``,
        ``warnWithFix``, and similar functions.  Each call includes a numeric
        code (e.g. 2048) and a quoted description string.  Calls can span
        multiple lines, so we look at a window of lines after each function
        keyword match.
        """
        checks = {}

        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for i, line in enumerate(lines):
            m = _WARN_FUNC_RE.search(line)
            if not m:
                continue

            func_name = m.group(1)
            # Determine native severity from function name
            if "err" in func_name:
                native_sev = "error"
            elif "warn" in func_name:
                native_sev = "warning"
            else:
                native_sev = "info"

            # Grab a window of lines after the function keyword to handle
            # multi-line calls.  ShellCheck calls are typically on 1-3 lines.
            window = "".join(lines[i:min(i + 6, len(lines))])
            after_func = window[m.end():m.end() + 300]

            # Find the first 3-4 digit number (the SC code)
            num_m = _NUM_RE.search(after_func)
            if not num_m:
                continue

            code_num = int(num_m.group(1))
            # ShellCheck codes range from ~1000 to ~3500
            if not (1000 <= code_num <= 9999):
                continue

            sc_code = f"SC{code_num}"

            # Find the first quoted string after the number (the message)
            after_num = after_func[num_m.end():num_m.end() + 300]
            str_m = _STR_RE.search(after_num)
            if not str_m:
                continue

            message = str_m.group(1)
            # Skip empty or very short messages (likely not check descriptions)
            if len(message) < 5:
                continue

            # Deduplicate by SC code, keeping the longest message
            if sc_code not in checks or len(message) > len(checks[sc_code]["message"]):
                checks[sc_code] = {
                    "code": sc_code,
                    "message": message,
                    "severity": native_sev,
                    "function": func_name,
                    "line": i + 1,
                    "source_file": rel_path,
                }

        return checks