"""Collector for CppCheck static C/C++ analyzer rules."""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# CppCheck severity -> aggregator severity mapping
SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "performance": "medium",
    "portability": "low",
    "style": "low",
    "information": "low",
    "debug": "low",
    "internal": "low",
}

# Files in lib/ that contain reportError/reportInfo calls
CHECK_FILES = [
    "check64bit.cpp", "checkassert.cpp", "checkautovariables.cpp",
    "checkbool.cpp", "checkbufferoverrun.cpp", "checkclass.cpp",
    "checkcondition.cpp", "checkexceptionsafety.cpp", "checkfunctions.cpp",
    "checkimpl.cpp", "checkinternal.cpp", "checkio.cpp",
    "checkleakautovar.cpp", "checkmemoryleak.cpp", "checknullpointer.cpp",
    "checkother.cpp", "checkpostfixoperator.cpp", "checksizeof.cpp",
    "checkstl.cpp", "checkstring.cpp", "checktype.cpp",
    "checkuninitvar.cpp", "checkunusedvar.cpp", "checkvaarg.cpp",
    "forwardanalyzer.cpp", "tokenize.cpp",
]

SEVERITY_ORDER = [
    "error", "warning", "performance", "portability",
    "style", "information", "debug", "internal",
]


class CppCheckCollector(BaseCollector):
    name = "cppcheck"
    display_name = "CppCheck"
    source_type = "github"
    source_url = "https://github.com/danmar/cppcheck.git"
    description = (
        "Static analysis tool for C/C++ code. Detects bugs, "
        "undefined behavior, performance issues, portability problems, "
        "and style violations with CWE mappings."
    )
    logo_url = "https://avatars.githubusercontent.com/u/65019456"

    def collect_rules(self):
        count = 0

        # --- Parse C++ source files for reportError/reportInfo calls ---
        lib_dir = os.path.join(self.clone_dir, "lib")
        if os.path.isdir(lib_dir):
            count += self._parse_cpp_files(lib_dir)

        # --- Parse XML rule files in rules/ directory ---
        rules_dir = os.path.join(self.clone_dir, "rules")
        if os.path.isdir(rules_dir):
            count += self._parse_xml_rules(rules_dir)

        logger.info(f"[cppcheck] Processed {count} checks")

    # ------------------------------------------------------------------
    # C++ source parsing
    # ------------------------------------------------------------------

    def _parse_cpp_files(self, lib_dir):
        """Parse all check*.cpp files for reportError/reportInfo calls."""
        all_cwe_defs = {}
        all_calls = []

        for fname in CHECK_FILES:
            fpath = os.path.join(lib_dir, fname)
            if not os.path.isfile(fpath):
                continue
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Extract CWE definitions: static const CWE NAME(NUMU);
            for name, num in re.findall(r"static const CWE (\w+)\((\d+)U\)", content):
                all_cwe_defs[name] = int(num)

            # Extract reportError/reportInfo calls using balanced-paren tracking
            lines = content.split("\n")
            i = 0
            while i < len(lines):
                line = lines[i]
                m = re.search(r"\breport(Error|Info)\s*\(", line)
                if m:
                    call_type = "reportError" if m.group(1) == "Error" else "reportInfo"
                    abs_pos = sum(len(lines[k]) + 1 for k in range(i)) + m.start()
                    match_len = m.end() - m.start()
                    pos = abs_pos + match_len
                    depth = 1
                    in_string = False
                    escape = False
                    while pos < len(content) and depth > 0:
                        ch = content[pos]
                        if escape:
                            escape = False
                            pos += 1
                            continue
                        if ch == "\\":
                            escape = True
                            pos += 1
                            continue
                        if ch == '"':
                            in_string = not in_string
                            pos += 1
                            continue
                        if not in_string:
                            if ch == "(":
                                depth += 1
                            elif ch == ")":
                                depth -= 1
                                if depth == 0:
                                    break
                        pos += 1
                    block_start = abs_pos + match_len
                    block_text = content[block_start:pos]
                    all_calls.append((fname, i + 1, call_type, block_text, lines, i))
                    end_line = content[:pos].count("\n")
                    i = end_line + 1
                else:
                    i += 1

        # Parse each call
        parsed = []
        for fname, lineno, ctype, block, lines, line_idx in all_calls:
            entry = self._parse_call(
                block, lines, line_idx, all_cwe_defs, fname, lineno, ctype
            )
            if entry:
                parsed.append(entry)

        # Deduplicate by error ID, keeping the entry with the longest message
        by_id = {}
        for p in parsed:
            eid = p["id"]
            if eid not in by_id:
                by_id[eid] = p
            else:
                if len(p["message"]) > len(by_id[eid]["message"]):
                    by_id[eid] = p
                # Pick higher-priority severity
                if SEVERITY_ORDER.index(p["severity"]) < SEVERITY_ORDER.index(by_id[eid]["severity"]):
                    by_id[eid]["severity"] = p["severity"]
                # Pick first non-None CWE
                if not by_id[eid]["cwe"] and p["cwe"]:
                    by_id[eid]["cwe"] = p["cwe"]

        count = 0
        for entry in by_id.values():
            severity_native = entry["severity"]
            severity_mapped = SEVERITY_MAP.get(severity_native, "low")
            cwe_ids = [entry["cwe"]] if entry["cwe"] else []
            rel_path = os.path.join("lib", entry["file"])

            self.upsert(
                rule_id=entry["id"],
                title=entry["message"][:500] if entry["message"] else entry["id"],
                description=entry["message"][:2000],
                severity=severity_mapped,
                category=severity_native,
                language="c",
                cwe_ids=cwe_ids,
                tags=["cppcheck", "c", "cpp", "sast", severity_native],
                source_file=rel_path,
                rule_content=entry["block"][:50000],
                rule_format="text",
                metadata={
                    "severity": severity_native,
                    "error_id": entry["id"],
                    "call_type": entry["type"],
                    "source_file": rel_path,
                    "source_line": entry["line"],
                    "cwe_name": entry.get("cwe_name"),
                },
            )
            count += 1

        return count

    def _parse_call(self, block, lines, line_idx, all_cwe_defs, fname, lineno, ctype):
        """Extract severity, errorId, message, and CWE from a reportError block."""
        # Severity
        sev_match = re.search(r"Severity::(\w+)", block)
        severity = sev_match.group(1) if sev_match else "unknown"

        # Error ID — first quoted string after severity
        id_match = re.search(r'Severity::\w+\s*,\s*"([^"]+)"', block)
        if not id_match:
            id_match = re.search(r',\s*"([^"]+)"\.c_str\(\)', block)
        error_id = id_match.group(1) if id_match else None
        if not error_id:
            return None

        # CWE — numbered (CWE123) or named (CWE_BUFFER_OVERRUN)
        cwe_id = None
        cwe_name = None
        cwe_match = re.search(r"\bCWE(\d+)\b", block)
        if cwe_match:
            cwe_id = int(cwe_match.group(1))
        else:
            cwe_name_match = re.search(r"\b(CWE_[A-Z_]+)\b", block)
            if cwe_name_match:
                cwe_name = cwe_name_match.group(1)
                if cwe_name in all_cwe_defs:
                    cwe_id = all_cwe_defs[cwe_name]
                else:
                    # Try to extract number from name (e.g., CWE_BUFFER_OVERRUN won't have it,
                    # but CWE398 would be caught by the first regex)
                    num_m = re.search(r"CWE_(\d+)", cwe_name)
                    if num_m:
                        cwe_id = int(num_m.group(1))

        # Message extraction
        message = self._extract_message(block, id_match, lines, line_idx)

        return {
            "id": error_id,
            "severity": severity,
            "cwe": cwe_id,
            "cwe_name": cwe_name,
            "message": message,
            "file": fname,
            "line": lineno,
            "type": ctype,
            "block": block,
        }

    def _extract_message(self, block, id_match, lines, line_idx):
        """Extract the human-readable message from a reportError block."""
        after_id = block[id_match.end():]
        # Split at CWE or Certainty to isolate the message argument
        msg_part = re.split(r",\s*CWE|,\s*Certainty", after_id)[0]

        # Direct string literals in the message expression
        string_literals = re.findall(r'"((?:[^"\\]|\\.)*)"', msg_part)

        if string_literals:
            message = " ".join(string_literals)
        else:
            # Message is a variable (e.g., msg, message, errmsg)
            # Search backwards for the variable's string content
            cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', "", msg_part)
            cleaned = re.sub(r"\w+\([^)]*\)", "", cleaned)
            vars_found = re.findall(r"\b(\w+)\b", cleaned)
            keywords = {
                "std", "string", "move", "c_str", "errorPath",
                "tok", "tokens", "stdmove",
            }
            vars_found = [v for v in vars_found if v not in keywords and len(v) > 1]

            var_messages = []
            for varname in vars_found:
                var_msgs = self._resolve_variable(varname, lines, line_idx)
                var_messages.extend(var_msgs)

            if var_messages:
                message = " ".join(var_messages)
            else:
                message = ""

        # Clean up
        message = message.replace("\\n", " ").strip()
        message = re.sub(r"\$symbol:[\w]*", "", message)
        message = re.sub(r"\$symbol", "", message)
        message = re.sub(r"\s+", " ", message).strip()
        return message

    @staticmethod
    def _resolve_variable(varname, lines, line_idx):
        """Search backwards from line_idx for string literals assigned to varname."""
        messages = []
        for j in range(line_idx - 1, max(0, line_idx - 80), -1):
            sline = lines[j]

            # Assignment patterns
            assign_patterns = [
                rf"(?:const\s+)?std::string\s+{re.escape(varname)}\s*=",
                rf"(?:const\s+)?std::string\s+{re.escape(varname)}\s*\{{",
                rf"(?:const\s+)?std::string\s+{re.escape(varname)}\s*\(",
            ]
            for ap in assign_patterns:
                if re.search(ap, sline):
                    # Grab ALL string literals from this assignment line
                    all_strings = re.findall(r'"((?:[^"\\]|\\.)*)"', sline)
                    messages = all_strings + messages
                    # Check for += appends between assignment and reportError
                    for k in range(j + 1, line_idx):
                        am = re.search(
                            rf'{re.escape(varname)}\s*\+=\s*"((?:[^"\\]|\\.)*)"',
                            lines[k],
                        )
                        if am:
                            messages.append(am.group(1))
                    return messages

            # Append pattern: varname += "..."
            am = re.search(
                rf'{re.escape(varname)}\s*\+=\s*"((?:[^"\\]|\\.)*)"', sline
            )
            if am:
                messages.insert(0, am.group(1))
                continue

            # Concatenation: varname = varname + "..."
            cm = re.search(
                rf'{re.escape(varname)}\s*=\s*{re.escape(varname)}\s*\+\s*"((?:[^"\\]|\\.)*)"',
                sline,
            )
            if cm:
                messages.insert(0, cm.group(1))
                continue

        return messages

    # ------------------------------------------------------------------
    # XML rule parsing (rules/ directory)
    # ------------------------------------------------------------------

    def _parse_xml_rules(self, rules_dir):
        """Parse XML rule files in the rules/ directory."""
        import xml.etree.ElementTree as ET

        count = 0
        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith(".xml"):
                continue
            fpath = os.path.join(rules_dir, fname)
            rel_path = os.path.join("rules", fname)
            try:
                tree = ET.parse(fpath)
                root = tree.getroot()
            except Exception:
                continue

            msg_el = root.find(".//message")
            if msg_el is None:
                continue

            id_el = msg_el.find("id")
            sev_el = msg_el.find("severity")
            summary_el = msg_el.find("summary")

            rule_id = id_el.text.strip() if id_el is not None and id_el.text else None
            if not rule_id:
                continue

            native_sev = sev_el.text.strip() if sev_el is not None and sev_el.text else "style"
            severity = SEVERITY_MAP.get(native_sev, "low")
            summary = summary_el.text.strip() if summary_el is not None and summary_el.text else ""

            self.upsert(
                rule_id=f"xml:{rule_id}",
                title=summary[:500],
                description=summary[:2000],
                severity=severity,
                category=native_sev,
                language="c",
                cwe_ids=[],
                tags=["cppcheck", "c", "cpp", "sast", native_sev, "xml-rule"],
                source_file=rel_path,
                rule_content=ET.tostring(root, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={
                    "severity": native_sev,
                    "error_id": rule_id,
                    "source_file": rel_path,
                    "rule_type": "xml",
                },
            )
            count += 1

        return count