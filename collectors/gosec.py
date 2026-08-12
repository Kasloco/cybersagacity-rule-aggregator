"""Collector for gosec (Go Security Checker) rules."""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# gosec issue severity → aggregator severity
SEVERITY_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
}

# Taint-based severity strings (used in analyzerslist.go)
TAINT_SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "high",
}


class GoSecCollector(BaseCollector):
    name = "gosec"
    display_name = "gosec"
    source_type = "github"
    source_url = "https://github.com/securego/gosec.git"
    description = (
        "Go security checker. Inspects Go source code for security issues "
        "including injection, file system traversal, weak crypto, hardcoded "
        "credentials, TLS misconfigurations, and more. Rules are mapped to "
        "CWEs."
    )
    logo_url = "https://avatars.githubusercontent.com/u/16501222"

    def collect_rules(self):
        count = 0

        # --- Parse rules/rulelist.go for the classic rule definitions ---
        rules_map = self._parse_rulelist()
        count += self._parse_rule_severities(rules_map)

        # --- Parse analyzers/analyzerslist.go for newer analyzer rules ---
        analyzer_map = self._parse_analyzer_list()
        count += self._upsert_analyzers(analyzer_map)

        # --- Parse issue/issue.go for the CWE mapping ---
        cwe_map = self._parse_cwe_map()
        # Enrich already-upserted rules with CWE data — we re-upsert so the
        # database gets the CWE IDs.  This is fine because upsert is
        # idempotent and will just mark them as updated/unchanged.
        count += self._enrich_with_cwes(rules_map, analyzer_map, cwe_map)

        logger.info(f"[gosec] Processed {count} rules")
        # Return total upserts (including enriched re-upserts)
        return

    def _parse_rulelist(self):
        """Parse rules/rulelist.go for the canonical rule ID → description map."""
        rules = {}
        fpath = os.path.join(self.clone_dir, "rules", "rulelist.go")
        if not os.path.isfile(fpath):
            logger.warning(f"[gosec] rulelist.go not found")
            return rules

        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        # Pattern: {"G1xx", "Description", NewFunctionName},
        for m in re.finditer(
            r'\{"(G\d+)",\s*"([^"]+)",\s*(\w+)\}', content
        ):
            rule_id = m.group(1)
            description = m.group(2)
            constructor = m.group(3)
            rules[rule_id] = {
                "id": rule_id,
                "description": description,
                "constructor": constructor,
                "severity": "medium",  # default, refined later
                "source_file": "rules/rulelist.go",
            }

        return rules

    def _parse_rule_severities(self, rules_map):
        """Walk each rule .go file to find severity and description for each rule.

        gosec rules embed ``issue.MetaData`` and set severity via
        ``issue.NewMetaData(id, what, severity, confidence)`` or
        ``newCallListRule(id, what, severity, confidence)``.  Some rules use
        ``c.NewIssue(...)`` with inline severity.
        """
        count = 0
        rules_dir = os.path.join(self.clone_dir, "rules")
        if not os.path.isdir(rules_dir):
            return count

        # Build a reverse map: constructor function name → rule_id
        constructor_to_id = {}
        for rid, info in rules_map.items():
            constructor_to_id[info["constructor"]] = rid

        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith(".go") or fname.endswith("_test.go"):
                continue
            if fname in ("rulelist.go", "base.go", "errors.go"):
                continue

            fpath = os.path.join(rules_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()

            # Find constructor functions: func NewXxx(id string, ...
            for m in re.finditer(
                r'func\s+(New\w+)\s*\(', content
            ):
                func_name = m.group(1)
                rule_id = constructor_to_id.get(func_name)
                if not rule_id:
                    continue

                # Search the function body (next ~3000 chars) for severity
                body = content[m.end():m.end() + 3000]

                # Try NewMetaData(id, "what", severity, confidence)
                meta_m = re.search(
                    r'NewMetaData\([^,]+,\s*"([^"]+)",\s*'
                    r'issue\.(Low|Medium|High)',
                    body,
                )
                if meta_m:
                    what = meta_m.group(1)
                    sev = meta_m.group(2).lower()
                    rules_map[rule_id]["description"] = what
                    rules_map[rule_id]["severity"] = sev
                    continue

                # Try newCallListRule(id, "what", severity, confidence)
                call_m = re.search(
                    r'newCallListRule\([^,]+,\s*"([^"]+)",\s*'
                    r'issue\.(Low|Medium|High)',
                    body,
                )
                if call_m:
                    what = call_m.group(1)
                    sev = call_m.group(2).lower()
                    rules_map[rule_id]["description"] = what
                    rules_map[rule_id]["severity"] = sev
                    continue

                # Try c.NewIssue with inline severity
                issue_m = re.search(
                    r'NewIssue\([^)]+,\s*"([^"]+)",\s*'
                    r'issue\.(Low|Medium|High)',
                    body,
                )
                if issue_m:
                    what = issue_m.group(1)
                    sev = issue_m.group(2).lower()
                    if not rules_map[rule_id].get("_desc_set"):
                        rules_map[rule_id]["description"] = what
                    rules_map[rule_id]["severity"] = sev
                    continue

        # Now upsert all rules
        for rule_id, info in rules_map.items():
            self.upsert(
                rule_id=rule_id,
                title=f"gosec {rule_id}: {info['description']}"[:500],
                description=info["description"],
                severity=SEVERITY_MAP.get(info["severity"], "medium"),
                category=self._rule_category(rule_id),
                language="go",
                cwe_ids=[],  # enriched later
                tags=["gosec", "go", "sast", self._rule_category(rule_id)],
                source_file=info["source_file"],
                rule_content="",
                rule_format="go",
                metadata={
                    "constructor": info["constructor"],
                    "rule_id": rule_id,
                    "severity_native": info["severity"],
                },
            )
            count += 1

        return count

    def _parse_analyzer_list(self):
        """Parse analyzers/analyzerslist.go for newer analyzer-based rules."""
        analyzers = {}
        fpath = os.path.join(self.clone_dir, "analyzers", "analyzerslist.go")
        if not os.path.isfile(fpath):
            return analyzers

        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse the defaultAnalyzers list:
        # {"G1xx", "Description", newFunctionName},
        for m in re.finditer(
            r'\{"(G\d+)",\s*"([^"]+)",\s*(\w+)\}', content
        ):
            aid = m.group(1)
            desc = m.group(2)
            func = m.group(3)
            analyzers[aid] = {
                "id": aid,
                "description": desc,
                "constructor": func,
                "severity": "medium",
                "source_file": "analyzers/analyzerslist.go",
            }

        # Parse taint rules (G701-G710, G120) with inline severity and CWE
        # Pattern: ID: "G7xx", Description: "...", Severity: "HIGH", CWE: "CWE-89"
        taint_pattern = re.compile(
            r'ID:\s*"(G\d+)".*?'
            r'Description:\s*"([^"]+)".*?'
            r'Severity:\s*"([^"]+)".*?'
            r'CWE:\s*"(CWE-\d+)"',
            re.DOTALL,
        )
        for m in taint_pattern.finditer(content):
            tid = m.group(1)
            desc = m.group(2)
            sev = m.group(3)
            cwe = m.group(4)
            if tid in analyzers:
                analyzers[tid]["description"] = desc
                analyzers[tid]["severity"] = TAINT_SEVERITY_MAP.get(sev, "medium")
                analyzers[tid]["cwe"] = cwe
            else:
                analyzers[tid] = {
                    "id": tid,
                    "description": desc,
                    "constructor": "",
                    "severity": TAINT_SEVERITY_MAP.get(sev, "medium"),
                    "cwe": cwe,
                    "source_file": "analyzers/analyzerslist.go",
                }

        return analyzers

    def _upsert_analyzers(self, analyzer_map):
        """Upsert analyzer-based rules."""
        count = 0
        for aid, info in analyzer_map.items():
            cwe_ids = []
            if "cwe" in info:
                cwe_ids = [info["cwe"]]

            self.upsert(
                rule_id=aid,
                title=f"gosec {aid}: {info['description']}"[:500],
                description=info["description"],
                severity=SEVERITY_MAP.get(info["severity"], "medium"),
                category=self._rule_category(aid),
                language="go",
                cwe_ids=cwe_ids,
                tags=["gosec", "go", "sast", self._rule_category(aid), "analyzer"],
                source_file=info["source_file"],
                rule_content="",
                rule_format="go",
                metadata={
                    "constructor": info["constructor"],
                    "rule_id": aid,
                    "severity_native": info["severity"],
                    "source": "analyzer",
                },
            )
            count += 1
        return count

    def _parse_cwe_map(self):
        """Parse issue/issue.go for the ruleToCWE mapping."""
        cwe_map = {}
        fpath = os.path.join(self.clone_dir, "issue", "issue.go")
        if not os.path.isfile(fpath):
            return cwe_map

        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        for m in re.finditer(r'"(G\d+)"\s*:\s*"(\d+)"', content):
            cwe_map[m.group(1)] = f"CWE-{m.group(2)}"

        return cwe_map

    def _enrich_with_cwes(self, rules_map, analyzer_map, cwe_map):
        """Re-upsert rules with their CWE IDs from the issue.go mapping."""
        count = 0
        for rule_id, cwe in cwe_map.items():
            # Determine which map has the rule info
            info = rules_map.get(rule_id) or analyzer_map.get(rule_id)
            if not info:
                # Rule is in the CWE map but not in either parsed list —
                # create a minimal entry
                self.upsert(
                    rule_id=rule_id,
                    title=f"gosec {rule_id}"[:500],
                    description=f"gosec rule {rule_id}",
                    severity="medium",
                    category=self._rule_category(rule_id),
                    language="go",
                    cwe_ids=[cwe],
                    tags=["gosec", "go", "sast", self._rule_category(rule_id)],
                    source_file="issue/issue.go",
                    rule_content="",
                    rule_format="go",
                    metadata={
                        "rule_id": rule_id,
                        "cwe_source": "issue/issue.go",
                    },
                )
                count += 1
                continue

            # Only re-upsert if we have a CWE that wasn't already set
            existing_cwes = [info.get("cwe")] if info.get("cwe") else []
            if cwe not in existing_cwes:
                existing_cwes.append(cwe)

            self.upsert(
                rule_id=rule_id,
                title=f"gosec {rule_id}: {info['description']}"[:500],
                description=info["description"],
                severity=SEVERITY_MAP.get(info.get("severity", "medium"), "medium"),
                category=self._rule_category(rule_id),
                language="go",
                cwe_ids=existing_cwes,
                tags=["gosec", "go", "sast", self._rule_category(rule_id)],
                source_file=info.get("source_file", ""),
                rule_content="",
                rule_format="go",
                metadata={
                    "constructor": info.get("constructor", ""),
                    "rule_id": rule_id,
                    "severity_native": info.get("severity", "medium"),
                    "cwe_source": "issue/issue.go",
                },
            )
            count += 1

        return count

    @staticmethod
    def _rule_category(rule_id):
        """Map a gosec rule ID prefix to a category string."""
        num = int(rule_id[1:]) if rule_id[1:].isdigit() else 0
        if 100 <= num <= 199:
            return "misc"
        elif 200 <= num <= 299:
            return "injection"
        elif 300 <= num <= 399:
            return "filesystem"
        elif 400 <= num <= 499:
            return "crypto"
        elif 500 <= num <= 599:
            return "blocklist"
        elif 600 <= num <= 699:
            return "memory-safety"
        elif 700 <= num <= 799:
            return "taint"
        return "general"