"""Collector for GitLab DAST (Dynamic Application Security Testing) rules.

GitLab DAST is a dynamic application security testing tool that scans
running web applications for vulnerabilities. The DAST analyzer is at
gitlab.com/gitlab-org/security-products/dast and is built on the OWASP ZAP
scanner with GitLab-specific rule profiles and Browserker-based active checks.

Rule sources in the repo:
  - src/config/exclude_rules.yml: ZAP rules that GitLab DAST excludes, each
    with rule_id, name, and a link to zaproxy.org docs.
  - src/config/browserker_active_checks.py: Browserker active check IDs with
    the ZAP plugin IDs they replace.
  - test/end-to-end/expect/*.json: Expected vulnerability reports with full
    metadata (name, severity, CWE, description, identifiers).
"""

import os
import re
import json
import glob
import logging

try:
    import yaml
except ImportError:
    yaml = None

from .base import BaseCollector

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


class GitLabDASTCollector(BaseCollector):
    name = "gitlab_dast"
    display_name = "GitLab DAST"
    source_type = "gitlab"
    source_url = "https://gitlab.com/gitlab-org/security-products/dast.git"
    description = (
        "GitLab DAST (Dynamic Application Security Testing) scans running "
        "web applications for security vulnerabilities including XSS, SQL "
        "injection, CSRF, header misconfigurations, and OWASP Top 10 issues. "
        "Built on the OWASP ZAP scanner with GitLab-specific rule profiles "
        "and Browserker-based browser active checks."
    )
    logo_url = "https://avatars.githubusercontent.com/u/10669714"

    def collect_rules(self):
        """Parse all DAST rule sources in the repo."""
        count = 0

        # 1) Parse exclude_rules.yml for ZAP rule IDs/names that DAST manages
        count += self._parse_exclude_rules()

        # 2) Parse browserker_active_checks.py for browser-based active checks
        count += self._parse_browserker_checks()

        # 3) Parse expected JSON test reports for vulnerability metadata
        count += self._parse_expected_reports()

        logger.info(f"[gitlab_dast] Processed {count} rules")

    # ------------------------------------------------------------------
    # exclude_rules.yml — ZAP rules that GitLab DAST manages
    # ------------------------------------------------------------------

    def _parse_exclude_rules(self):
        """Parse src/config/exclude_rules.yml for ZAP rule IDs that GitLab
        DAST explicitly excludes or manages."""
        fpath = os.path.join(
            self.clone_dir, "src", "config", "exclude_rules.yml"
        )
        if not os.path.isfile(fpath):
            return 0

        if yaml is None:
            return 0
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            return 0

        if not isinstance(data, dict):
            return 0

        rules = data.get("exclude_rules", [])
        if not isinstance(rules, list):
            return 0

        rel_path = os.path.relpath(fpath, self.clone_dir)
        count = 0

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            rule_id_raw = str(rule.get("rule_id", ""))
            name = rule.get("name", "")
            link = rule.get("link", "")

            if not rule_id_raw or not name:
                continue

            rule_id = f"gitlab-dast:zap-{rule_id_raw}"

            self.upsert(
                rule_id=rule_id,
                title=name,
                description=(
                    f"ZAP scanner rule {rule_id_raw} managed by GitLab DAST. "
                    f"This rule is excluded from DAST scans by default. "
                    f"Reference: {link}"
                ),
                severity="medium",
                category="dast",
                language="",
                cwe_ids=[],
                tags=["gitlab", "dast", "zap", "excluded"],
                source_file=rel_path,
                rule_content=(yaml.dump(rule, default_flow_style=False) if yaml else str(rule)),
                rule_format="yaml",
                metadata={
                    "rule_id_raw": rule_id_raw,
                    "zap_rule_id": rule_id_raw,
                    "link": link,
                    "status": "excluded",
                },
            )
            count += 1

        return count

    # ------------------------------------------------------------------
    # browserker_active_checks.py — Browser-based active check definitions
    # ------------------------------------------------------------------

    def _parse_browserker_checks(self):
        """Parse src/config/browserker_active_checks.py for Browserker
        active check IDs and the ZAP plugin IDs they replace."""
        fpath = os.path.join(
            self.clone_dir, "src", "config", "browserker_active_checks.py"
        )
        if not os.path.isfile(fpath):
            return 0

        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return 0

        rel_path = os.path.relpath(fpath, self.clone_dir)
        count = 0

        # Parse BrowserkerActiveCheck entries:
        #   BrowserkerActiveCheck('1336.1', replaced_zap_checks=['90035'], alpha=False)
        #   BrowserkerActiveCheck('94.4', replaced_zap_checks=['90019'], alpha=False, callback_attacks=['94.4.2'])
        pattern = re.compile(
            r"BrowserkerActiveCheck\(\s*"
            r"'([^']+)'\s*,\s*"          # check_id
            r"replaced_zap_checks=\[([^\]]*)\]\s*,\s*"  # replaced checks
            r"alpha=(True|False)"        # alpha flag
            r"(?:,\s*callback_attacks=\[([^\]]*)\])?"  # optional callback attacks
            r"\s*\)"
        )

        for m in pattern.finditer(content):
            check_id = m.group(1)
            replaced_raw = m.group(2).strip()
            alpha = m.group(3) == "True"
            callback_raw = m.group(4) or ""

            # Parse replaced ZAP check IDs
            replaced_ids = re.findall(r"'(\d+)'", replaced_raw)
            callback_attacks = re.findall(r"'([\d.]+)'", callback_raw)

            rule_id = f"gitlab-dast:browserker-{check_id}"

            # Build description
            desc = f"Browserker browser-based active check {check_id}"
            if replaced_ids:
                desc += f". Replaces ZAP plugin IDs: {', '.join(replaced_ids)}"
            if alpha:
                desc += " (alpha)"
            if callback_attacks:
                desc += f". Callback attacks: {', '.join(callback_attacks)}"

            self.upsert(
                rule_id=rule_id,
                title=f"Browserker Check {check_id}",
                description=desc,
                severity="high" if not alpha else "medium",
                category="dast-active",
                language="python",
                cwe_ids=[],
                tags=["gitlab", "dast", "browserker", "active", "alpha" if alpha else "stable"],
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="python",
                metadata={
                    "check_id": check_id,
                    "replaced_zap_checks": replaced_ids,
                    "alpha": alpha,
                    "callback_attacks": callback_attacks,
                },
            )
            count += 1

        return count

    # ------------------------------------------------------------------
    # Expected JSON test reports — vulnerability metadata
    # ------------------------------------------------------------------

    def _parse_expected_reports(self):
        """Parse test/end-to-end/expect/*.json for vulnerability definitions
        with full metadata (name, severity, CWE, description, identifiers)."""
        report_files = glob.glob(
            os.path.join(
                self.clone_dir, "test", "end-to-end", "expect", "*.json"
            )
        )

        # Deduplicate by rule identifier (ZAProxy plugin ID or browserker check ID)
        seen = set()
        count = 0

        for fpath in sorted(report_files):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, Exception):
                continue

            vulns = data.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                continue

            rel_path = os.path.relpath(fpath, self.clone_dir)

            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue

                name = vuln.get("name", "")
                severity = _SEVERITY_MAP.get(
                    (vuln.get("severity") or "medium").lower(), "medium"
                )
                desc = vuln.get("description", "")
                solution = vuln.get("solution", "") or vuln.get("remediation", "")
                references = vuln.get("links", [])

                # Extract identifiers
                identifiers = vuln.get("identifiers", [])
                zap_plugin_id = None
                cwe_id = None
                browserker_id = None

                if isinstance(identifiers, list):
                    for ident in identifiers:
                        if not isinstance(ident, dict):
                            continue
                        ident_type = ident.get("type", "")
                        ident_value = str(ident.get("value", ""))
                        ident_name = ident.get("name", "")

                        if ident_type == "ZAProxy_PluginId":
                            zap_plugin_id = ident_value
                        elif ident_type == "CWE":
                            cwe_id = ident_value
                        elif ident_type == "browserker":
                            browserker_id = ident_value

                # Determine the primary rule ID
                # Prefer ZAP plugin ID, then browserker ID
                primary_id = zap_plugin_id or browserker_id
                if not primary_id or not name:
                    continue

                # Deduplicate
                dedup_key = primary_id
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                rule_id = f"gitlab-dast:{primary_id}"

                cwe_ids = []
                if cwe_id:
                    cwe_nums = re.findall(r"(\d+)", str(cwe_id))
                    cwe_ids = [f"CWE-{n}" for n in cwe_nums]

                # Build reference links
                ref_urls = []
                if isinstance(references, list):
                    for ref in references:
                        if isinstance(ref, dict) and ref.get("url"):
                            ref_urls.append(ref["url"])
                        elif isinstance(ref, str):
                            ref_urls.append(ref)

                full_desc = desc[:2000] if desc else name
                if solution:
                    full_desc += f"\n\nSolution: {solution[:500]}"

                self.upsert(
                    rule_id=rule_id,
                    title=name[:500],
                    description=full_desc,
                    severity=severity,
                    category="dast",
                    language="",
                    cwe_ids=cwe_ids,
                    tags=["gitlab", "dast", "expected-vuln"],
                    source_file=rel_path,
                    rule_content=json.dumps(vuln, indent=2, default=str)[:50000],
                    rule_format="json",
                    metadata={
                        "zap_plugin_id": zap_plugin_id or "",
                        "browserker_id": browserker_id or "",
                        "cwe_id": cwe_id or "",
                        "severity_raw": vuln.get("severity", ""),
                        "references": ref_urls[:10],
                    },
                )
                count += 1

        return count