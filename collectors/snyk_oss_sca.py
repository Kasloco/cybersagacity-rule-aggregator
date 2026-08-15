"""Collector for Snyk Open Source (SCA) vulnerability database.

Snyk maintains a public vulnerability database at https://security.snyk.io
with advisories for npm, pip, maven, go, and other ecosystems.

This collector scrapes the Snyk vulnerability DB API:
  https://security.snyk.io/vuln/?type=npm (etc)

Each vulnerability has: Snyk ID, CVE, CVE alias, severity, language,
affected packages, CVSS score, and CWE mapping.
"""

import logging
import re
import json
import time

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

SNYK_VULN_URL = "https://snyk.io/api/v1/vulgates/public_vulnerabilities"
SNYK_DB_URL = "https://security.snyk.io/vuln/"
REQUEST_TIMEOUT = 60
MAX_PAGES = 50
PER_PAGE = 50


class SnykOSSCollector(BaseCollector):
    name = "snyk_oss_sca"
    display_name = "Snyk Open Source (SCA)"
    source_type = "api"
    source_url = "https://security.snyk.io/vuln/"
    description = (
        "Snyk Open Source vulnerability database. Public advisories covering "
        "npm, pip, maven, go, ruby, and other package ecosystems with CVE "
        "mappings, CVSS scores, and severity ratings."
    )
    logo_url = "https://avatars.githubusercontent.com/u/8549"

    def collect_rules(self):
        logger.info(f"[snyk_oss_sca] Fetching vulnerabilities from Snyk public DB...")

        count = 0
        seen_ids = set()

        # Try the Snyk public API — if it's not available, fall back to
        # scraping the web pages
        try:
            headers = {
                "User-Agent": "CyberSagacity-RuleAggregator/1.0",
                "Accept": "application/json",
            }

            for page in range(1, MAX_PAGES + 1):
                params = {
                    "page": page,
                    "per_page": PER_PAGE,
                }
                resp = requests.get(
                    SNYK_VULN_URL,
                    headers=headers,
                    params=params,
                    timeout=REQUEST_TIMEOUT,
                )

                if resp.status_code == 429:
                    logger.warning(f"[snyk_oss_sca] Rate limited, waiting 10s...")
                    time.sleep(10)
                    continue

                if resp.status_code != 200:
                    logger.warning(
                        f"[snyk_oss_sca] API returned {resp.status_code}, "
                        f"falling back to web scrape"
                    )
                    break

                data = resp.json()
                vulns = data if isinstance(data, list) else data.get("results", data.get("vulnerabilities", []))

                if not vulns:
                    break

                for vuln in vulns:
                    snyk_id = vuln.get("id", "")
                    if not snyk_id or snyk_id in seen_ids:
                        continue
                    seen_ids.add(snyk_id)

                    title = vuln.get("title", snyk_id)
                    severity = (vuln.get("severity") or "medium").lower()
                    language = (vuln.get("language") or "").lower()
                    cve = vuln.get("identifiers", {}).get("CVE", [])
                    cwe = vuln.get("identifiers", {}).get("CWE", [])

                    pkg = vuln.get("package", "")
                    desc = vuln.get("description", "")

                    self.upsert(
                        rule_id=f"SNYK-{snyk_id}",
                        title=title[:500],
                        description=desc[:2000],
                        severity=severity,
                        category="dependency-vulnerability",
                        language=language,
                        cwe_ids=cwe if isinstance(cwe, list) else [cwe],
                        owasp_ids=[],
                        tags=["sca", "dependency"] + ([pkg] if pkg else []),
                        source_file=f"{SNYK_DB_URL}{snyk_id}",
                        rule_content="",
                        rule_format="json",
                        metadata={
                            "snyk_id": snyk_id,
                            "cve_ids": cve,
                            "package": pkg,
                        },
                    )
                    count += 1

                if len(vulns) < PER_PAGE:
                    break
                time.sleep(1)  # be nice

        except Exception as e:
            logger.warning(f"[snyk_oss_sca] API approach failed: {e}, trying web scrape...")

        # Fallback: scrape the Snyk DB web pages for vulnerability listings
        if count == 0:
            count = self._scrape_web()

        logger.info(f"[snyk_oss_sca] Collected {count} vulnerabilities.")
        return self.stats

    def _scrape_web(self):
        """Fallback: scrape Snyk's public vulnerability listing pages."""
        count = 0
        seen_ids = set()

        for page in range(1, MAX_PAGES + 1):
            url = f"{SNYK_DB_URL}?page={page}"
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={
                    "User-Agent": "CyberSagacity-RuleAggregator/1.0"
                })
                resp.raise_for_status()
                html = resp.text

                # Parse vulnerability links from the page
                # Snyk pages list vulnerabilities as links like /vuln/SNYK-JS-XXXX
                vuln_links = re.findall(r'href="/vuln/(SNYK[^"]+)"', html)
                if not vuln_links:
                    break

                for vid in vuln_links:
                    if vid in seen_ids:
                        continue
                    seen_ids.add(vid)

                    self.upsert(
                        rule_id=vid,
                        title=vid,
                        description="Snyk Open Source vulnerability. See source URL for details.",
                        severity="medium",
                        category="dependency-vulnerability",
                        language="",
                        cwe_ids=[],
                        owasp_ids=[],
                        tags=["sca", "dependency"],
                        source_file=f"{SNYK_DB_URL}{vid}",
                        rule_content="",
                        rule_format="html",
                        metadata={"snyk_id": vid},
                    )
                    count += 1

                if len(vuln_links) < 20:
                    break
                time.sleep(2)

            except Exception as e:
                logger.warning(f"[snyk_oss_sca] Web scrape page {page} failed: {e}")
                break

        return count