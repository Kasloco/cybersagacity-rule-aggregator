"""Collector for Fortify Software Security Errors from vulncat.fortify.com.

This collector scrapes the public Fortify Taxonomy at
https://vulncat.fortify.com/en — a catalog of software security
errors maintained by the Fortify Software Security Research Group
together with Dr. Gary McGraw.

The taxonomy organizes vulnerability categories ("phyla") into 8
"kingdoms":
  1. Input Validation and Representation
  2. API Abuse
  3. Security Features
  4. Time and State
  5. Errors
  6. Code Quality
  7. Encapsulation
  8. Environment

Each kingdom listing is paginated (20 weaknesses per page).  Each
weakness entry contains a title, an abstract description, and
language tabs indicating which programming languages the rule
applies to.

The collector uses source_type='web' and overrides clone_or_pull()
to be a no-op since there is no Git repository to clone.
"""

import logging
import re
import time
import urllib.parse

from .base import BaseCollector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kingdom → severity mapping (in order of importance per the taxonomy)
# ---------------------------------------------------------------------------
KINGDOM_SEVERITY = {
    "Input Validation and Representation": "high",
    "API Abuse": "medium",
    "Security Features": "high",
    "Time and State": "medium",
    "Errors": "medium",
    "Code Quality": "low",
    "Encapsulation": "medium",
    "Environment": "low",
}

# Kingdom → normalized category
KINGDOM_CATEGORY = {
    "Input Validation and Representation": "input-validation",
    "API Abuse": "api-abuse",
    "Security Features": "security-features",
    "Time and State": "concurrency",
    "Errors": "error-handling",
    "Code Quality": "code-quality",
    "Encapsulation": "encapsulation",
    "Environment": "environment",
}

BASE_URL = "https://vulncat.fortify.com/en"
KINGDOMS = list(KINGDOM_SEVERITY.keys())


class FortifyCollector(BaseCollector):
    name = "fortify"
    display_name = "Fortify SCA (OpenText)"
    source_type = "web"
    source_url = "https://vulncat.fortify.com/en"
    # Web scrape of a paginated, rate-limited site. True catalog ~1,691
    # (polite census 2026-08-31); biggest throttled run observed = 836.
    # Floor must be ABOVE the biggest throttled fragment (836) yet BELOW
    # the deployed baseline (1,017) so the guard can actually fire while
    # the DB holds the restored set: current_active(1017) >= 900, and a
    # throttled 837-836-style run (< 900) gets blocked instead of trusted.
    min_rules_floor = 900
    description = (
        "OpenText Fortify Taxonomy of Software Security Errors — a public "
        "catalog of security vulnerability categories organized into 8 "
        "kingdoms (Input Validation, API Abuse, Security Features, Time & "
        "State, Errors, Code Quality, Encapsulation, Environment). Each "
        "weakness includes an abstract, supported languages, and references "
        "to CWE, OWASP, and other standards. Scraped from "
        "vulncat.fortify.com."
    )
    logo_url = (
        "https://www.microfocus.com/etc/clientlibs/microfocus/clientlibs/"
        "base/img/favicon.ico"
    )

    # ------------------------------------------------------------------
    # Lifecycle overrides
    # ------------------------------------------------------------------
    def clone_or_pull(self):  # type: ignore[override]
        """No-op — there is no Git repository to clone for this web source."""
        logger.info(f"[{self.name}] Web source — no clone/pull needed.")
        return None

    def has_changes(self):
        """Web source — always re-scrape unless caller passes force=False
        and the vendor row has a commit SHA (which it won't for web sources).
        Returning True ensures sync() always proceeds."""
        return True

    def save_commit_sha(self):
        """No commit SHA for web sources; record the sync timestamp instead."""
        import datetime
        try:
            from database import get_db
            with get_db() as conn:
                conn.execute(
                    "UPDATE vendors SET last_commit_sha=? WHERE name=?",
                    (datetime.datetime.utcnow().isoformat(), self.name),
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Main collection logic
    # ------------------------------------------------------------------
    def collect_rules(self):
        """Scrape all weakness entries from vulncat.fortify.com/en.

        Iterates over each kingdom, paginates through all results, and
        registers each weakness as a rule.
        """
        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError:
            logger.error(
                "[fortify] requests and beautifulsoup4 are required. "
                "Install with: pip install requests beautifulsoup4"
            )
            return

        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})

        count = 0
        for kingdom in KINGDOMS:
            try:
                count += self._scrape_kingdom(
                    session, kingdom, BeautifulSoup
                )
            except Exception as e:
                logger.error(
                    f"[fortify] Error scraping kingdom '{kingdom}': {e}",
                    exc_info=True,
                )

        logger.info(f"[fortify] Scraped {count} rules from {BASE_URL}")

    def _scrape_kingdom(self, session, kingdom, BeautifulSoup):
        """Scrape all weakness pages for a single kingdom.

        Returns the number of rules registered.
        """
        count = 0
        page = 1
        max_page = 1  # refined from pagination links on page 1

        # Keep fetching while pages return full content. _get_max_page is a
        # hint, not ground truth: if the site's pagination links under-count
        # (the 2026-08-30 collapse signature — exactly 4 pages x 20 rules
        # scraped before stopping), continue past it until a page returns
        # fewer than a full page of weakness cells, or the hard cap hits.
        while True:
            url = self._kingdom_url(kingdom, page)

            resp = None
            for attempt in range(3):
                try:
                    logger.info(
                        f"[fortify] Fetching kingdom='{kingdom}' page={page}"
                        f"{f'/{max_page}' if max_page > 1 else ''}"
                    )
                    resp = session.get(url, timeout=90)
                    resp.raise_for_status()
                    break
                except Exception as e:
                    # vulncat rate-limits mid-crawl (verified 2026-08-31:
                    # 403s after ~50 rapid requests, cooldown ~90s). Short
                    # backoff is useless against it — wait out the window.
                    cooldown = 60 if "403" in str(e) or "rate" in str(e).lower() else 2 * (attempt + 1)
                    logger.warning(
                        f"[fortify] Fetch {url} failed "
                        f"({attempt + 1}/3): {e}"
                    )
                    time.sleep(cooldown)
            if resp is None:
                logger.warning(
                    f"[fortify] Kingdom '{kingdom}' page {page}: giving up "
                    f"after 3 attempts. Rules scraped so far: {count}."
                )
                break

            soup = BeautifulSoup(resp.text, "html.parser")

            # Determine max_page from pagination on the first page
            if page == 1:
                max_page = max(1, self._get_max_page(soup))
                logger.info(
                    f"[fortify] Kingdom '{kingdom}' reports {max_page} pages"
                )

            # Parse weakness cells on this page
            cells = soup.find_all("div", class_="weaknessCell")
            if not cells:
                logger.info(
                    f"[fortify] No weakness cells on page {page}, stopping."
                )
                break

            for cell in cells:
                rule = self._parse_weakness_cell(cell, kingdom)
                if rule:
                    self._register_rule(rule)
                    count += 1

            # End of kingdom: page returned fewer cells than a full page, or
            # hard cap reached. If the site claims more pages but keeps
            # returning full pages, keep going (under-count protection).
            if len(cells) < 20 or page >= 200:
                break
            page += 1
            # Be polite — vulncat 403-throttles after ~50 rapid requests;
            # 3.5s pacing completed a full 8-kingdom crawl with zero 403s.
            time.sleep(3.5)

        if 0 < count < 20:
            logger.error(
                f"[fortify] Kingdom '{kingdom}' yielded only {count} rules — "
                f"possible pagination or layout break; investigate."
            )

        logger.info(
            f"[fortify] Kingdom '{kingdom}': registered {count} rules"
        )
        return count

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _kingdom_url(kingdom, page=1):
        """Build the URL for a kingdom listing page."""
        encoded = urllib.parse.quote(kingdom)
        if page <= 1:
            return f"{BASE_URL}/weakness?kingdom={encoded}"
        return f"{BASE_URL}/weakness?kingdom={encoded}&po={page}"

    @staticmethod
    def _get_max_page(soup):
        """Extract the maximum page number from pagination links."""
        max_page = 1
        pag = soup.find("ul", class_=re.compile(r"pag", re.I))
        if pag:
            for link in pag.find_all("a", href=True):
                m = re.search(r"po=(\d+)", link.get("href", ""))
                if m:
                    max_page = max(max_page, int(m.group(1)))
        return max_page

    @staticmethod
    def _parse_weakness_cell(cell, kingdom):
        """Parse a single weaknessCell div into a rule dict.

        Returns None if the cell doesn't contain a valid weakness.
        """
        # Title
        title_div = cell.find("div", class_="title")
        if not title_div:
            return None
        title = title_div.get_text(strip=True)
        if not title:
            return None

        # Languages from tab links
        tab_links = cell.find_all("a", attrs={"data-toggle": "tab"})
        languages = [t.get_text(strip=True) for t in tab_links if t.get_text(strip=True)]

        # Abstract from the first (active) tab pane
        abstract = ""
        first_pane = (
            cell.find("div", class_="tab-pane", attrs={"class": re.compile(r"active")})
            or cell.find("div", class_="tab-pane")
        )
        if first_pane:
            sub_title = first_pane.find("div", class_="sub-title")
            if sub_title and "abstract" in sub_title.get_text(strip=True).lower():
                ab_div = sub_title.find_next_sibling("div", class_="t")
                if ab_div:
                    abstract = ab_div.get_text(strip=True)

        # External detail link (gives us category/subcategory)
        detail_link = cell.find("a", class_="external-link")
        detail_url = ""
        category_name = ""
        subcategory_name = ""
        if detail_link:
            detail_url = detail_link.get("href", "")
            # Parse query params: /en/detail?category=X&subcategory=Y#lang
            parsed = urllib.parse.urlparse(detail_url)
            qs = urllib.parse.parse_qs(parsed.query)
            category_name = (qs.get("category", [""])[0])
            subcategory_name = (qs.get("subcategory", [""])[0])

        # data-id on the cell
        data_id = cell.get("data-id", "")

        # Build rule_id — slugified title
        rule_id = f"fortify:{FortifyCollector._slugify(title)}"

        return {
            "rule_id": rule_id,
            "title": title,
            "abstract": abstract,
            "kingdom": kingdom,
            "languages": languages,
            "detail_url": detail_url,
            "category_name": category_name,
            "subcategory_name": subcategory_name,
            "data_id": data_id,
        }

    def _register_rule(self, rule):
        """Upsert a parsed weakness into the database."""
        kingdom = rule["kingdom"]
        severity = KINGDOM_SEVERITY.get(kingdom, "medium")
        category = KINGDOM_CATEGORY.get(kingdom, "security")
        languages = rule["languages"]
        language_str = ", ".join(languages) if languages else ""

        # Build tags
        tags = ["fortify", "sast", category, "vulncat"]
        # Add kingdom slug as tag
        kingdom_slug = kingdom.lower().replace(" ", "-").replace("&", "and")
        tags.append(kingdom_slug)

        # Build description
        desc = rule["abstract"]
        if not desc:
            desc = f"Fortify {kingdom} weakness: {rule['title']}"

        # Build metadata
        metadata = {
            "kingdom": kingdom,
            "category": rule["category_name"],
            "subcategory": rule["subcategory_name"],
            "languages": languages,
            "data_id": rule["data_id"],
            "detail_url": rule["detail_url"],
            "source": "vulncat.fortify.com",
        }

        self.upsert(
            rule_id=rule["rule_id"],
            title=rule["title"][:500],
            description=desc[:5000],
            severity=severity,
            category=category,
            language=language_str,
            cwe_ids=[],
            tags=tags,
            source_file="",
            rule_content="",
            rule_format="html",
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    @staticmethod
    def _slugify(text):
        """Convert a title to a slug suitable for a rule ID."""
        # Lowercase, replace non-alphanumeric with hyphens
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower())
        slug = slug.strip("-")
        return slug