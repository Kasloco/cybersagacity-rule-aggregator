"""Collector for Clang Static Analyzer checkers.

Scrapes the official available-checkers documentation:
  https://clang.llvm.org/docs/analyzer/checkers.html

Each checker is a <section> with:
  - id anchor (e.g. "core-nulldereference")
  - <h4> title containing the checker name, e.g. "core.NullDereference (C, C++, ObjC)"
  - <p> description
  - optional code example

Grouped into families (core, cplusplus, security, unix, osx, etc.).
Some checkers carry a "Checker Name:" label; we derive the canonical name
from the h4 title (the dotted prefix before the parenthetical).

Severity is not published per-checker; we map by family/category heuristics:
  - security.* → high
  - core.* memory-safety (NullDereference, UseAfterFree, etc.) → high/medium
  - everything else → medium
"""

import logging
import re
import html as html_mod

import requests

from .base import BaseCollector

logger = logging.getLogger(__name__)

CHECKERS_URL = "https://clang.llvm.org/docs/analyzer/checkers.html"
REQUEST_TIMEOUT = 60

# Map checker family → normalized category
FAMILY_CATEGORY = {
    "security": "security",
    "core": "memory-safety",
    "cplusplus": "memory-safety",
    "unix": "api",
    "osx": "api",
    "optin": "security",
    "nullability": "correctness",
    "webkit": "security",
    "llvm": "correctness",
    "debug": "correctness",
    "apiModeling": "api",
}

# Checkers we treat as higher severity (memory safety / injection)
HIGH_SEVERITY_HINTS = [
    "nulldereference", "useafterfree", "use-after-free", "doublefree",
    "double-free", "stackaddress", "uninitialized", "bufferoverflow",
    "integeroverflow", "divisionbyzero", "mismatcheddeallocator",
    "insecureapi", "strcpy", "gets", "memcpy", "leak",
]

CHECKER_RE = re.compile(
    r'<section id="[a-z0-9_.-]+">.*?<h4>.*?</h4>\s*<p>(.*?)</p>',
    re.DOTALL,
)


def _strip_tags(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_mod.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


class ClangCollector(BaseCollector):
    name = "clang"
    display_name = "Clang Static Analyzer"
    source_type = "web_scrape"
    source_url = CHECKERS_URL
    description = (
        "Clang Static Analyzer — the LLVM project's source code analysis tool. "
        "Checkers are grouped into families (core, cplusplus, unix, security, "
        "osx, optin, nullability, webkit) covering memory safety, API misuse, "
        "and security-sensitive code patterns for C, C++, and Objective-C."
    )
    logo_url = "https://avatars.githubusercontent.com/u/1507452"

    def collect_rules(self):
        logger.info(f"[clang] Fetching checkers from {CHECKERS_URL}...")
        resp = requests.get(CHECKERS_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        html = resp.text

        # Split into sections per checker anchor.
        # Each checker begins with <span id="<family>-<name>"></span> inside
        # a <section id="...">. We iterate over <section> blocks.
        sections = re.split(r'(?=<section id=")', html)
        count = 0

        for sec in sections:
            m = re.search(r'<section id="([a-z0-9_.-]+)"', sec)
            if not m:
                continue
            anchor = m.group(1)

            # Skip family-level section headers (no checker name in h4)
            hm = re.search(r"<h4>(.*?)</h4>", sec, re.DOTALL)
            if not hm:
                continue
            h4_raw = hm.group(1)

            # The checker name lives inside the <a class="toc-backref"> link:
            #   <a class="toc-backref" href="#id42"><span class="section-number">1.1.1.5. </span>core.NullDereference (C, C++, ObjC)</a>
            link_m = re.search(r'<a class="toc-backref"[^>]*>(.*?)</a>', h4_raw, re.DOTALL)
            if not link_m:
                continue
            link_text = _strip_tags(link_m.group(1))
            # Strip any leading section-number (e.g. "1.1.1.5.")
            link_text = re.sub(r"^\s*[0-9]+(?:\.[0-9]+)*\.\s*", "", link_text)

            # link_text like "core.NullDereference (C, C++, ObjC)" or "alpha.core.CastSize (C)"
            name_match = re.match(r"([\w.]+)\s*(?:\((.*?)\))?", link_text)
            if not name_match:
                continue
            checker_name = name_match.group(1)
            languages = name_match.group(2) or ""

            # Skip pure section index entries
            if checker_name in (
                "Default Checkers", "Experimental Checkers", "Available Checkers",
            ) or "." not in checker_name:
                continue

            # Extract the description paragraph (first <p> after the h4)
            body = sec[hm.end():]
            pm = re.search(r"<p>(.*?)</p>", body, re.DOTALL)
            description = _strip_tags(pm.group(1)) if pm else ""

            # Family = dotted prefix (alpha.core.X → core, security.X → security)
            parts = checker_name.split(".")
            if len(parts) >= 2 and parts[0] == "alpha":
                family = parts[1] if len(parts) >= 2 else "alpha"
                short_id = ".".join(parts[2:])
            else:
                family = parts[0]
                short_id = ".".join(parts[1:])

            category = FAMILY_CATEGORY.get(family, "correctness")

            # Severity heuristic
            low_name = checker_name.lower()
            if family == "security" or any(h in low_name for h in HIGH_SEVERITY_HINTS):
                severity = "high"
            elif family in ("core", "cplusplus", "optin"):
                severity = "medium"
            else:
                severity = "medium"

            rule_id = checker_name
            title = f"{checker_name} — {_strip_tags(langs_title(short_id))}" \
                if short_id else checker_name

            tags = [family, category]
            if languages:
                lang_list = [l.strip() for l in languages.split(",")]
                tags.extend(lang_list)

            self.upsert(
                rule_id=rule_id,
                title=checker_name,
                description=description[:2000] if description else "",
                severity=severity,
                category=category,
                language="c,c++,objc",
                cwe_ids=[],
                owasp_ids=[],
                tags=tags,
                source_file=CHECKERS_URL + "#" + anchor,
                rule_content="",
                rule_format="html",
                metadata={
                    "family": family,
                    "checker_name": checker_name,
                    "languages": languages,
                    "url": CHECKERS_URL + "#" + anchor,
                    "source": "clang.llvm.org",
                },
            )
            count += 1

        logger.info(f"[clang] Collected {count} checkers.")
        return self.stats


def langs_title(short_id):
    """Humanize a dotted short id for a readable title suffix."""
    return short_id.replace(".", " ").replace("_", " ").title()
