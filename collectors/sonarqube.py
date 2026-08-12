"""Collector for SonarQube rules from SonarSource GitHub repos and RSPEC forks.

Since rules.sonarsource.com is offline, this collector pulls rule metadata
directly from:
  1. SonarSource/sonar-dotnet (C#, VB.NET) — JSON metadata per rule
  2. SonarSource/sonar-python — JSON metadata per rule
  3. dancer1325/sonar-rspec fork — 3,800+ rules across all languages

Each rule's JSON contains: title, type, severity, tags, CWE, OWASP mappings.

Output format matches Chris Near's specification:
  - ID: Capital S + number (e.g., S2077)
  - Severity: B=Blocker, C=Critical, M=Major, Mn=Minor
  - Classification: V=Vulnerability, B=Bug, CS=Code Smell, S=Security Hotspot
  - CWE: comma-separated CWE numbers from securityStandards
"""

import json
import logging
import os
import time

import git
import requests

from .base import BaseCollector, CLONE_BASE

logger = logging.getLogger(__name__)

# Maps SonarQube severity to our normalized severity AND Chris's abbreviation
SEVERITY_MAP = {
    "Blocker": ("critical", "B"),
    "Critical": ("high", "C"),
    "Major": ("medium", "M"),
    "Minor": ("low", "Mn"),
    "Info": ("info", "I"),
}

# Maps SonarQube type to our category AND Chris's classification abbreviation
TYPE_MAP = {
    "VULNERABILITY": ("vulnerability", "V"),
    "BUG": ("bug", "B"),
    "CODE_SMELL": ("code_smell", "CS"),
    "SECURITY_HOTSPOT": ("security_hotspot", "S"),
}

# Languages to collect and their repo/path configurations
LANGUAGE_SOURCES = {
    "csharp": {
        "repo": "https://github.com/SonarSource/sonar-dotnet.git",
        "rspec_path": "analyzers/rspec/cs",
        "display": "C#",
    },
    "vbnet": {
        "repo": "https://github.com/SonarSource/sonar-dotnet.git",
        "rspec_path": "analyzers/rspec/vbnet",
        "display": "VB.NET",
    },
    "vb6": {
        # VB6 rules are in the RSPEC fork under the vb6 language directory.
        # The sonar-vb6 repository (SonarSource/sonar-vb6) is private/archived,
        # but the RSPEC fork (dancer1325/sonar-rspec) has vb6 rule metadata.
        # We also try the sonar-dotnet repo's rspec/vb6 path as a fallback.
        "repo": "https://github.com/dancer1325/sonar-rspec.git",
        "rspec_path": "rules/vb6",
        "display": "VB6",
        # VB6 rules in the RSPEC fork are structured as S####/metadata.json
        "is_rspec_fork_language": True,
    },
    "python": {
        "repo": "https://github.com/SonarSource/sonar-python.git",
        "rspec_path": "python-checks/src/main/resources/org/sonar/l10n/py/rules/python",
        "display": "Python",
    },
    "java": {
        "repo": "https://github.com/SonarSource/sonar-java.git",
        "rspec_path": "java-checks/src/main/resources/org/sonar/l10n/java/rules/java",
        "display": "Java",
    },
    "javascript": {
        "repo": "https://github.com/SonarSource/SonarJS.git",
        "rspec_path": "sonar-plugin/javascript-checks/src/main/resources/org/sonar/l10n/javascript/rules/javascript",
        "display": "JavaScript",
    },
    "typescript": {
        "repo": "https://github.com/SonarSource/SonarJS.git",
        "rspec_path": "sonar-plugin/javascript-checks/src/main/resources/org/sonar/l10n/javascript/rules/javascript",
        "display": "TypeScript",
    },
    "go": {
        "repo": "https://github.com/SonarSource/sonar-go.git",
        "rspec_path": "sonar-go-checks/src/main/resources/org/sonar/l10n/go/rules/go",
        "display": "Go",
    },
    "php": {
        "repo": "https://github.com/SonarSource/sonar-php.git",
        "rspec_path": "php-checks/src/main/resources/org/sonar/l10n/php/rules/php",
        "display": "PHP",
    },
    "kotlin": {
        "repo": "https://github.com/SonarSource/sonar-kotlin.git",
        "rspec_path": "sonar-kotlin-checks/src/main/resources/org/sonar/l10n/kotlin/rules/kotlin",
        "display": "Kotlin",
    },
}

# Comprehensive RSPEC fork for languages not in individual repos
RSPEC_FORK = "https://github.com/dancer1325/sonar-rspec.git"


class SonarQubeCollector(BaseCollector):
    name = "sonarqube"
    display_name = "SonarQube (SonarSource)"
    source_type = "github"
    source_url = "https://github.com/SonarSource"
    description = (
        "SonarSource's comprehensive rule catalog covering 30+ languages. "
        "Detects bugs, vulnerabilities, code smells, and security hotspots "
        "with CWE, OWASP, and PCI DSS mappings."
    )
    logo_url = "https://avatars.githubusercontent.com/u/37981986"

    def sync(self, force=False):
        """Override sync — pull from multiple GitHub repos."""
        self.register_vendor()
        from database import start_sync, complete_sync, update_vendor_stats
        self.sync_id = start_sync(self.vendor["id"])
        logger.info(f"[{self.name}] Starting SonarQube multi-repo sync...")

        try:
            self.collect_rules()
            update_vendor_stats(self.vendor["id"])
            complete_sync(
                self.sync_id, "success",
                self.stats["added"], self.stats["updated"], self.stats["removed"],
            )
            logger.info(
                f"[{self.name}] Sync complete: "
                f"+{self.stats['added']} ~{self.stats['updated']} "
                f"-{self.stats['removed']} ={self.stats['unchanged']}"
            )
        except Exception as e:
            logger.error(f"[{self.name}] Sync failed: {e}", exc_info=True)
            complete_sync(self.sync_id, "failed", error_message=str(e))
            raise

        return self.stats

    def collect_rules(self):
        total = 0

        # Phase 1: Try the RSPEC fork first (most comprehensive)
        rspec_count = self._collect_from_rspec_fork()
        total += rspec_count

        # Phase 2: Supplement with individual analyzer repos for latest rules
        for lang, config in LANGUAGE_SOURCES.items():
            try:
                count = self._collect_from_analyzer_repo(lang, config)
                total += count
                logger.info(f"[sonarqube] {config['display']}: {count} rules from analyzer repo")
            except Exception as e:
                logger.warning(f"[sonarqube] Failed to fetch {lang} from analyzer repo: {e}")

        logger.info(f"[sonarqube] Total: processed {total} rule entries")

    def _clone_repo(self, url, name):
        """Clone or pull a repo, return the local path."""
        clone_dir = os.path.join(CLONE_BASE, f"sonarqube-{name}")
        os.makedirs(CLONE_BASE, exist_ok=True)

        if os.path.exists(os.path.join(clone_dir, ".git")):
            logger.info(f"[sonarqube] Pulling {name}...")
            try:
                repo = git.Repo(clone_dir)
                repo.remotes.origin.pull()
            except Exception as e:
                logger.warning(f"[sonarqube] Pull failed for {name}: {e}, re-cloning...")
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)
                git.Repo.clone_from(url, clone_dir, depth=1, single_branch=True)
        else:
            logger.info(f"[sonarqube] Cloning {name}...")
            git.Repo.clone_from(url, clone_dir, depth=1, single_branch=True)

        return clone_dir

    def _collect_from_rspec_fork(self):
        """Collect rules from the sonar-rspec fork (all languages)."""
        count = 0
        try:
            clone_dir = self._clone_repo(RSPEC_FORK, "rspec-fork")
            rules_dir = os.path.join(clone_dir, "rules")

            if not os.path.isdir(rules_dir):
                logger.warning("[sonarqube] RSPEC fork has no rules/ directory")
                return 0

            for rule_dirname in os.listdir(rules_dir):
                rule_dir = os.path.join(rules_dir, rule_dirname)
                if not os.path.isdir(rule_dir):
                    continue

                # Read shared metadata
                shared_meta_path = os.path.join(rule_dir, "metadata.json")
                if not os.path.exists(shared_meta_path):
                    continue

                try:
                    with open(shared_meta_path, "r", encoding="utf-8") as f:
                        shared_meta = json.load(f)
                except (json.JSONDecodeError, IOError):
                    continue

                # Find language-specific overrides
                lang_dirs = [
                    d for d in os.listdir(rule_dir)
                    if os.path.isdir(os.path.join(rule_dir, d))
                    and d not in ("metadata.json",)
                ]

                if lang_dirs:
                    for lang_dir_name in lang_dirs:
                        lang_meta_path = os.path.join(
                            rule_dir, lang_dir_name, "metadata.json"
                        )
                        lang_meta = {}
                        if os.path.exists(lang_meta_path):
                            try:
                                with open(lang_meta_path, "r", encoding="utf-8") as f:
                                    lang_meta = json.load(f)
                            except (json.JSONDecodeError, IOError):
                                pass

                        # Merge shared + language-specific
                        merged = {**shared_meta, **lang_meta}
                        self._upsert_sonar_rule(
                            rule_dirname, merged, lang_dir_name, "rspec-fork"
                        )
                        count += 1
                else:
                    # No language subdirs — use shared metadata
                    self._upsert_sonar_rule(
                        rule_dirname, shared_meta, "generic", "rspec-fork"
                    )
                    count += 1

            logger.info(f"[sonarqube] RSPEC fork: {count} rules")
        except Exception as e:
            logger.warning(f"[sonarqube] RSPEC fork collection failed: {e}")

        return count

    def _collect_from_analyzer_repo(self, language, config):
        """Collect rules from an individual analyzer repo."""
        count = 0

        # Repos may be shared (e.g., sonar-dotnet for both C# and VB.NET)
        repo_name = config["repo"].split("/")[-1].replace(".git", "")
        clone_dir = self._clone_repo(config["repo"], repo_name)
        rspec_path = os.path.join(clone_dir, config["rspec_path"])

        if not os.path.isdir(rspec_path):
            # Try alternate paths
            logger.debug(f"[sonarqube] Path not found: {rspec_path}")
            return 0

        # RSPEC fork language directories use S####/metadata.json structure
        # (directories containing metadata.json), while analyzer repos use
        # flat S####.json files or S####/metadata.json directories.
        is_rspec_lang = config.get("is_rspec_fork_language", False)

        for fname in os.listdir(rspec_path):
            fpath = os.path.join(rspec_path, fname)

            # JSON metadata files (S1234.json)
            if fname.endswith(".json") and fname[0] == "S":
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    rule_id = fname.replace(".json", "")
                    self._upsert_sonar_rule(rule_id, meta, language, repo_name)
                    count += 1
                except (json.JSONDecodeError, IOError) as e:
                    logger.debug(f"[sonarqube] Failed to parse {fpath}: {e}")

            # Directory-based rules (S1234/metadata.json)
            elif os.path.isdir(fpath) and fname.startswith("S"):
                meta_file = os.path.join(fpath, "metadata.json")
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                        self._upsert_sonar_rule(fname, meta, language, repo_name)
                        count += 1
                    except (json.JSONDecodeError, IOError) as e:
                        logger.debug(f"[sonarqube] Failed to parse {meta_file}: {e}")

        return count

    def _upsert_sonar_rule(self, rule_id, meta, language, source):
        """Insert/update a SonarQube rule using Chris's format."""
        title = meta.get("title", rule_id)

        # Severity
        raw_severity = meta.get("defaultSeverity", "Major")
        normalized_severity, severity_abbrev = SEVERITY_MAP.get(
            raw_severity, ("medium", "M")
        )

        # Type / Classification
        raw_type = meta.get("type", "CODE_SMELL")
        category, type_abbrev = TYPE_MAP.get(raw_type, ("code_smell", "CS"))

        # CWE mappings
        security_standards = meta.get("securityStandards", {})
        cwe_list = security_standards.get("CWE", [])
        cwe_ids = [f"CWE-{c}" for c in cwe_list] if cwe_list else []
        cwe_display = ", ".join(str(c) for c in cwe_list) if cwe_list else "none"

        # OWASP mappings
        owasp_list = security_standards.get("OWASP", [])
        owasp_2021 = security_standards.get("OWASP Top 10 2021", [])
        owasp_ids = [f"A{o}" if not str(o).startswith("A") else str(o)
                     for o in (owasp_2021 or owasp_list)]

        # Tags
        tags = meta.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tags = list(set(tags + [language, raw_type.lower()]))

        # Unique rule ID per language
        full_rule_id = f"sonar:{language}:{rule_id}"

        # Code impacts (new SonarQube format)
        code_meta = meta.get("code", {})
        impacts = code_meta.get("impacts", {})

        self.upsert(
            rule_id=full_rule_id,
            title=title[:500],
            description=title,
            severity=normalized_severity,
            category=category,
            language=language,
            cwe_ids=cwe_ids,
            owasp_ids=owasp_ids,
            tags=tags,
            source_file=f"https://rules.sonarsource.com/{language}/{rule_id}",
            rule_content=json.dumps(meta, indent=2)[:50000],
            rule_format="json",
            metadata={
                "sonarqube_id": rule_id,
                "sonarqube_severity": severity_abbrev,
                "sonarqube_classification": type_abbrev,
                "sonarqube_cwe": cwe_display,
                "sonarqube_severity_full": raw_severity,
                "sonarqube_type_full": raw_type,
                "status": meta.get("status", ""),
                "impacts": impacts,
                "security_standards": security_standards,
                "source_repo": source,
            },
        )
