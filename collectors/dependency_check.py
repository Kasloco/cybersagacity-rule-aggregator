"""Collector for OWASP Dependency-Check suppression and hint rules.

OWASP Dependency-Check is a SCA (Software Composition Analysis) tool that
identifies known-vulnerable dependencies using the NVD. Its "rules" are not
detection rules in the SAST sense — they are suppression and hint rules that
control false-positive management and CPE matching:

  1. **Base suppression XML** (``core/src/main/resources/dependencycheck-base-suppression.xml``)
     — 7,000+ lines defining false-positive suppressions keyed by package URL
     regexes, CPE matches, and CVE identifiers. Each ``<suppress>`` entry maps
     a package pattern to CPEs/CVEs that should be suppressed.

  2. **Hints XML** (``core/src/test/resources/hints.xml`` and similar) —
     evidence matching hints that help the analyzer correctly identify
     vendor/product names.

  3. **Java analyzers** (``core/src/main/java/org/owasp/dependencycheck/analyzer/*.java``)
     — 20+ analyzer classes that perform different types of dependency scanning
     (Nuspec, NPM, Ruby, Go, Python, etc.).

This collector parses the base suppression XML as the primary rule source
(each ``<suppress>`` entry becomes a rule) and also indexes the analyzer
classes as secondary rules, since they represent the detection capabilities
of the tool.
"""

import os
import re
import xml.etree.ElementTree as ET
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Default namespace used by suppression XML files
SUPPRESSION_NS = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"
HINTS_NS = "https://jeremylong.github.io/DependencyCheck/dependency-hint.1.1.xsd"


class DependencyCheckCollector(BaseCollector):
    name = "dependency_check"
    display_name = "OWASP Dependency-Check"
    source_type = "github"
    source_url = "https://github.com/jeremylong/DependencyCheck.git"
    description = (
        "OWASP Software Composition Analysis tool that identifies known-vulnerable "
        "dependencies using NVD CVE data. Includes base suppression rules for "
        "false-positive management and 20+ analyzers for different package ecosystems "
        "(Maven, NPM, Go, Python, Ruby, .NET, etc.)."
    )
    logo_url = "https://owasp.org/assets/images/logo/owasp-logo.svg"

    def collect_rules(self):
        count = 0

        # 1. Parse base suppression rules
        count += self._parse_suppression_file(
            os.path.join(self.clone_dir, "core/src/main/resources/dependencycheck-base-suppression.xml")
        )

        # 2. Parse analyzer classes as detection rules
        count += self._parse_analyzer_classes()

        # 3. Parse hints XML if present (test resource, still useful metadata)
        hints_path = os.path.join(self.clone_dir, "core/src/test/resources/hints.xml")
        if os.path.exists(hints_path):
            count += self._parse_hints_file(hints_path)

        logger.info(f"[dependency_check] Processed {count} rules")

    def _parse_suppression_file(self, fpath):
        """Parse the base suppression XML and upsert each <suppress> entry."""
        if not os.path.exists(fpath):
            logger.warning(f"[dependency_check] Suppression file not found: {fpath}")
            return 0

        rel_path = os.path.relpath(fpath, self.clone_dir)

        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception as e:
            logger.error(f"[dependency_check] Failed to parse {fpath}: {e}")
            return 0

        # Handle namespace — try both namespaced and non-namespaced
        ns = {"sup": SUPPRESSION_NS}

        # Try namespaced first, then non-namespaced
        suppressions = root.findall(".//sup:suppress", ns)
        if not suppressions:
            suppressions = root.findall(".//suppress")

        count = 0
        for idx, suppress in enumerate(suppressions):
            # Extract notes/description
            notes_el = suppress.find("sup:notes", ns)
            if notes_el is None:
                notes_el = suppress.find("notes")
            notes = notes_el.text.strip() if notes_el is not None and notes_el.text else ""

            # Extract package URL patterns
            pkg_urls = []
            for pel in suppress.findall("sup:packageUrl", ns) or suppress.findall("packageUrl"):
                regex_attr = pel.get("regex", "false")
                pkg_urls.append({
                    "value": pel.text.strip() if pel.text else "",
                    "regex": regex_attr == "true",
                })

            # Extract CPE references
            cpes = []
            for cel in suppress.findall("sup:cpe", ns) or suppress.findall("cpe"):
                cpes.append(cel.text.strip() if cel.text else "")

            # Extract CVE references
            cves = []
            for cel in suppress.findall("sup:cve", ns) or suppress.findall("cve"):
                cves.append(cel.text.strip() if cel.text else "")

            # Build rule_id — use file position + first package URL or CVE
            base_attr = suppress.get("base", "false")
            is_base = base_attr == "true"

            # Create a unique rule ID from the suppression content
            first_pkg = pkg_urls[0]["value"] if pkg_urls else ""
            first_cve = cves[0] if cves else ""
            first_cpe = cpes[0] if cpes else ""

            if first_pkg:
                rule_id = f"suppress-{idx:05d}-{first_pkg[:50]}"
            elif first_cve:
                rule_id = f"suppress-{first_cve}"
            elif first_cpe:
                rule_id = f"suppress-{idx:05d}-{first_cpe[:50]}"
            else:
                rule_id = f"suppress-{idx:05d}"

            # Clean rule_id for DB safety
            rule_id = re.sub(r'[^a-zA-Z0-9_\-.]', '_', rule_id)[:200]

            # Build title from notes or package pattern
            title = notes[:200].strip() if notes else f"Suppression #{idx}"
            title = title.replace("\n", " ").strip()

            # Build description
            desc_parts = []
            if notes:
                desc_parts.append(notes.strip()[:1000])
            if pkg_urls:
                desc_parts.append(f"Package URL patterns: {len(pkg_urls)}")
            if cpes:
                desc_parts.append(f"CPE matches: {', '.join(cpes[:5])}")
            if cves:
                desc_parts.append(f"CVEs: {', '.join(cves[:10])}")
            description = " | ".join(desc_parts)[:2000]

            # Severity: suppressions are informational rules
            severity = "info"
            if cves:
                severity = "medium"  # CVE-related suppressions are more significant

            metadata = {
                "type": "suppression",
                "base": is_base,
                "package_urls": pkg_urls,
                "cpes": cpes,
                "cves": cves,
                "notes": notes.strip()[:500],
                "index": idx,
            }

            self.upsert(
                rule_id=rule_id,
                title=title[:500] if title else f"Suppression #{idx}",
                description=description,
                severity=severity,
                category="suppression",
                language="universal",
                cwe_ids=[],
                tags=["dependency-check", "sca", "owasp", "suppression"],
                source_file=rel_path,
                rule_content=ET.tostring(suppress, encoding="unicode")[:50000],
                rule_format="xml",
                metadata=metadata,
            )
            count += 1

        return count

    def _parse_hints_file(self, fpath):
        """Parse hints XML and upsert each <hint> entry."""
        rel_path = os.path.relpath(fpath, self.clone_dir)

        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
        except Exception as e:
            logger.debug(f"[dependency_check] Failed to parse hints: {e}")
            return 0

        ns = {"hint": HINTS_NS}
        hints = root.findall(".//hint:hint", ns)
        if not hints:
            hints = root.findall(".//hint")

        count = 0
        for idx, hint in enumerate(hints):
            rule_id = f"hint-{idx:04d}"

            # Extract given/add evidence
            given_els = hint.findall(".//hint:given/*", ns) or hint.findall(".//given/*")
            add_els = hint.findall(".//hint:add/*", ns) or hint.findall(".//add/*")

            desc_parts = []
            for el in given_els:
                desc_parts.append(f"given: {el.tag}={el.get('value', el.get('contains', ''))}")
            for el in add_els:
                desc_parts.append(f"add: {el.tag}={el.get('value', '')}")

            self.upsert(
                rule_id=rule_id,
                title=f"Evidence Hint #{idx}",
                description="; ".join(desc_parts)[:2000],
                severity="info",
                category="hint",
                language="universal",
                cwe_ids=[],
                tags=["dependency-check", "sca", "owasp", "hint"],
                source_file=rel_path,
                rule_content=ET.tostring(hint, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={
                    "type": "hint",
                    "given_count": len(given_els),
                    "add_count": len(add_els),
                },
            )
            count += 1

        # Also parse vendorDuplicatingHint entries
        dup_hints = root.findall(".//hint:vendorDuplicatingHint", ns) or root.findall(".//vendorDuplicatingHint")
        for idx, dh in enumerate(dup_hints):
            val = dh.get("value", "")
            dup = dh.get("duplicate", "")
            rule_id = f"vendor-dup-{idx:04d}"

            self.upsert(
                rule_id=rule_id,
                title=f"Vendor Duplicate: {val} -> {dup}",
                description=f"Treat vendor '{val}' as duplicate of '{dup}'",
                severity="info",
                category="hint",
                language="universal",
                cwe_ids=[],
                tags=["dependency-check", "sca", "owasp", "vendor-duplicate"],
                source_file=rel_path,
                rule_content=ET.tostring(dh, encoding="unicode")[:50000],
                rule_format="xml",
                metadata={"type": "vendor_duplicate", "value": val, "duplicate": dup},
            )
            count += 1

        return count

    def _parse_analyzer_classes(self):
        """Parse Java analyzer class names as detection capability rules."""
        analyzer_dir = os.path.join(self.clone_dir, "core/src/main/java/org/owasp/dependencycheck/analyzer")
        if not os.path.isdir(analyzer_dir):
            return 0

        count = 0
        for fname in sorted(os.listdir(analyzer_dir)):
            if not fname.endswith(".java"):
                continue
            # Skip abstract base classes and interfaces
            if fname.startswith("Abstract") or fname == "Analyzer.java":
                continue
            if fname.endswith("Service.java") or fname.endswith("AnalysisPhase.java"):
                continue

            fpath = os.path.join(analyzer_dir, fname)
            rel_path = os.path.relpath(fpath, self.clone_dir)

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue

            # Extract class name
            class_match = re.search(r'class\s+(\w+)\s+extends\s+(\w+)', content)
            if not class_match:
                continue

            class_name = class_match.group(1)
            parent_class = class_match.group(2)

            # Extract class Javadoc description
            desc_match = re.search(r'/\*\*(.*?)\*/\s*(?:public\s+)?class', content, re.DOTALL)
            description = ""
            if desc_match:
                javadoc = desc_match.group(1)
                # Clean Javadoc: remove * prefixes and @tags
                lines = []
                for line in javadoc.split("\n"):
                    line = line.strip().lstrip("*").strip()
                    if line and not line.startswith("@"):
                        lines.append(line)
                description = " ".join(lines)[:2000]

            # Extract @SuppressForTesting or other annotations as tags
            tags = ["dependency-check", "sca", "owasp", "analyzer"]

            # Determine the package ecosystem from the class name
            ecosystem = "generic"
            name_lower = class_name.lower()
            if "npm" in name_lower or "node" in name_lower:
                ecosystem = "npm"
            elif "python" in name_lower or "pip" in name_lower:
                ecosystem = "python"
            elif "ruby" in name_lower or "gem" in name_lower:
                ecosystem = "ruby"
            elif "golang" in name_lower or "go" in name_lower:
                ecosystem = "go"
            elif "swift" in name_lower:
                ecosystem = "swift"
            elif "assembly" in name_lower or "dotnet" in name_lower or "nuspec" in name_lower:
                ecosystem = "dotnet"
            elif "maven" in name_lower or "pom" in name_lower or "jar" in name_lower:
                ecosystem = "maven"
            elif "composer" in name_lower or "php" in name_lower:
                ecosystem = "php"

            tags.append(ecosystem)

            rule_id = f"analyzer-{class_name}"

            self.upsert(
                rule_id=rule_id,
                title=class_name,
                description=description,
                severity="info",
                category="analyzer",
                language="universal",
                cwe_ids=[],
                tags=tags,
                source_file=rel_path,
                rule_content=content[:50000],
                rule_format="xml",
                metadata={
                    "type": "analyzer",
                    "class_name": class_name,
                    "parent_class": parent_class,
                    "ecosystem": ecosystem,
                },
            )
            count += 1

        return count