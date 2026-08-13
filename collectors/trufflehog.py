"""Collector for TruffleHog secret scanner detectors.

TruffleHog is a tool for detecting and verifying secrets in source code.
Detectors are defined in pkg/detectors/ as Go source files. Each detector
implements a struct that embeds `detectors.Detector` and provides metadata
such as a Keywords list for initial filtering. We parse the Go source to
extract detector struct names (used as rule IDs), description comments,
and keyword lists. Severity is inferred from the detector type — verified
detectors (those with a Verify method that calls out to a remote API) are
higher severity because they confirm the secret is live.
"""

import os
import re
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)


class TruffleHogCollector(BaseCollector):
    name = "trufflehog"
    display_name = "TruffleHog"
    source_type = "github"
    source_url = "https://github.com/trufflesecurity/trufflehog.git"
    description = (
        "TruffleHog is a secret scanner that finds and verifies credentials "
        "in source code, cloud environments, and container images. Detectors "
        "cover API keys, tokens, certificates, and connection strings for "
        "hundreds of services. Verified secrets are confirmed live."
    )
    logo_url = "https://avatars.githubusercontent.com/u/84495923"

    # Severity heuristics:
    #   - Detectors with a Verify() method that makes a network call are
    #     "verified" — if the secret is confirmed live, severity is high.
    #   - Detectors without verification are "unverified" — medium.
    #   - Cloud-provider / infrastructure detectors get a slight bump.
    HIGH_SEVERITY_KEYWORDS = {
        "aws", "gcp", "azure", "github_token", "gitlab", "stripe",
        "digitalocean", "heroku", "firebase", "terraform", "kube",
    }

    def collect_rules(self):
        """Parse pkg/detectors/ Go source files for detector definitions."""
        count = 0
        detectors_dir = os.path.join(self.clone_dir, "pkg", "detectors")

        if not os.path.isdir(detectors_dir):
            logger.warning("[trufflehog] pkg/detectors/ directory not found")
            return

        for root, dirs, files in os.walk(detectors_dir):
            # Skip testdata directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "testdata"]
            for fname in sorted(files):
                if not fname.endswith(".go"):
                    continue
                if fname.endswith("_test.go"):
                    continue
                if fname in ("detectorset.go", "detectors.go", "trueup.go"):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)
                count += self._parse_detector_file(fpath, rel_path)

        logger.info(f"[trufflehog] Processed {count} detectors")

    def _parse_detector_file(self, fpath, rel_path):
        """Parse a single Go detector file for detector struct and metadata."""
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return 0

        # Each detector defines a struct that embeds something from the
        # detectors package, e.g.:
        #   type CustomDetector struct {
        #       detectors.CommonDetector
        #   }
        # or:
        #   type AWSS3 struct {
        #       ...
        #   }
        # We look for struct definitions in the file.
        struct_match = re.search(
            r"type\s+(\w+)\s+struct\s*\{([^}]*)\}",
            content,
        )
        if not struct_match:
            return 0

        struct_name = struct_match.group(1)
        struct_body = struct_match.group(2)

        # Skip generic/abstract types
        if struct_name in ("CustomDetector", "Detector", "CommonDetector"):
            return 0

        # Extract Keywords (used for initial content scanning)
        keywords = []
        kw_match = re.search(
            r'Keywords\s*:?\s*(?:\[\]string\{)?\s*((?:[^}]+))\s*\}?',
            content,
        )
        if kw_match:
            kw_block = kw_match.group(1)
            keywords = re.findall(r'"([^"]+)"', kw_block)

        # Extract description from the doc comment immediately above the struct
        # or from a Description field
        desc = ""
        # Doc comment: lines starting with // above the struct
        doc_match = re.search(
            r'((?://[^\n]*\n)+)\s*type\s+' + re.escape(struct_name) + r'\s+struct',
            content,
        )
        if doc_match:
            doc_lines = doc_match.group(1).strip().splitlines()
            desc = " ".join(
                line.strip().lstrip("/").strip() for line in doc_lines
            ).strip()

        # Try Description field
        if not desc:
            desc_match = re.search(
                r'Description\s*:\s*"([^"]+)"', content
            )
            if desc_match:
                desc = desc_match.group(1)

        if not desc:
            # Fall back to a humanized struct name
            desc = re.sub(
                r"([a-z])([A-Z])", r"\1 \2", struct_name
            ).strip()

        # Determine severity
        # Look for a Verify method — verified detectors are higher severity
        has_verify = bool(
            re.search(r"func\s+\([^)]+\)\s*Verify\s*\(", content)
        )

        # Look for Type() returning a detector type
        type_match = re.search(
            r'func\s+\([^)]+\)\s*Type\s*\(\s*\)\s*detectors\.Type\s*\{[^}]*return\s*detectors\.TypeDetector_NamedCustom\s*\}',
            content,
        )

        # Bump severity for high-sensitivity keywords
        kw_lower = [k.lower() for k in keywords]
        is_high_severity = any(
            kw in kw_lower for kw in self.HIGH_SEVERITY_KEYWORDS
        )

        if has_verify and is_high_severity:
            severity = "critical"
        elif has_verify:
            severity = "high"
        elif is_high_severity:
            severity = "high"
        else:
            severity = "medium"

        # Build rule ID
        rule_id = f"trufflehog:{struct_name}"

        # Category from keywords
        category = "secrets"
        if any(kw in kw_lower for kw in ("aws", "gcp", "azure", "cloud", "firebase")):
            category = "cloud-secrets"
        elif any(kw in kw_lower for kw in ("database", "postgres", "mysql", "mongo", "redis")):
            category = "database-secrets"
        elif any(kw in kw_lower for kw in ("token", "api_key", "apikey", "jwt", "oauth")):
            category = "api-secrets"

        tags = ["trufflehog", "secrets", "scanner"]
        if has_verify:
            tags.append("verified")
        tags.append(category)

        self.upsert(
            rule_id=rule_id,
            title=f"TruffleHog: {struct_name}"[:500],
            description=desc[:2000],
            severity=severity,
            category=category,
            language="go",
            cwe_ids=["CWE-798"],  # Use of Hard-coded Credentials — generic for all secret detectors
            owasp_ids=["A07:2021"],  # Identification and Authentication Failures
            tags=tags,
            source_file=rel_path,
            rule_content=content[:50000],
            rule_format="go",
            metadata={
                "detector_name": struct_name,
                "keywords": keywords,
                "verified": has_verify,
                "detector_type": "named_custom" if type_match else "standard",
            },
        )
        return 1