"""Collector for GitLab SAST security scanner templates.

GitLab SAST runs multiple analyzers (Semgrep, ESLint, Bandit, etc.) and
provides CI/CD security templates for each scanner type. The templates
live in the GitLab monolith repo at lib/gitlab/ci/templates/Security/.

The GitLab monolith is too large to clone in CI (multi-GB), so this
collector uses source_type='web' with a curated list of the known
security templates, each with its source URL pointing to the exact
file in the GitLab repo.
"""

import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Curated list of GitLab CI security templates.
# Each entry maps to a template file in the GitLab monolith repo.
# Source: https://gitlab.com/gitlab-org/gitlab/-/tree/master/lib/gitlab/ci/templates/Security
GITLAB_SAST_TEMPLATES = [
    {"id": "SAST", "file": "Security/SAST.gitlab-ci.yml", "category": "sast", "severity": "high",
     "desc": "GitLab SAST (Static Application Security Testing) template. Runs multi-language static analysis using analyzers like Semgrep, ESLint, Bandit, and Gosec."},
    {"id": "SAST-IaC", "file": "Jobs/SAST-IaC.gitlab-ci.yml", "category": "iac-sast", "severity": "high",
     "desc": "GitLab SAST for Infrastructure-as-Code. Scans Terraform, Ansible, CloudFormation, and Kubernetes manifests for misconfigurations."},
    {"id": "SAST-IaC.latest", "file": "Jobs/SAST-IaC.latest.gitlab-ci.yml", "category": "iac-sast", "severity": "high",
     "desc": "Latest version of GitLab SAST IaC template."},
    {"id": "Secret-Detection", "file": "Security/Secret-Detection.gitlab-ci.yml", "category": "secrets", "severity": "high",
     "desc": "GitLab Secret Detection template. Scans repository for hardcoded secrets, API keys, tokens, and credentials using Gitleaks-based analyzer."},
    {"id": "Dependency-Scanning", "file": "Security/Dependency-Scanning.gitlab-ci.yml", "category": "sca", "severity": "high",
     "desc": "GitLab Dependency Scanning template. Software Composition Analysis for detecting vulnerable dependencies (Maven, NPM, pip, gem, etc.)."},
    {"id": "Container-Scanning", "file": "Security/Container-Scanning.gitlab-ci.yml", "category": "container-security", "severity": "high",
     "desc": "GitLab Container Scanning template. Scans Docker container images for known vulnerabilities using Trivy."},
    {"id": "Container-Scanning.latest", "file": "Security/Container-Scanning.latest.gitlab-ci.yml", "category": "container-security", "severity": "high",
     "desc": "Latest version of GitLab Container Scanning template."},
    {"id": "Multi-Container-Scanning.latest", "file": "Security/Multi-Container-Scanning.latest.gitlab-ci.yml", "category": "container-security", "severity": "high",
     "desc": "Multi-image container scanning template (legacy)."},
    {"id": "DAST", "file": "Security/DAST.gitlab-ci.yml", "category": "dast", "severity": "high",
     "desc": "GitLab DAST (Dynamic Application Security Testing) template. Scans running web applications for vulnerabilities like XSS, SQL injection, and CSRF."},
    {"id": "DAST.latest", "file": "Security/DAST.latest.gitlab-ci.yml", "category": "dast", "severity": "high",
     "desc": "Latest version of GitLab DAST template."},
    {"id": "DAST-API", "file": "Security/DAST-API.gitlab-ci.yml", "category": "dast-api", "severity": "high",
     "desc": "GitLab DAST API template. Dynamic security testing for REST, GraphQL, and SOAP APIs."},
    {"id": "DAST-API.latest", "file": "Security/DAST-API.latest.gitlab-ci.yml", "category": "dast-api", "severity": "high",
     "desc": "Latest version of GitLab DAST API template."},
    {"id": "API-Security", "file": "Security/API-Security.gitlab-ci.yml", "category": "api-security", "severity": "high",
     "desc": "GitLab API Security testing template. Fuzzes API endpoints for security issues."},
    {"id": "API-Security.latest", "file": "Security/API-Security.latest.gitlab-ci.yml", "category": "api-security", "severity": "high",
     "desc": "Latest version of GitLab API Security template."},
    {"id": "API-Fuzzing", "file": "Security/API-Fuzzing.gitlab-ci.yml", "category": "api-fuzzing", "severity": "medium",
     "desc": "GitLab API Fuzzing template (legacy name for API Security)."},
    {"id": "API-Fuzzing.latest", "file": "Security/API-Fuzzing.latest.gitlab-ci.yml", "category": "api-fuzzing", "severity": "medium",
     "desc": "Latest version of GitLab API Fuzzing template (legacy name)."},
    {"id": "API-Discovery", "file": "Security/API-Discovery.gitlab-ci.yml", "category": "api-discovery", "severity": "info",
     "desc": "GitLab API Discovery template. Discovers API endpoints from web application traffic for subsequent security testing."},
    {"id": "Coverage-Fuzzing", "file": "Security/Coverage-Fuzzing.gitlab-ci.yml", "category": "fuzzing", "severity": "medium",
     "desc": "GitLab Coverage Fuzzing template. Coverage-guided fuzz testing for detecting crashes and memory safety issues."},
    {"id": "Coverage-Fuzzing.latest", "file": "Security/Coverage-Fuzzing.latest.gitlab-ci.yml", "category": "fuzzing", "severity": "medium",
     "desc": "Latest version of GitLab Coverage Fuzzing template."},
    {"id": "BAS.latest", "file": "Security/BAS.latest.gitlab-ci.yml", "category": "breach-simulation", "severity": "high",
     "desc": "GitLab Breach and Attack Simulation template. Runs simulated attacks to validate security controls."},
    {"id": "DAST-On-Demand-Scan", "file": "Security/DAST-On-Demand-Scan.gitlab-ci.yml", "category": "dast", "severity": "high",
     "desc": "GitLab DAST On-Demand Scan template. Allows running DAST scans without a pipeline."},
    {"id": "DAST-On-Demand-API-Scan", "file": "Security/DAST-On-Demand-API-Scan.gitlab-ci.yml", "category": "dast-api", "severity": "high",
     "desc": "GitLab DAST On-Demand API Scan template. On-demand API security testing without a pipeline."},
    {"id": "DAST-Runner-Validation", "file": "Security/DAST-Runner-Validation.gitlab-ci.yml", "category": "dast", "severity": "info",
     "desc": "GitLab DAST Runner Validation template. Validates DAST runner configuration."},
    {"id": "Fortify-FoD-sast", "file": "Security/Fortify-FoD-sast.gitlab-ci.yml", "category": "sast", "severity": "high",
     "desc": "GitLab template for integrating Fortify on Demand SAST scans into CI/CD pipelines."},
    {"id": "Qualys-IaC-Security", "file": "Qualys-IaC-Security.gitlab-ci.yml", "category": "iac-security", "severity": "high",
     "desc": "GitLab template for Qualys IaC Security scanning. Scans infrastructure-as-code for misconfigurations."},
    {"id": "Secure-Binaries", "file": "Security/Secure-Binaries.gitlab-ci.yml", "category": "binary-security", "severity": "medium",
     "desc": "GitLab Secure Binaries template. Scans compiled binaries for known vulnerabilities."},
]


class GitLabSASTCollector(BaseCollector):
    name = "gitlab_sast"
    display_name = "GitLab SAST"
    source_type = "web"
    source_url = "https://gitlab.com/gitlab-org/gitlab/-/tree/master/lib/gitlab/ci/templates/Security"
    description = (
        "GitLab SAST (Static Application Security Testing). "
        "Multi-language security scanning with CI/CD templates for SAST, "
        "DAST, secret detection, dependency scanning, container scanning, "
        "API security, and fuzzing. Integrates with GitLab CI/CD pipelines."
    )
    logo_url = "https://avatars.githubusercontent.com/u/10669714"

    def clone_or_pull(self):  # type: ignore[override]
        """No-op — curated list, no git clone needed."""
        logger.info(f"[{self.name}] Web source — no clone/pull needed.")
        return None

    def has_changes(self):
        return True

    def save_commit_sha(self):
        """No commit SHA for web sources."""
        pass

    def collect_rules(self):
        count = 0
        for tmpl in GITLAB_SAST_TEMPLATES:
            rule_id = f"gitlab-sast:{tmpl['id']}"
            source_file = f"lib/gitlab/ci/templates/{tmpl['file']}"
            # Direct link to the file in GitLab
            file_url = (
                f"https://gitlab.com/gitlab-org/gitlab/-/raw/master/"
                f"lib/gitlab/ci/templates/{tmpl['file']}"
            )

            self.upsert(
                rule_id=rule_id,
                title=f"GitLab SAST: {tmpl['id']}",
                description=tmpl["desc"],
                severity=tmpl["severity"],
                category=tmpl["category"],
                language="yaml",
                cwe_ids=[],
                owasp_ids=[],
                tags=["gitlab", "sast", "ci-cd", "security", tmpl["category"]],
                source_file=file_url,
                rule_content="",
                rule_format="yaml",
                metadata={
                    "template": tmpl["id"],
                    "template_file": source_file,
                    "source": "gitlab-curated",
                },
            )
            count += 1

        logger.info(f"[gitlab_sast] Processed {count} rules from curated templates")