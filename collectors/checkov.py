"""Collector for Checkov (IaC security scanner) rules."""

import os
import re
import ast
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Checkov check ID prefixes → IaC framework
ID_PREFIX_MAP = {
    "CKV_AWS": "aws",
    "CKV_AZURE": "azure",
    "CKV_GCP": "gcp",
    "CKV_ALI": "alicloud",
    "CKV_OCI": "oracle",
    "CKV_LIN": "linode",
    "CKV_DO": "digitalocean",
    "CKV_NCP": "ncp",
    "CKV_K8S": "kubernetes",
    "CKV_TF": "terraform",
    "CKV_CFN": "cloudformation",
    "CKV_ARM": "arm",
    "CKV_DOCKER": "dockerfile",
    "CKV_OPENAPI": "openapi",
    "CKV_SERVERLESS": "serverless",
    "CKV_GITHUB": "github",
    "CKV_GITLAB": "gitlab",
    "CKV_BITBUCKET": "bitbucket",
    "CKV_ANSIBLE": "ansible",
    "CKV_BICEP": "bicep",
    "CKV_CIRCLECI": "circleci",
    "CKV_AZURE_PIPELINES": "azure_pipelines",
    "CKV_GITHUB_ACTIONS": "github_actions",
    "CKV_GITLAB_CI": "gitlab_ci",
    "CKV_BITBUCKET_PIPELINES": "bitbucket_pipelines",
    "CKV_ARGO": "argo_workflows",
    "CKV_CDK": "cdk",
    "CKV_SECRETS": "secrets",
}


class CheckovCollector(BaseCollector):
    name = "checkov"
    display_name = "Checkov"
    source_type = "github"
    source_url = "https://github.com/bridgecrewio/checkov.git"
    description = (
        "Infrastructure-as-Code (IaC) security scanner by Bridgecrew/Palo "
        "Alto Networks.  Scans Terraform, CloudFormation, Kubernetes, ARM, "
        "Bicep, Dockerfile, Helm, Serverless, OpenAPI, GitHub Actions, and "
        "more for misconfigurations and policy violations."
    )
    logo_url = "https://avatars.githubusercontent.com/u/51955454"

    def collect_rules(self):
        count = 0
        checkov_dir = os.path.join(self.clone_dir, "checkov")
        if not os.path.isdir(checkov_dir):
            logger.warning(f"[checkov] checkov dir not found at {checkov_dir}")
            return

        # Walk all checkov/*/checks/ directories (including nested subdirs
        # like checkov/terraform/checks/resource/aws/).
        for root, dirs, files in os.walk(checkov_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fname in files:
                if not fname.endswith(".py") or fname.startswith("__"):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.clone_dir)

                # Determine the IaC framework from the path
                framework = self._detect_framework(rel_path)

                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue

                rule = self._parse_check_file(content, fname, rel_path, framework)
                if rule:
                    self.upsert(
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=rule["category"],
                        language="yaml",
                        cwe_ids=[],
                        tags=rule["tags"],
                        source_file=rel_path,
                        rule_content=content[:50000],
                        rule_format="python",
                        metadata=rule["metadata"],
                    )
                    count += 1

        logger.info(f"[checkov] Processed {count} checks")

    def _parse_check_file(self, content, filename, rel_path, framework):
        """Parse a Checkov check Python file for id, name, and category.

        Checkov checks follow a consistent pattern: a class with an
        ``__init__`` method that sets ``id = "CKV_..."``, ``name = "..."``,
        and ``categories = (CheckCategories.X,)``.

        We use AST parsing to extract these assignments reliably, then fall
        back to regex for files that are harder to parse.
        """
        # Try AST parsing first
        rule = self._parse_with_ast(content, filename, rel_path, framework)
        if rule:
            return rule

        # Fall back to regex
        return self._parse_with_regex(content, filename, rel_path, framework)

    def _parse_with_ast(self, content, filename, rel_path, framework):
        """Extract id, name, and categories using AST."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return None

        check_id = None
        check_name = None
        categories = []
        class_name = None
        supported_resources = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                # Look in __init__ for assignments
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                        for stmt in ast.walk(item):
                            if isinstance(stmt, ast.Assign):
                                for target in stmt.targets:
                                    if isinstance(target, ast.Name):
                                        if target.id == "id" and isinstance(stmt.value, ast.Constant):
                                            check_id = stmt.value.value
                                        elif target.id == "name" and isinstance(stmt.value, ast.Constant):
                                            check_name = stmt.value.value
                                        elif target.id == "supported_resources":
                                            supported_resources = self._extract_list(stmt.value)
                                        elif target.id == "categories":
                                            categories = self._extract_categories(stmt.value)
                            elif isinstance(stmt, ast.Call):
                                # super().__init__(name=name, id=id, ...)
                                for kw in stmt.keywords:
                                    if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                                        check_id = kw.value.value
                                    elif kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                        check_name = kw.value.value
                                    elif kw.arg == "categories":
                                        categories = self._extract_categories(kw.value)

        if not check_id:
            return None

        if not check_name:
            check_name = class_name or filename.replace(".py", "")

        category = categories[0] if categories else "GENERAL_SECURITY"

        return {
            "id": check_id,
            "title": f"{check_id}: {check_name}"[:500],
            "description": check_name,
            "severity": self._map_severity(category),
            "category": category,
            "framework": framework,
            "tags": ["checkov", "iac", framework, "sast",
                     category.lower().replace(" ", "-")],
            "metadata": {
                "check_id": check_id,
                "class_name": class_name,
                "framework": framework,
                "categories": categories,
                "supported_resources": supported_resources,
                "source_file": rel_path,
            },
        }

    def _parse_with_regex(self, content, filename, rel_path, framework):
        """Fall back to regex for files that can't be AST-parsed."""
        # id = "CKV_..."
        id_match = re.search(r'\bid\s*=\s*["\'](CKV_[\w]+)["\']', content)
        if not id_match:
            return None
        check_id = id_match.group(1)

        # name = "..."
        name_match = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', content)
        check_name = name_match.group(1) if name_match else filename.replace(".py", "")

        # categories = (CheckCategories.X, ...)
        cat_matches = re.findall(r'CheckCategories\.(\w+)', content)
        categories = cat_matches if cat_matches else ["GENERAL_SECURITY"]
        category = categories[0]

        # supported_resources
        res_match = re.search(r'supported_resources\s*=\s*\[([^\]]+)\]', content)
        supported_resources = []
        if res_match:
            supported_resources = re.findall(r"['\"]([^'\"]+)['\"]", res_match.group(1))

        # Class name
        class_match = re.search(r'class\s+(\w+)\s*\(', content)
        class_name = class_match.group(1) if class_match else filename.replace(".py", "")

        return {
            "id": check_id,
            "title": f"{check_id}: {check_name}"[:500],
            "description": check_name,
            "severity": self._map_severity(category),
            "category": category,
            "framework": framework,
            "tags": ["checkov", "iac", framework, "sast",
                     category.lower().replace(" ", "-")],
            "metadata": {
                "check_id": check_id,
                "class_name": class_name,
                "framework": framework,
                "categories": categories,
                "supported_resources": supported_resources,
                "source_file": rel_path,
            },
        }

    @staticmethod
    def _extract_list(node):
        """Extract string elements from an AST List/Tuple node."""
        items = []
        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    items.append(elt.value)
        return items

    @staticmethod
    def _extract_categories(node):
        """Extract CheckCategories enum names from an AST node."""
        cats = []
        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                if isinstance(elt, ast.Attribute):
                    if isinstance(elt.value, ast.Name) and elt.value.id == "CheckCategories":
                        cats.append(elt.attr)
        return cats

    @staticmethod
    def _map_severity(category):
        """Map Checkov categories to a severity level."""
        high_cats = {"SECRETS", "IAM", "ENCRYPTION", "APPLICATION_SECURITY",
                     "API_SECURITY"}
        medium_cats = {"NETWORKING", "GENERAL_SECURITY", "BACKUP_AND_RECOVERY",
                       "SUPPLY_CHAIN", "KUBERNETES", "SAST", "AI_AND_ML"}
        if category in high_cats:
            return "high"
        if category in medium_cats:
            return "medium"
        return "low"

    @staticmethod
    def _detect_framework(rel_path):
        """Detect the IaC framework from the file path."""
        # Path: checkov/<framework>/checks/...
        parts = rel_path.split(os.sep)
        if len(parts) >= 2 and parts[0] == "checkov":
            framework = parts[1]
            return framework
        return "unknown"