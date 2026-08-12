"""
CyberSagacity Rule Collectors
Each collector fetches rules from a specific security scanning vendor.
"""

from .base import BaseCollector
from .semgrep import SemgrepCollector
from .nuclei import NucleiCollector
from .falco import FalcoCollector
from .trivy import TrivyCollector
from .checkmarx_kics import CheckmarxKICSCollector
from .bandit import BanditCollector
from .findsecbugs import FindSecBugsCollector
from .pmd import PMDCollector
from .eslint_security import ESLintSecurityCollector
from .sonarqube import SonarQubeCollector
from .spotbugs import SpotBugsCollector
from .cppcheck import CppCheckCollector
from .flawfinder import FlawfinderCollector
from .phpmd import PHPMDCollector
from .php_codesniffer import PHPCodeSnifferCollector
from .deque_axe import DequeAXECollector
from .gitlab_sast import GitLabSASTCollector
from .snyk import SnykCollector

ALL_COLLECTORS = [
    SemgrepCollector,
    NucleiCollector,
    FalcoCollector,
    TrivyCollector,
    CheckmarxKICSCollector,
    BanditCollector,
    FindSecBugsCollector,
    PMDCollector,
    ESLintSecurityCollector,
    SonarQubeCollector,
    SpotBugsCollector,
    CppCheckCollector,
    FlawfinderCollector,
    PHPMDCollector,
    PHPCodeSnifferCollector,
    DequeAXECollector,
    GitLabSASTCollector,
    SnykCollector,
]
