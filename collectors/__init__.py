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
from .clang import ClangCollector
from .veracode import VeracodeCollector
from .brakeman import BrakemanCollector
from .gosec import GoSecCollector
from .shellcheck import ShellCheckCollector
from .checkov import CheckovCollector
from .detekt import DetektCollector
from .swiftlint import SwiftLintCollector
from .pylint import PylintCollector
from .infer import InferCollector
from .hadolint import HadolintCollector
from .phpstan import PHPStanCollector
from .tfsec import TfsecCollector
from .psalm import PsalmCollector
from .dependency_check import DependencyCheckCollector
from .retirejs import RetireJsCollector

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
    ClangCollector,
    VeracodeCollector,
    BrakemanCollector,
    GoSecCollector,
    ShellCheckCollector,
    CheckovCollector,
    DetektCollector,
    SwiftLintCollector,
    PylintCollector,
    InferCollector,
    HadolintCollector,
    PHPStanCollector,
    TfsecCollector,
    PsalmCollector,
    DependencyCheckCollector,
    RetireJsCollector,
]