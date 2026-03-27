# CyberSagacity Rule Intelligence Platform

A comprehensive security rule aggregation engine that automatically collects, normalizes, and indexes **30,843+ security rules** from the world's leading static analysis and scanning tools — all searchable through a single dashboard and REST API.

Built for **Chris Near, Founder of CyberSagacity**.

🔗 **Live Dashboard:** [cybersagacity-deploy.vercel.app](https://cybersagacity-deploy.vercel.app)

---

## What It Does

Security teams deal with dozens of scanning tools, each with their own rule formats, severity scales, and update cycles. This platform solves that by:

- **Aggregating rules** from 10 major vendors into a single normalized database
- **Automated monthly syncing** to catch new rules, updates, and deprecations
- **Full-text search** across 30,000+ rules with filtering by vendor, severity, category, and language
- **REST API** for programmatic access and integration with other tools
- **Change tracking** to see what's new since the last sync

## Supported Vendors

| Vendor | Rules | Source | Method |
|--------|------:|--------|--------|
| **Semgrep** | 7,856 | [semgrep.dev/r](https://semgrep.dev/r) | Registry API (`/api/registry/rules` + `/c/r/all`) |
| **SonarQube** | 6,711 | [SonarSource GitHub repos](https://github.com/SonarSource) | JSON metadata from `sonar-dotnet`, `sonar-python`, `sonar-java`, `sonar-php` + RSPEC fork |
| **Nuclei** | 12,818 | [github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Git clone + YAML parsing |
| **Checkmarx KICS** | 1,811 | [github.com/Checkmarx/kics](https://github.com/Checkmarx/kics) | Git clone + Rego/JSON parsing |
| **Trivy** | 905 | [github.com/aquasecurity/trivy-checks](https://github.com/aquasecurity/trivy-checks) | Git clone + Rego parsing |
| **PMD** | 449 | [github.com/pmd/pmd](https://github.com/pmd/pmd) | Git clone + XML parsing |
| **FindSecBugs** | 144 | [github.com/find-sec-bugs/find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) | Git clone + XML parsing |
| **Falco** | 93 | [github.com/falcosecurity/rules](https://github.com/falcosecurity/rules) | Git clone + YAML parsing |
| **Bandit** | 42 | [github.com/PyCQA/bandit](https://github.com/PyCQA/bandit) | Git clone + Python AST parsing |
| **ESLint Security** | 14 | [github.com/eslint-community/eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) | Git clone + JS parsing |

## SonarQube Format (Chris's Specification)

SonarQube rules follow Chris Near's exact format specification:

- **ID:** Capital S + number (e.g., `S2077`)
- **Severity:** `B` = Blocker, `C` = Critical, `M` = Major, `Mn` = Minor
- **Classification:** `V` = Vulnerability, `B` = Bug, `CS` = Code Smell, `S` = Security Hotspot
- **CWE:** Comma-separated CWE numbers from `securityStandards`

Languages covered: C#, VB.NET, Python, Java, JavaScript, TypeScript, Go, PHP, Kotlin, and 20+ more via the RSPEC repository.

## Quick Start

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
git clone https://github.com/Kasloco/cybersagacity-rule-aggregator.git
cd cybersagacity-rule-aggregator
pip install -r requirements.txt
```

### Initialize & Sync

```bash
# Sync all vendors (takes ~5–10 minutes on first run)
python cli.py sync

# Sync a specific vendor
python cli.py sync --vendor semgrep
python cli.py sync --vendor sonarqube

# Force re-sync (ignore cache)
python cli.py sync --force
```

### View Status

```bash
python cli.py status
```

### Search Rules

```bash
python cli.py search "SQL injection"
python cli.py search "XSS" --vendor semgrep --severity high
python cli.py search "crypto" --language python
```

### Run the Dashboard

```bash
python app.py
# Open http://localhost:8080
```

## REST API

The dashboard exposes a full REST API:

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Dashboard statistics (totals, distributions) |
| `GET /api/rules?q=injection&vendor=semgrep&severity=high&category=security&language=python&page=1&per_page=50` | Search rules with filters |
| `GET /api/rules/<rule_id>` | Get a specific rule's full details |
| `GET /api/vendors` | List all vendors with rule counts |
| `GET /api/languages` | Language distribution |
| `GET /api/categories` | Category distribution |

## Automated Monthly Sync

The scheduler can be configured to run monthly syncs:

```bash
python scheduler.py
```

Or set up a cron job:

```bash
# Run on the 1st of every month at 2am
0 2 1 * * cd /path/to/cybersagacity-rule-aggregator && python cli.py sync
```

## Project Structure

```text
cybersagacity-rule-aggregator/
├── app.py                  # Flask web dashboard
├── cli.py                  # Command-line interface
├── database.py             # SQLite database layer with FTS5 search
├── scheduler.py            # Automated sync scheduler
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container deployment
├── collectors/
│   ├── base.py             # Base collector class (git clone, upsert)
│   ├── semgrep.py          # Semgrep Registry API collector
│   ├── sonarqube.py        # SonarQube multi-repo collector
│   ├── nuclei.py           # Nuclei templates collector
│   ├── checkmarx_kics.py   # Checkmarx KICS collector
│   ├── trivy.py            # Trivy checks collector
│   ├── pmd.py              # PMD rules collector
│   ├── findsecbugs.py      # FindSecBugs collector
│   ├── falco.py            # Falco rules collector
│   ├── bandit.py           # Bandit collector
│   └── eslint_security.py  # ESLint Security collector
└── templates/
    └── dashboard.html      # Dashboard UI (Chart.js + dark theme)
```

## Database

Uses SQLite with FTS5 full-text search. The database (`rules.db`) is generated by running `sync` and is not committed to git due to size (~89MB). Key tables:

- **vendors** — Registered scanning tool sources
- **rules** — Normalized rules with severity, category, language, CWE, OWASP mappings
- **sync_history** — Audit log of all sync operations
- **rule_changes** — Change tracking for rule updates
- **rules_fts** — Full-text search index

## Adding New Vendors

Create a new collector in `collectors/` by extending `BaseCollector`:

```python
from .base import BaseCollector

class MyToolCollector(BaseCollector):
    name = "mytool"
    display_name = "My Tool"
    source_type = "github"
    source_url = "https://github.com/org/repo.git"

    def collect_rules(self):
        # Parse rules from self.clone_dir
        self.upsert(
            rule_id="RULE-001",
            title="My Rule",
            severity="high",
            category="security",
            language="python",
            ...
        )
```

Then register it in `collectors/__init__.py`.

---

*Built by Jonathan Kaslow for CyberSagacity*
