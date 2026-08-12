# SARIF 2.1.0 Schema Reference for SATriage Rule Collectors

This document defines the SARIF (Static Analysis Results Interchange Format)
output shape that all CyberSagacity rule collectors should produce for
SATriage ingestion testing.

## SARIF 2.1.0 Top-Level Structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ToolName",
          "version": "1.0",
          "informationUri": "https://example.com",
          "rules": [...]
        }
      },
      "results": [...]
    }
  ]
}
```

## Rule Object (in tool.driver.rules[])

Each rule from the aggregator maps to a SARIF rule object:

```json
{
  "id": "spotbugs-XYZ",
  "name": "Rule Title",
  "shortDescription": {
    "text": "Short description"
  },
  "fullDescription": {
    "text": "Full description text"
  },
  "helpUri": "https://example.com/rule/XYZ",
  "help": {
    "text": "Help text"
  },
  "defaultConfiguration": {
    "level": "error"
  },
  "properties": {
    "severity": "high",
    "category": "security",
    "language": "java",
    "cwe": ["CWE-79"],
    "owasp": ["A03"],
    "tags": ["spotbugs", "java", "sast"],
    "vendor_metadata": {}
  }
}
```

### level mapping (SARIF defaultConfiguration.level):
- `error` → critical, high
- `warning` → medium
- `note` → low
- `none` → info

### properties bag:
- `severity`: our normalized severity (critical/high/medium/low/info)
- `category`: our category field
- `language`: target language
- `cwe`: JSON array of CWE IDs
- `owasp`: JSON array of OWASP IDs
- `tags`: JSON array of tags
- `vendor_metadata`: vendor-specific fields (preserved from collector metadata)
- `rule_format`: original format (xml, json, yaml, python, etc.)

## Result Object (in results[])

When testing a collector against a sample project, each finding becomes:

```json
{
  "ruleId": "spotbugs-XYZ",
  "ruleIndex": 0,
  "level": "error",
  "message": {
    "text": "Finding description"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "src/main/java/Example.java",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": 42,
          "startColumn": 10
        }
      }
    }
  ],
  "properties": {
    "severity": "high",
    "confidence": "high"
  }
}
```

## Minimal SARIF for Rule Catalog Only (no findings)

For testing rule ingestion without running against a codebase:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "cybersagacity-rule-aggregator",
          "version": "2.0",
          "informationUri": "https://github.com/Kasloco/cybersagacity-rule-aggregator",
          "rules": [
            {
              "id": "<rule_id>",
              "name": "<title>",
              "shortDescription": { "text": "<description>" },
              "defaultConfiguration": { "level": "<error|warning|note|none>" },
              "properties": {
                "severity": "<critical|high|medium|low|info>",
                "category": "<category>",
                "language": "<language>",
                "cwe": [],
                "owasp": [],
                "tags": [],
                "vendor_metadata": {},
                "rule_format": "<xml|json|yaml|python|...>"
              }
            }
          ]
        }
      },
      "results": []
    }
  ]
}
```

## SATriage MCP Integration

The SATriage MCP accepts SARIF result files via `satResultPaths` on a project:

```json
{
  "id": "project-id",
  "satResultPaths": [
    {
      "id": "unique-id",
      "tool": "ToolName",
      "path": "sarifOutput.json"
    }
  ]
}
```

### Testing flow:
1. Run collector: `python cli.py sync --vendor <name>`
2. Export rules as SARIF (using the schema above)
3. Create/update SATriage project with `mcp__satriage__create_project` or `mcp__satriage__update_project`
4. Add the SARIF file path to `satResultPaths`
5. Run analysis with `mcp__satriage__analyze_project` using profile ID `1786466794750`

### Existing SATriage projects for reference:
- `1786561940764` (app) - has PMD SARIF at `pmdSarifOutput.json`
- `1774471050764` (Zlib) - has Fortify CSV + Infer XML
- Profile: `1786466794750` (Simple Prioritization)