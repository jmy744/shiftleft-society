"""
sarif_export.py
Convert ShiftLeft Society verdicts to SARIF 2.1.0 — the industry-standard
static analysis format consumed by GitHub Code Scanning, Azure DevOps,
SonarQube, and most enterprise security pipelines.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

import json
from datetime import datetime, timezone
from typing import Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Map ShiftLeft severities to SARIF levels
SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "NONE": "none",
}

# Map ShiftLeft severities to SARIF rank (0-100, higher = more severe)
SEVERITY_TO_RANK = {
    "CRITICAL": 95.0,
    "HIGH": 80.0,
    "MEDIUM": 50.0,
    "LOW": 20.0,
    "INFO": 5.0,
}


def _normalize_severity(s: Optional[str]) -> str:
    if not s:
        return "MEDIUM"
    return s.strip().upper()


def _build_rule(rule_id: str, finding: dict) -> dict:
    sev = _normalize_severity(finding.get("severity"))
    return {
        "id": rule_id,
        "name": finding.get("category", "TribunalFinding").replace(" ", ""),
        "shortDescription": {"text": finding.get("title", "Security finding")[:120]},
        "fullDescription": {"text": finding.get("description", finding.get("title", ""))},
        "defaultConfiguration": {
            "level": SEVERITY_TO_LEVEL.get(sev, "warning"),
            "rank": SEVERITY_TO_RANK.get(sev, 50.0),
        },
        "properties": {
            "tags": ["security", "tribunal", finding.get("category", "general").lower()],
            "agent": finding.get("agent", "tribunal"),
        },
    }


def _build_result(rule_id: str, finding: dict, file_path: str) -> dict:
    sev = _normalize_severity(finding.get("severity"))
    line = finding.get("line", finding.get("line_number", 1))

    result = {
        "ruleId": rule_id,
        "level": SEVERITY_TO_LEVEL.get(sev, "warning"),
        "rank": SEVERITY_TO_RANK.get(sev, 50.0),
        "message": {
            "text": finding.get("description") or finding.get("title", "Tribunal finding"),
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(line))},
            }
        }],
    }

    fix = finding.get("remediation") or finding.get("fix")
    if fix:
        result["fixes"] = [{
            "description": {"text": fix if isinstance(fix, str) else fix.get("text", "")},
        }]

    return result


def verdict_to_sarif(
    verdict_data: dict,
    file_path: str = "analyzed_file.py",
    repo_uri: str = "https://github.com/yogeswary/shiftleft-society",
    version: str = "2.0.0",
) -> dict:
    """
    Convert a tribunal verdict dict to SARIF 2.1.0 JSON.

    Expected verdict_data shape (flexible — extra keys ignored):
      {
        "verdict": "REJECT" | "APPROVE" | "REVIEW",
        "severity": "CRITICAL",
        "findings": [
          {"title": "...", "description": "...", "severity": "HIGH",
           "category": "SQLInjection", "line": 23, "remediation": "..."}
        ],
        "agents": ["security_auditor", "performance_analyst", "mediator"]
      }
    """
    findings = verdict_data.get("findings", [])

    rules = []
    results = []
    seen_rules = set()

    for idx, finding in enumerate(findings, start=1):
        rule_id = f"SLS{idx:04d}"
        if rule_id not in seen_rules:
            rules.append(_build_rule(rule_id, finding))
            seen_rules.add(rule_id)
        results.append(_build_result(rule_id, finding, file_path))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ShiftLeft Society",
                    "fullName": "ShiftLeft Society Multi-Agent DevSecOps Tribunal",
                    "version": version,
                    "informationUri": repo_uri,
                    "rules": rules,
                    "properties": {
                        "agents": verdict_data.get("agents", []),
                        "verdict": verdict_data.get("verdict", "UNKNOWN"),
                    },
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }],
            "properties": {
                "overall_severity": verdict_data.get("severity", "UNKNOWN"),
                "overall_verdict": verdict_data.get("verdict", "UNKNOWN"),
            },
        }],
    }


def verdict_to_sarif_json(verdict_data: dict, **kwargs) -> str:
    """Return formatted JSON string."""
    return json.dumps(verdict_to_sarif(verdict_data, **kwargs), indent=2)
