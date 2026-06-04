"""
SARIF v2.1 reporter — native GitHub Actions / GitLab CI / Azure DevOps output.

Produces a SARIF 2.1.0 JSON file from an ARGUS session, enabling zero-config
integration with any CI/CD platform that supports the SARIF standard.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from argus.core.session import SessionState, Finding

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "ARGUS"
_TOOL_VERSION = "1.0.0"
_TOOL_URI = "https://github.com/sunilgentyala/argus"

_SEVERITY_MAP = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
    "None":     "none",
}


def _finding_to_result(finding: Finding) -> dict:
    return {
        "ruleId": finding.owasp_category,
        "level": _SEVERITY_MAP.get(finding.cvss_severity, "warning"),
        "message": {
            "text": (
                f"{finding.owasp_category} confirmed via {finding.strategy} "
                f"on surface '{finding.surface}'. "
                f"CVSS {finding.cvss_base_score} ({finding.cvss_severity}). "
                f"Vector: {finding.cvss_vector}"
            )
        },
        "properties": {
            "finding_id": finding.finding_id,
            "surface": finding.surface,
            "strategy": finding.strategy,
            "detection_layer": finding.detection_layer,
            "cvss_vector": finding.cvss_vector,
            "cvss_base_score": finding.cvss_base_score,
            "compliance_tags": finding.compliance_tags,
            "timestamp": finding.timestamp,
        },
    }


def _owasp_rule(category: str) -> dict:
    descriptions = {
        "LLM01": "Prompt Injection — direct, indirect, or cross-prompt injection attack",
        "LLM02": "Insecure Output Handling — unsafe rendering of LLM-generated content",
        "LLM03": "Training Data Poisoning — backdoor or integrity attack on training data",
        "LLM04": "Model Denial of Service — resource exhaustion via adversarial input",
        "LLM05": "Supply Chain Vulnerabilities — compromise via third-party components",
        "LLM06": "Sensitive Information Disclosure — leakage of protected system data",
        "LLM07": "Insecure Plugin Design — scope escalation via tool or plugin abuse",
        "LLM08": "Excessive Agency — agent actions beyond authorised scope",
        "LLM09": "Overreliance — induced hallucination in safety-critical contexts",
        "LLM10": "Model Theft — functional extraction via black-box query abuse",
    }
    return {
        "id": category,
        "name": category,
        "shortDescription": {"text": descriptions.get(category, category)},
        "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/#{category.lower()}",
        "properties": {"tags": ["security", "llm", "owasp"]},
    }


class SARIFReporter:
    def generate(self, session: SessionState, output_path: str | None = None) -> dict:
        confirmed = session.confirmed_findings()
        rules_used = list({f.owasp_category for f in confirmed})

        sarif = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": _TOOL_URI,
                            "rules": [_owasp_rule(r) for r in sorted(rules_used)],
                        }
                    },
                    "results": [_finding_to_result(f) for f in confirmed],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": session.started_at,
                            "endTimeUtc": session.completed_at
                                or datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "properties": {
                        "session_id": session.session_id,
                        "scan_profile": session.scan_profile,
                        "payloads_sent": session.payloads_sent,
                    },
                }
            ],
        }

        if output_path:
            Path(output_path).write_text(
                json.dumps(sarif, indent=2), encoding="utf-8"
            )
        return sarif
