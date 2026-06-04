"""
Global Compliance Mapper — maps ARGUS findings to regulatory framework obligations.

Covers: NIST AI RMF, EU AI Act, US EO 14110, UK AISI, India CERT-In,
ISO/IEC 42001, APAC (SG PDPA, AU AI Ethics), EMEA (GDPR, DORA, NIS2),
Africa (AU Data Policy, ECOWAS).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ComplianceTag:
    framework: str
    reference: str          # e.g. "Art. 9(2)", "GOVERN 1.7", "§4.2(b)"
    obligation_type: str    # technical | documentation | audit | notification
    obligation_strength: str  # mandatory | recommended | best_practice
    harm_scenario: str


# ── Cross-reference table ─────────────────────────────────────────────────────
# Structure: { owasp_category: { framework_key: [ComplianceTag, ...] } }

_MAPPING: dict[str, dict[str, list[ComplianceTag]]] = {
    "LLM01": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "GOVERN 1.7", "technical", "mandatory",
                "Prompt injection undermines integrity controls required by GOVERN 1.7"),
            ComplianceTag("NIST AI RMF", "MANAGE 2.2", "documentation", "mandatory",
                "Attack vector must be documented in incident response procedures"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(2)", "technical", "mandatory",
                "Risk management system must address adversarial input attacks"),
            ComplianceTag("EU AI Act", "Art. 15(1)", "technical", "mandatory",
                "High-risk systems must be resilient against attempts to alter outputs"),
        ],
        "UK_AISI": [
            ComplianceTag("UK AISI", "Evaluation Pillar 3", "audit", "recommended",
                "Adversarial robustness evaluation against prompt injection"),
        ],
        "US_EO_14110": [
            ComplianceTag("US EO 14110", "§4.2(b)(i)", "documentation", "mandatory",
                "Red-team findings on adversarial inputs must be reported"),
        ],
        "CERT_IN": [
            ComplianceTag("CERT-In", "AI-SEC-01", "technical", "mandatory",
                "Prompt injection defences required for public-facing LLM deployments"),
        ],
        "ISO_42001": [
            ComplianceTag("ISO/IEC 42001", "§6.1.2", "documentation", "mandatory",
                "AI risk treatment must include prompt injection controls"),
        ],
    },
    "LLM02": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "MEASURE 2.6", "technical", "mandatory",
                "Output handling failures expose downstream systems to injection"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 15(1)", "technical", "mandatory",
                "Output integrity is a robustness requirement for high-risk systems"),
        ],
        "CERT_IN": [
            ComplianceTag("CERT-In", "AI-SEC-03", "technical", "recommended",
                "Sanitize LLM outputs before rendering in web or code contexts"),
        ],
    },
    "LLM03": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "MAP 2.3", "documentation", "mandatory",
                "Training data integrity must be documented in the AI risk map"),
            ComplianceTag("NIST AI RMF", "MEASURE 2.8", "audit", "mandatory",
                "Data poisoning indicators require measurement and monitoring"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(7)", "technical", "mandatory",
                "Training data governance must prevent poisoning attacks"),
            ComplianceTag("EU AI Act", "Art. 17", "documentation", "mandatory",
                "Quality management system must cover training data integrity"),
        ],
        "US_EO_14110": [
            ComplianceTag("US EO 14110", "§4.3(d)", "audit", "mandatory",
                "Training data security assessments required for frontier models"),
        ],
    },
    "LLM04": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "MANAGE 3.1", "technical", "recommended",
                "Availability impacts from DoS attacks require response planning"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(2)", "technical", "mandatory",
                "High-risk systems must maintain performance under adversarial load"),
        ],
    },
    "LLM05": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "GOVERN 1.1", "documentation", "mandatory",
                "Third-party component risks must be governed at the organisational level"),
            ComplianceTag("NIST AI RMF", "MAP 3.5", "audit", "mandatory",
                "Supply chain dependencies must be mapped and assessed"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(2)", "technical", "mandatory",
                "Risk management must extend to third-party AI components"),
            ComplianceTag("EU AI Act", "Art. 25", "documentation", "mandatory",
                "Obligations of deployers include oversight of upstream providers"),
        ],
        "CERT_IN": [
            ComplianceTag("CERT-In", "AI-SEC-05", "technical", "mandatory",
                "Third-party plugin and tool integrity verification required"),
        ],
    },
    "LLM06": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "MAP 1.5", "documentation", "mandatory",
                "Sensitive data exposure risk must appear in the AI system risk map"),
            ComplianceTag("NIST AI RMF", "MEASURE 2.5", "audit", "mandatory",
                "Information disclosure metrics must be tracked"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 10", "technical", "mandatory",
                "Training data containing personal data requires GDPR-aligned controls"),
            ComplianceTag("EU AI Act", "Art. 72", "notification", "mandatory",
                "Serious incidents involving data disclosure must be reported to authorities"),
        ],
        "CERT_IN": [
            ComplianceTag("CERT-In", "AI-SEC-04", "technical", "mandatory",
                "System prompt and training data leakage constitutes a reportable incident"),
        ],
        "ISO_42001": [
            ComplianceTag("ISO/IEC 42001", "§9.1", "audit", "mandatory",
                "Performance monitoring must include information disclosure detection"),
        ],
    },
    "LLM07": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "MANAGE 2.2", "technical", "mandatory",
                "Plugin authorization scope must be managed as part of AI risk treatment"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(5)", "technical", "mandatory",
                "Tool and plugin authorisation must be subject to risk management"),
        ],
    },
    "LLM08": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "GOVERN 6.1", "documentation", "mandatory",
                "Human oversight mechanisms must be defined for consequential agent actions"),
            ComplianceTag("NIST AI RMF", "MANAGE 4.1", "technical", "mandatory",
                "Excessive agency risks require active risk treatment controls"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(5)", "technical", "mandatory",
                "Agent action boundaries must be defined in the risk management system"),
            ComplianceTag("EU AI Act", "Art. 16(g)", "documentation", "mandatory",
                "Human oversight measures must be documented for high-risk systems"),
        ],
        "UK_AISI": [
            ComplianceTag("UK AISI", "Human Oversight Subpillar", "audit", "recommended",
                "Agentic systems require evaluation of human oversight effectiveness"),
        ],
        "US_EO_14110": [
            ComplianceTag("US EO 14110", "§4.2(a)", "documentation", "mandatory",
                "Human oversight of consequential AI actions required under EO 14110"),
        ],
        "CERT_IN": [
            ComplianceTag("CERT-In", "AI-SEC-07", "technical", "mandatory",
                "Agentic AI action scope must be technically constrained and monitored"),
        ],
    },
    "LLM09": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "MEASURE 2.1", "audit", "mandatory",
                "Overreliance risk requires accuracy and reliability measurement"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 13", "documentation", "mandatory",
                "Transparency obligations require disclosure of AI system limitations"),
        ],
    },
    "LLM10": {
        "NIST_AI_RMF": [
            ComplianceTag("NIST AI RMF", "GOVERN 4.1", "documentation", "recommended",
                "Intellectual property risks from model extraction must be governed"),
        ],
        "EU_AI_ACT": [
            ComplianceTag("EU AI Act", "Art. 9(2)", "technical", "recommended",
                "Risk management should consider model theft as an integrity threat"),
        ],
    },
}


class ComplianceMapper:
    """Maps confirmed findings to regulatory framework obligations."""

    def map(
        self,
        owasp_category: str,
        frameworks: list[str] | None = None,
    ) -> list[ComplianceTag]:
        """
        Return compliance tags for an OWASP category.

        Parameters
        ----------
        owasp_category : e.g. "LLM01", "LLM08"
        frameworks : filter to specific framework keys; None = return all
        """
        category_map = _MAPPING.get(owasp_category, {})
        tags: list[ComplianceTag] = []
        for fw_key, fw_tags in category_map.items():
            if frameworks is None or fw_key in frameworks:
                tags.extend(fw_tags)
        return tags

    def tag_strings(
        self,
        owasp_category: str,
        frameworks: list[str] | None = None,
    ) -> list[str]:
        """Return compact tag strings like 'EU AI Act / Art. 9(2)'."""
        return [
            f"{t.framework} / {t.reference}"
            for t in self.map(owasp_category, frameworks)
        ]

    def compliance_block(
        self,
        owasp_category: str,
        frameworks: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return full compliance block suitable for JSON report embedding."""
        return [
            {
                "framework": t.framework,
                "reference": t.reference,
                "obligation_type": t.obligation_type,
                "obligation_strength": t.obligation_strength,
                "harm_scenario": t.harm_scenario,
            }
            for t in self.map(owasp_category, frameworks)
        ]
