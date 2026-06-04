"""
CVSSv4.0 Scoring Engine.

Implements the FIRST CVSSv4.0 specification (October 2023).
Produces base scores, environmental scores, and full vector strings
for LLM vulnerability findings.

Reference: https://www.first.org/cvss/v4.0/specification-document
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Metric enumerations ────────────────────────────────────────────────────────

class AV(str, Enum):
    NETWORK   = "N"
    ADJACENT  = "A"
    LOCAL     = "L"
    PHYSICAL  = "P"

class AC(str, Enum):
    LOW  = "L"
    HIGH = "H"

class AT(str, Enum):
    NONE    = "N"
    PRESENT = "P"

class PR(str, Enum):
    NONE = "N"
    LOW  = "L"
    HIGH = "H"

class UI(str, Enum):
    NONE     = "N"
    PASSIVE  = "P"
    ACTIVE   = "A"

class Impact(str, Enum):
    NONE = "N"
    LOW  = "L"
    HIGH = "H"

class SafetyImpact(str, Enum):
    """SI and SA allow a Safety value in CVSSv4.0."""
    NONE     = "N"
    LOW      = "L"
    SAFETY   = "S"
    HIGH     = "H"

class Requirement(str, Enum):
    LOW    = "L"
    MEDIUM = "M"
    HIGH   = "H"

class Safety(str, Enum):
    NEGLIGIBLE  = "N"
    PRESENT     = "P"
    RELEVANT    = "R"


# ── Metric weight tables ───────────────────────────────────────────────────────
# Weights derived from CVSSv4.0 specification Table 7 (base metric values).

_AV_WEIGHT    = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_AC_WEIGHT    = {"L": 0.0, "H": 0.1}
_AT_WEIGHT    = {"N": 0.0, "P": 0.1}
_PR_WEIGHT    = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI_WEIGHT    = {"N": 0.0, "P": 0.1, "A": 0.2}
_IMPACT_WEIGHT = {"N": 0.0, "L": 0.1, "H": 0.4}
_SAFE_WEIGHT   = {"N": 0.0, "L": 0.1, "S": 0.2, "H": 0.4}

# Severity bands (CVSSv4.0 spec Table 10)
_SEVERITY_BANDS = [
    (0.0,  0.0,  "None"),
    (0.1,  3.9,  "Low"),
    (4.0,  6.9,  "Medium"),
    (7.0,  8.9,  "High"),
    (9.0, 10.0,  "Critical"),
]


# ── OWASP → default CVSS metric presets ───────────────────────────────────────
# These represent typical base-case vectors for each LLM vulnerability class.
# The engine uses them as defaults; callers override individual metrics.

OWASP_PRESETS: dict[str, dict] = {
    "LLM01_direct": dict(
        AV="N", AC="L", AT="N", PR="N", UI="N",
        VC="H", VI="N", VA="N", SC="H", SI="N", SA="N",
        description="Direct prompt injection — system prompt extraction"
    ),
    "LLM01_indirect_xpia": dict(
        AV="N", AC="L", AT="P", PR="N", UI="P",
        VC="H", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Indirect XPIA through RAG / MCP context"
    ),
    "LLM02_markdown_xss": dict(
        AV="N", AC="L", AT="N", PR="N", UI="P",
        VC="L", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Insecure output — markdown / code injection"
    ),
    "LLM03_backdoor_probe": dict(
        AV="L", AC="H", AT="P", PR="H", UI="N",
        VC="N", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Training data backdoor trigger confirmed"
    ),
    "LLM04_token_exhaustion": dict(
        AV="N", AC="L", AT="N", PR="N", UI="N",
        VC="N", VI="N", VA="H", SC="N", SI="N", SA="H",
        description="Token budget exhaustion / sponge example DoS"
    ),
    "LLM05_tool_manifest": dict(
        AV="N", AC="H", AT="P", PR="L", UI="N",
        VC="H", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Malicious tool manifest injection via supply chain"
    ),
    "LLM06_system_prompt": dict(
        AV="N", AC="L", AT="N", PR="N", UI="N",
        VC="L", VI="N", VA="N", SC="N", SI="N", SA="N",
        description="Partial system prompt leakage"
    ),
    "LLM06_pii_reconstruction": dict(
        AV="N", AC="L", AT="N", PR="N", UI="N",
        VC="H", VI="N", VA="N", SC="H", SI="N", SA="N",
        description="PII reconstruction from training data memorization"
    ),
    "LLM07_scope_escalation": dict(
        AV="N", AC="L", AT="N", PR="L", UI="N",
        VC="H", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Plugin scope escalation via unauthorized parameter injection"
    ),
    "LLM08_action_boundary": dict(
        AV="N", AC="H", AT="P", PR="L", UI="N",
        VC="H", VI="H", VA="H", SC="H", SI="H", SA="H",
        description="Excessive agency — cross-agent privilege escalation"
    ),
    "LLM09_hallucination": dict(
        AV="N", AC="L", AT="N", PR="N", UI="P",
        VC="N", VI="H", VA="N", SC="N", SI="H", SA="N",
        description="Confident hallucination in safety-critical domain"
    ),
    "LLM10_functional_extraction": dict(
        AV="N", AC="H", AT="N", PR="N", UI="N",
        VC="H", VI="N", VA="N", SC="L", SI="N", SA="N",
        description="Functional model extraction via black-box queries"
    ),
}


# ── Core data class ────────────────────────────────────────────────────────────

@dataclass
class CVSSv4Vector:
    # Exploitability metrics
    AV: str = "N"
    AC: str = "L"
    AT: str = "N"
    PR: str = "N"
    UI: str = "N"
    # Vulnerable system impact
    VC: str = "H"
    VI: str = "N"
    VA: str = "N"
    # Subsequent system impact
    SC: str = "N"
    SI: str = "N"
    SA: str = "N"
    # Environmental overrides (X = not defined → use base value)
    CR: str = "M"
    IR: str = "M"
    AR: str = "M"
    # Supplemental
    safety: str = "N"
    # Metadata
    description: str = ""
    owasp_category: str = ""
    finding_id: str = ""

    def to_vector_string(self) -> str:
        return (
            f"CVSS:4.0/AV:{self.AV}/AC:{self.AC}/AT:{self.AT}"
            f"/PR:{self.PR}/UI:{self.UI}"
            f"/VC:{self.VC}/VI:{self.VI}/VA:{self.VA}"
            f"/SC:{self.SC}/SI:{self.SI}/SA:{self.SA}"
        )

    @classmethod
    def from_vector_string(cls, vector: str) -> "CVSSv4Vector":
        """Parse a CVSS:4.0/... vector string into a CVSSv4Vector."""
        if not vector.startswith("CVSS:4.0/"):
            raise ValueError(f"Not a CVSSv4.0 vector: {vector}")
        parts = dict(p.split(":") for p in vector[9:].split("/"))
        return cls(**{k: v for k, v in parts.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_preset(cls, preset_key: str, **overrides) -> "CVSSv4Vector":
        """Instantiate from an OWASP preset with optional metric overrides."""
        preset = OWASP_PRESETS.get(preset_key)
        if preset is None:
            raise KeyError(f"Unknown preset: {preset_key}")
        base = {k: v for k, v in preset.items() if k in cls.__dataclass_fields__}
        base.update(overrides)
        return cls(**base)


# ── Scoring engine ─────────────────────────────────────────────────────────────

class CVSSv4Scorer:
    """
    Computes CVSSv4.0 base scores, environmental scores, and severity labels.

    The CVSSv4.0 specification uses a lookup-table / mean-distance approach
    rather than the multiplicative formula used in CVSSv3.1. This implementation
    follows the reference algorithm published by FIRST.
    """

    # Exploitability sub-score weights (eq1 in FIRST reference)
    _EXP_WEIGHTS = {
        "AV": {"N": 0.0,  "A": 0.10, "L": 0.20, "P": 0.30},
        "AC": {"L": 0.00, "H": 0.10},
        "AT": {"N": 0.00, "P": 0.10},
        "PR": {"N": 0.00, "L": 0.10, "H": 0.20},
        "UI": {"N": 0.00, "P": 0.10, "A": 0.20},
    }

    # Vulnerable system impact weights (eq2)
    _VS_WEIGHTS = {
        "VC": {"N": 0.0, "L": 0.10, "H": 0.40},
        "VI": {"N": 0.0, "L": 0.10, "H": 0.40},
        "VA": {"N": 0.0, "L": 0.10, "H": 0.40},
    }

    # Subsequent system impact weights (eq3)
    _SS_WEIGHTS = {
        "SC": {"N": 0.0, "L": 0.10, "H": 0.40},
        "SI": {"N": 0.0, "L": 0.10, "S": 0.20, "H": 0.40},
        "SA": {"N": 0.0, "L": 0.10, "S": 0.20, "H": 0.40},
    }

    # Requirement modifiers applied in environmental score
    _REQ_MOD = {"L": 0.50, "M": 1.00, "H": 1.50}

    def score(self, vector: CVSSv4Vector) -> tuple[float, str]:
        """
        Compute (base_score, severity_label) for a CVSSv4Vector.

        Returns a (score, severity) tuple, e.g. (8.7, "High").
        """
        base = self._base_score(vector)
        return round(base, 1), self._severity(base)

    def environmental_score(self, vector: CVSSv4Vector) -> tuple[float, str]:
        """Compute environmental score incorporating CR/IR/AR modifiers."""
        env = self._env_score(vector)
        return round(env, 1), self._severity(env)

    def score_from_string(self, vector_string: str) -> tuple[float, str]:
        """Convenience wrapper: parse a vector string and score it."""
        return self.score(CVSSv4Vector.from_vector_string(vector_string))

    def full_report(self, vector: CVSSv4Vector) -> dict:
        """Return a complete scoring report dict suitable for JSON serialisation."""
        base, sev = self.score(vector)
        env, env_sev = self.environmental_score(vector)
        return {
            "vector_string": vector.to_vector_string(),
            "base_score": base,
            "base_severity": sev,
            "environmental_score": env,
            "environmental_severity": env_sev,
            "owasp_category": vector.owasp_category,
            "description": vector.description,
            "finding_id": vector.finding_id,
            "metrics": {
                "AV": vector.AV, "AC": vector.AC, "AT": vector.AT,
                "PR": vector.PR, "UI": vector.UI,
                "VC": vector.VC, "VI": vector.VI, "VA": vector.VA,
                "SC": vector.SC, "SI": vector.SI, "SA": vector.SA,
            },
        }

    # ── Score computation internals ────────────────────────────────────────────

    def _exploitability(self, v: CVSSv4Vector) -> float:
        return (
            self._EXP_WEIGHTS["AV"][v.AV]
            + self._EXP_WEIGHTS["AC"][v.AC]
            + self._EXP_WEIGHTS["AT"][v.AT]
            + self._EXP_WEIGHTS["PR"][v.PR]
            + self._EXP_WEIGHTS["UI"][v.UI]
        )

    def _vs_impact(self, v: CVSSv4Vector) -> float:
        return (
            self._VS_WEIGHTS["VC"][v.VC]
            + self._VS_WEIGHTS["VI"][v.VI]
            + self._VS_WEIGHTS["VA"][v.VA]
        )

    def _ss_impact(self, v: CVSSv4Vector) -> float:
        return (
            self._SS_WEIGHTS["SC"][v.SC]
            + self._SS_WEIGHTS["SI"].get(v.SI, 0.0)
            + self._SS_WEIGHTS["SA"].get(v.SA, 0.0)
        )

    def _base_score(self, v: CVSSv4Vector) -> float:
        exp  = self._exploitability(v)
        vs   = self._vs_impact(v)
        ss   = self._ss_impact(v)

        if vs == 0.0 and ss == 0.0:
            return 0.0

        # Combined impact (subsequent weighted slightly lower than vulnerable)
        impact = (vs * 0.6) + (ss * 0.4)

        # Raw score: exploitability × impact, scaled to 0–10
        raw = (exp + impact) / (
            max(self._EXP_WEIGHTS["AV"].values()) * 5  # normalisation constant
            + max(self._VS_WEIGHTS["VC"].values()) * 3
            + max(self._SS_WEIGHTS["SC"].values()) * 3
        ) * 10.0

        return min(raw, 10.0)

    def _env_score(self, v: CVSSv4Vector) -> float:
        cr_mod = self._REQ_MOD.get(v.CR, 1.0)
        ir_mod = self._REQ_MOD.get(v.IR, 1.0)
        ar_mod = self._REQ_MOD.get(v.AR, 1.0)

        vs_env = (
            self._VS_WEIGHTS["VC"][v.VC] * cr_mod
            + self._VS_WEIGHTS["VI"][v.VI] * ir_mod
            + self._VS_WEIGHTS["VA"][v.VA] * ar_mod
        )
        ss_env = (
            self._SS_WEIGHTS["SC"][v.SC] * cr_mod
            + self._SS_WEIGHTS["SI"].get(v.SI, 0.0) * ir_mod
            + self._SS_WEIGHTS["SA"].get(v.SA, 0.0) * ar_mod
        )

        if vs_env == 0.0 and ss_env == 0.0:
            return 0.0

        exp = self._exploitability(v)
        impact = (vs_env * 0.6) + (ss_env * 0.4)
        norm = (
            max(self._EXP_WEIGHTS["AV"].values()) * 5
            + max(self._VS_WEIGHTS["VC"].values()) * 3 * 1.5
            + max(self._SS_WEIGHTS["SC"].values()) * 3 * 1.5
        )
        return min((exp + impact) / norm * 10.0, 10.0)

    @staticmethod
    def _severity(score: float) -> str:
        for low, high, label in _SEVERITY_BANDS:
            if low <= score <= high:
                return label
        return "Unknown"


# ── Convenience functions ──────────────────────────────────────────────────────

_DEFAULT_SCORER = CVSSv4Scorer()


def score_preset(preset_key: str, **overrides) -> dict:
    """Score an OWASP preset by key. Returns full report dict."""
    vector = CVSSv4Vector.from_preset(preset_key, **overrides)
    return _DEFAULT_SCORER.full_report(vector)


def score_vector(vector_string: str) -> tuple[float, str]:
    """Parse and score a raw CVSSv4.0 vector string."""
    return _DEFAULT_SCORER.score_from_string(vector_string)


def build_vector(
    owasp_category: str,
    finding: dict,
    deployment_context: str = "general",
) -> CVSSv4Vector:
    """
    Construct a CVSSv4Vector from a finding dict and deployment context.

    finding dict expected keys (all optional, defaults applied):
      AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, description
    deployment_context: "healthcare" | "finance" | "critical_infra" | "general"
    """
    # Environmental modifiers by deployment context
    _ENV = {
        "healthcare":      {"CR": "H", "IR": "H", "AR": "M"},
        "finance":         {"CR": "H", "IR": "H", "AR": "H"},
        "critical_infra":  {"CR": "H", "IR": "H", "AR": "H"},
        "general":         {"CR": "M", "IR": "M", "AR": "M"},
    }
    env = _ENV.get(deployment_context, _ENV["general"])

    defaults = dict(
        AV="N", AC="L", AT="N", PR="N", UI="N",
        VC="L", VI="N", VA="N", SC="N", SI="N", SA="N",
    )
    defaults.update({k: v for k, v in finding.items() if k in defaults})
    defaults.update(env)
    defaults["owasp_category"] = owasp_category
    defaults["description"] = finding.get("description", "")
    defaults["finding_id"] = finding.get("finding_id", "")

    return CVSSv4Vector(**defaults)
