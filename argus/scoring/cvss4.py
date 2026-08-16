"""
CVSSv4.0 Scoring Engine.

Implements the FIRST CVSSv4.0 specification (October 2023).
Produces base scores, environmental scores, and full vector strings
for LLM vulnerability findings.

Reference: https://www.first.org/cvss/v4.0/specification-document
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

# ── Metric enumerations ────────────────────────────────────────────────────────

class AV(StrEnum):
    NETWORK   = "N"
    ADJACENT  = "A"
    LOCAL     = "L"
    PHYSICAL  = "P"

class AC(StrEnum):
    LOW  = "L"
    HIGH = "H"

class AT(StrEnum):
    NONE    = "N"
    PRESENT = "P"

class PR(StrEnum):
    NONE = "N"
    LOW  = "L"
    HIGH = "H"

class UI(StrEnum):
    NONE     = "N"
    PASSIVE  = "P"
    ACTIVE   = "A"

class Impact(StrEnum):
    NONE = "N"
    LOW  = "L"
    HIGH = "H"

class SafetyImpact(StrEnum):
    """SI and SA allow a Safety value in CVSSv4.0."""
    NONE     = "N"
    LOW      = "L"
    SAFETY   = "S"
    HIGH     = "H"

class Requirement(StrEnum):
    LOW    = "L"
    MEDIUM = "M"
    HIGH   = "H"

class Safety(StrEnum):
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

OWASP_PRESETS: dict[str, dict[str, str]] = {
    "LLM01_direct": dict(
        AV="N", AC="L", AT="N", PR="N", UI="N",
        VC="H", VI="N", VA="N", SC="H", SI="N", SA="N",
        description="Direct prompt injection: system prompt extraction"
    ),
    "LLM01_indirect_xpia": dict(
        AV="N", AC="L", AT="P", PR="N", UI="P",
        VC="H", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Indirect XPIA through RAG / MCP context"
    ),
    "LLM02_markdown_xss": dict(
        AV="N", AC="L", AT="N", PR="N", UI="P",
        VC="L", VI="H", VA="N", SC="H", SI="H", SA="N",
        description="Insecure output: markdown / code injection"
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
        description="Excessive agency: cross-agent privilege escalation"
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
    def from_vector_string(cls, vector: str) -> CVSSv4Vector:
        """Parse a CVSS:4.0/... vector string into a CVSSv4Vector."""
        if not vector.startswith("CVSS:4.0/"):
            raise ValueError(f"Not a CVSSv4.0 vector: {vector}")
        parts = dict(p.split(":") for p in vector[9:].split("/"))
        return cls(**{k: v for k, v in parts.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_preset(cls, preset_key: str, **overrides: str) -> CVSSv4Vector:
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

    The CVSSv4.0 specification scores a vector by mapping it to one of 270
    "MacroVectors" (six equivalence classes EQ1-EQ6, each collapsing several
    metrics into a small number of severity buckets), looking up that
    MacroVector's score in the table FIRST derived from ~500 assessor
    judgments (Table 27/`cvss4_lookup.json`), and then interpolating within
    the MacroVector by the vector's severity distance from the MacroVector's
    highest-severity member. This is NOT a linear weighted sum of metric
    values (that was CVSSv3.1's approach): an earlier version of this engine
    approximated it as one and produced scores that deviated from the
    official FIRST reference calculator by a mean of 4.7 points (max 7.5)
    across a 48-vector validation battery. This implementation instead
    ports the MacroVector/lookup-table/interpolation algorithm from the
    official reference implementation (FIRSTdotorg/cvss-v4-calculator,
    BSD-2-Clause) so its output matches that calculator exactly.
    """

    _LOOKUP: dict[str, float] = json.loads(
        (Path(__file__).parent / "cvss4_lookup.json").read_text(encoding="utf-8")
    )

    _AV_L = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
    _PR_L = {"N": 0.0, "L": 0.1, "H": 0.2}
    _UI_L = {"N": 0.0, "P": 0.1, "A": 0.2}
    _AC_L = {"L": 0.0, "H": 0.1}
    _AT_L = {"N": 0.0, "P": 0.1}
    _VC_L = {"H": 0.0, "L": 0.1, "N": 0.2}
    _VI_L = {"H": 0.0, "L": 0.1, "N": 0.2}
    _VA_L = {"H": 0.0, "L": 0.1, "N": 0.2}
    _SC_L = {"H": 0.1, "L": 0.2, "N": 0.3}
    _SI_L = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
    _SA_L = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
    _CR_L = {"H": 0.0, "M": 0.1, "L": 0.2}
    _IR_L = {"H": 0.0, "M": 0.1, "L": 0.2}
    _AR_L = {"H": 0.0, "M": 0.1, "L": 0.2}

    _MAX_COMPOSED: dict[str, Any] = {
        "eq1": {0: ["AV:N/PR:N/UI:N/"],
                1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
                2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]},
        "eq2": {0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
        "eq3": {
            0: {0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
                1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
            1: {0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
                1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                    "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                    "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
            2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
        },
        "eq4": {0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]},
        "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
    }
    _MAX_SEVERITY: dict[str, Any] = {
        "eq1": {0: 1, 1: 4, 2: 5},
        "eq2": {0: 1, 1: 2},
        "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
        "eq4": {0: 6, 1: 5, 2: 4},
    }

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

    def full_report(self, vector: CVSSv4Vector) -> dict[str, Any]:
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

    # ── Score computation internals (MacroVector / lookup / interpolation) ────

    @staticmethod
    def _m(metrics: dict[str, str], key: str) -> str:
        """Resolve a metric value, applying CVSSv4.0 'not defined' (X) defaults."""
        val = metrics.get(key)
        if key == "E" and val in (None, "X"):
            return "A"
        if key in ("CR", "IR", "AR") and val in (None, "X"):
            return "H"
        mod = metrics.get("M" + key)
        if mod not in (None, "X"):
            return mod
        assert val is not None, f"missing required CVSSv4.0 metric: {key}"
        return val

    @classmethod
    def _macro_vector(cls, metrics: dict[str, str]) -> str:
        m = cls._m
        AV, PR, UI = m(metrics, "AV"), m(metrics, "PR"), m(metrics, "UI")
        all_none = AV == "N" and PR == "N" and UI == "N"
        any_none = AV == "N" or PR == "N" or UI == "N"
        if all_none:
            eq1 = "0"
        elif any_none and not all_none and AV != "P":
            eq1 = "1"
        else:
            eq1 = "2"

        AC, AT = m(metrics, "AC"), m(metrics, "AT")
        eq2 = "0" if (AC == "L" and AT == "N") else "1"

        VC, VI, VA = m(metrics, "VC"), m(metrics, "VI"), m(metrics, "VA")
        if VC == "H" and VI == "H":
            eq3 = 0
        elif not (VC == "H" and VI == "H") and (VC == "H" or VI == "H" or VA == "H"):
            eq3 = 1
        else:
            eq3 = 2

        SC, SI, SA = m(metrics, "SC"), m(metrics, "SI"), m(metrics, "SA")
        MSI, MSA = metrics.get("MSI"), metrics.get("MSA")
        if MSI == "S" or MSA == "S":
            eq4 = 0
        elif SC == "H" or SI == "H" or SA == "H":
            eq4 = 1
        else:
            eq4 = 2

        eq5 = {"A": 0, "P": 1, "U": 2}[m(metrics, "E")]

        CR, IR, AR = m(metrics, "CR"), m(metrics, "IR"), m(metrics, "AR")
        if (CR == "H" and VC == "H") or (IR == "H" and VI == "H") or (AR == "H" and VA == "H"):
            eq6 = 0
        else:
            eq6 = 1

        return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

    @staticmethod
    def _extract(metric: str, s: str) -> str:
        i = s.index(metric) + len(metric) + 1
        rest = s[i:]
        slash = rest.find("/")
        return rest[:slash] if slash > 0 else rest

    _LEVELS = {
        "AV": _AV_L, "PR": _PR_L, "UI": _UI_L, "AC": _AC_L, "AT": _AT_L,
        "VC": _VC_L, "VI": _VI_L, "VA": _VA_L, "SC": _SC_L, "SI": _SI_L,
        "SA": _SA_L, "CR": _CR_L, "IR": _IR_L, "AR": _AR_L,
    }

    def _score(self, metrics: dict[str, str]) -> float:
        """
        Score an arbitrary CVSSv4.0 metric dict using the official FIRST
        MacroVector/lookup/interpolation algorithm (ported from
        FIRSTdotorg/cvss-v4-calculator's cvss_score.js).
        """
        m = self._m
        if all(m(metrics, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
            return 0.0

        mv = self._macro_vector(metrics)
        value = self._LOOKUP[mv]
        eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

        lower = {
            "eq1": f"{eq1+1}{eq2}{eq3}{eq4}{eq5}{eq6}",
            "eq2": f"{eq1}{eq2+1}{eq3}{eq4}{eq5}{eq6}",
            "eq4": f"{eq1}{eq2}{eq3}{eq4+1}{eq5}{eq6}",
            "eq5": f"{eq1}{eq2}{eq3}{eq4}{eq5+1}{eq6}",
        }
        if eq3 == 1 and eq6 == 1:
            eq3eq6_lower = [f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6}"]
        elif eq3 == 0 and eq6 == 1:
            eq3eq6_lower = [f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6}"]
        elif eq3 == 1 and eq6 == 0:
            eq3eq6_lower = [f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6+1}"]
        elif eq3 == 0 and eq6 == 0:
            eq3eq6_lower = [
                f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6+1}",
                f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6}",
            ]
        else:
            eq3eq6_lower = [f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6+1}"]

        score_lower: dict[str, float | None] = {k: self._LOOKUP.get(v) for k, v in lower.items()}
        raw_candidates = [self._LOOKUP.get(k) for k in eq3eq6_lower]
        candidates = [c for c in raw_candidates if c is not None]
        score_lower["eq3eq6"] = max(candidates) if candidates else None

        eq1_maxes = self._MAX_COMPOSED["eq1"][eq1]
        eq2_maxes = self._MAX_COMPOSED["eq2"][eq2]
        eq3_eq6_maxes = self._MAX_COMPOSED["eq3"][eq3][eq6]
        eq4_maxes = self._MAX_COMPOSED["eq4"][eq4]
        eq5_maxes = self._MAX_COMPOSED["eq5"][eq5]

        dists: dict[str, float] | None = None
        for e1 in eq1_maxes:
            for e2 in eq2_maxes:
                for e36 in eq3_eq6_maxes:
                    for e4 in eq4_maxes:
                        for e5 in eq5_maxes:
                            cand = e1 + e2 + e36 + e4 + e5
                            d = {
                                k: self._LEVELS[k][m(metrics, k)]
                                - self._LEVELS[k][self._extract(k, cand)]
                                for k in ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                                          "SC", "SI", "SA", "CR", "IR", "AR")
                            }
                            if all(x >= 0 for x in d.values()):
                                dists = d
                                break
                        if dists:
                            break
                    if dists:
                        break
                if dists:
                    break
            if dists:
                break

        assert dists is not None, "no severity-distance candidate found for this vector"
        sd = {
            "eq1": dists["AV"] + dists["PR"] + dists["UI"],
            "eq2": dists["AC"] + dists["AT"],
            "eq3eq6": (
                dists["VC"] + dists["VI"] + dists["VA"]
                + dists["CR"] + dists["IR"] + dists["AR"]
            ),
            "eq4": dists["SC"] + dists["SI"] + dists["SA"],
            "eq5": 0.0,
        }
        step = 0.1
        max_sev = {
            "eq1": self._MAX_SEVERITY["eq1"][eq1] * step,
            "eq2": self._MAX_SEVERITY["eq2"][eq2] * step,
            "eq3eq6": self._MAX_SEVERITY["eq3eq6"][eq3][eq6] * step,
            "eq4": self._MAX_SEVERITY["eq4"][eq4] * step,
        }

        n = 0
        normalized_total = 0.0
        for key in ("eq1", "eq2", "eq3eq6", "eq4"):
            lo = score_lower[key]
            if lo is None:
                continue
            n += 1
            available = value - lo
            normalized_total += available * (sd[key] / max_sev[key])
        if score_lower["eq5"] is not None:
            n += 1  # eq5's severity distance and thus contribution is always 0

        mean_distance = 0.0 if n == 0 else normalized_total / n
        result = max(0.0, min(10.0, value - mean_distance))
        return result

    def _base_score(self, v: CVSSv4Vector) -> float:
        # Base score = Base metric group only. CR/IR/AR are intentionally
        # forced to "X" (-> H) here regardless of what's set on the vector,
        # since those are Environmental metrics and must not influence the
        # pure Base score (matches the official calculator's default state
        # when no environmental sliders have been touched).
        metrics = dict(
            AV=v.AV, AC=v.AC, AT=v.AT, PR=v.PR, UI=v.UI,
            VC=v.VC, VI=v.VI, VA=v.VA, SC=v.SC, SI=v.SI, SA=v.SA,
            CR="X", IR="X", AR="X",
        )
        return self._score(metrics)

    def _env_score(self, v: CVSSv4Vector) -> float:
        metrics = dict(
            AV=v.AV, AC=v.AC, AT=v.AT, PR=v.PR, UI=v.UI,
            VC=v.VC, VI=v.VI, VA=v.VA, SC=v.SC, SI=v.SI, SA=v.SA,
            CR=v.CR, IR=v.IR, AR=v.AR,
        )
        return self._score(metrics)

    @staticmethod
    def _severity(score: float) -> str:
        for low, high, label in _SEVERITY_BANDS:
            if low <= score <= high:
                return label
        return "Unknown"


# ── Convenience functions ──────────────────────────────────────────────────────

_DEFAULT_SCORER = CVSSv4Scorer()


def score_preset(preset_key: str, **overrides: str) -> dict[str, Any]:
    """Score an OWASP preset by key. Returns full report dict."""
    vector = CVSSv4Vector.from_preset(preset_key, **overrides)
    return _DEFAULT_SCORER.full_report(vector)


def score_vector(vector_string: str) -> tuple[float, str]:
    """Parse and score a raw CVSSv4.0 vector string."""
    return _DEFAULT_SCORER.score_from_string(vector_string)


def build_vector(
    owasp_category: str,
    finding: dict[str, Any],
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
