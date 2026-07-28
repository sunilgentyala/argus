"""
Regression tests for the CVSSv4.0 scoring engine.

Expected scores are ground truth taken from the official FIRST CVSS v4.0
reference calculator (FIRSTdotorg/cvss-v4-calculator), verified during the
ICCVBIC-383 camera-ready revision. A prior version of CVSSv4Scorer used an
ad-hoc linear-weighted approximation that deviated from the reference
implementation by a mean of 4.7 points (max 7.5) across a 48-vector
battery; these cases guard against regressing back to that approximation.
"""
from argus.scoring.cvss4 import CVSSv4Scorer, CVSSv4Vector

REFERENCE_VECTORS = [
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L", 2.4),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.1),
    ("CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H", 7.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 6.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", 7.9),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.5),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 5.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7),
]


def test_matches_official_reference_calculator():
    scorer = CVSSv4Scorer()
    for vector_string, expected in REFERENCE_VECTORS:
        score, _ = scorer.score_from_string(vector_string)
        assert score == expected, f"{vector_string}: got {score}, expected {expected}"


def test_zero_impact_vector_scores_zero():
    scorer = CVSSv4Scorer()
    vector = CVSSv4Vector(VC="N", VI="N", VA="N", SC="N", SI="N", SA="N")
    score, severity = scorer.score(vector)
    assert score == 0.0
    assert severity == "None"


def test_base_score_ignores_vector_cr_ir_ar():
    """Base score must equal the Base-metrics-only score regardless of what
    CR/IR/AR happen to be set to on the vector object (those are
    Environmental metrics and must only affect environmental_score())."""
    scorer = CVSSv4Scorer()
    v_default = CVSSv4Vector(AV="N", AC="L", AT="N", PR="N", UI="N",
                              VC="H", VI="N", VA="N", SC="H", SI="N", SA="N")
    v_with_cr = CVSSv4Vector(AV="N", AC="L", AT="N", PR="N", UI="N",
                              VC="H", VI="N", VA="N", SC="H", SI="N", SA="N",
                              CR="L", IR="L", AR="L")
    assert scorer.score(v_default) == scorer.score(v_with_cr)


def test_environmental_score_reflects_cr_ir_ar_override():
    scorer = CVSSv4Scorer()
    base = CVSSv4Vector(AV="N", AC="L", AT="N", PR="N", UI="N",
                         VC="H", VI="N", VA="N", SC="N", SI="N", SA="N",
                         CR="H", IR="H", AR="H")
    lowered = CVSSv4Vector(AV="N", AC="L", AT="N", PR="N", UI="N",
                            VC="H", VI="N", VA="N", SC="N", SI="N", SA="N",
                            CR="L", IR="L", AR="L")
    env_base, _ = scorer.environmental_score(base)
    env_lowered, _ = scorer.environmental_score(lowered)
    assert env_base >= env_lowered
