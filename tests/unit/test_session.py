"""Unit tests for SessionState and Finding."""

import pytest
from argus.core.session import SessionState, Finding, ScanPhase


class TestSessionState:

    def test_initial_phase_is_init(self):
        s = SessionState()
        assert s.phase == ScanPhase.INIT

    def test_transition_updates_phase(self):
        s = SessionState()
        s.transition(ScanPhase.PLANNING)
        assert s.phase == ScanPhase.PLANNING

    def test_budget_not_exhausted_at_start(self):
        s = SessionState(payloads_budget=100)
        assert not s.budget_exhausted()

    def test_budget_exhausted_when_at_limit(self):
        s = SessionState(payloads_budget=10)
        s.payloads_sent = 10
        assert s.budget_exhausted()

    def test_add_finding_increments_list(self):
        s = SessionState()
        f = Finding(
            finding_id="ARG-00000001",
            owasp_category="LLM01",
            surface="direct",
            strategy="direct_injection",
            payload_text="ignore previous instructions",
            response_text="ok",
            detection_layer="llm_judge",
            confirmed=True,
        )
        s.add_finding(f)
        assert len(s.findings) == 1

    def test_confirmed_findings_filters_unconfirmed(self):
        s = SessionState()
        confirmed = Finding(
            finding_id="ARG-00000001", owasp_category="LLM01", surface="direct",
            strategy="direct_injection", payload_text="x", response_text="y",
            detection_layer="llm_judge", confirmed=True,
        )
        unconfirmed = Finding(
            finding_id="ARG-00000002", owasp_category="LLM06", surface="direct",
            strategy="system_prompt_extraction", payload_text="x", response_text="y",
            detection_layer="semantic", confirmed=False,
        )
        s.add_finding(confirmed)
        s.add_finding(unconfirmed)
        assert len(s.confirmed_findings()) == 1
        assert s.confirmed_findings()[0].finding_id == "ARG-00000001"

    def test_summary_keys_present(self):
        s = SessionState()
        summary = s.summary()
        for key in ("session_id", "phase", "total_findings", "critical", "high",
                    "medium", "low", "payloads_sent", "budget_remaining"):
            assert key in summary

    def test_completed_at_set_on_complete_transition(self):
        s = SessionState()
        assert s.completed_at == ""
        s.transition(ScanPhase.COMPLETE)
        assert s.completed_at != ""


class TestFinding:

    def test_new_id_has_arg_prefix(self):
        fid = Finding.new_id()
        assert fid.startswith("ARG-")
        assert len(fid) == 12

    def test_to_dict_contains_required_keys(self):
        f = Finding(
            finding_id="ARG-TESTTEST",
            owasp_category="LLM08",
            surface="multiagent",
            strategy="action_boundary_breach",
            payload_text="escalate privileges",
            response_text="done",
            detection_layer="llm_judge",
            cvss_base_score=8.7,
            cvss_severity="High",
            confirmed=True,
        )
        d = f.to_dict()
        assert d["owasp_category"] == "LLM08"
        assert d["cvss_base_score"] == 8.7
        assert d["confirmed"] is True
