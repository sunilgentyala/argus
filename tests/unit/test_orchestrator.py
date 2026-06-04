"""Unit tests for the Orchestrator and agent interfaces."""

import pytest
from unittest.mock import MagicMock, patch
from argus.core.session import SessionState, Finding, ScanPhase
from argus.core.orchestrator import Orchestrator
from argus.agents.planner import AttackPlan, AttackTask


def _make_finding(fid: str = "ARG-AAAAAAAA", confirmed: bool = True) -> Finding:
    return Finding(
        finding_id=fid, owasp_category="LLM01", surface="direct",
        strategy="direct_injection", payload_text="test", response_text="resp",
        detection_layer="llm_judge", cvss_base_score=7.5, cvss_severity="High",
        confirmed=confirmed,
    )


def _make_plan(tasks: int = 1) -> AttackPlan:
    queue = [
        AttackTask(
            rank=i + 1, owasp_category="LLM01", surface="direct",
            strategy="direct_injection", payload_hint="", expected_cvss_range="7-9",
            rationale="test",
        )
        for i in range(tasks)
    ]
    return AttackPlan(session_id="test-session", revision=0, priority_queue=queue)


class TestOrchestrator:

    def _make_orch(self, plan: AttackPlan | None = None) -> tuple[Orchestrator, dict]:
        plan = plan or _make_plan(1)
        mocks: dict = {
            "planner": MagicMock(),
            "attacker": MagicMock(),
            "evaluator": MagicMock(),
            "reporter": MagicMock(),
            "memory": MagicMock(),
            "hitlog": MagicMock(),
        }
        mocks["planner"].initialize.return_value = plan
        mocks["planner"].revise.return_value = AttackPlan(
            session_id="test-session", revision=1, priority_queue=[]
        )
        mocks["attacker"].profile_target.return_value = {"model_family": "test"}
        mocks["attacker"].generate_payloads.return_value = [MagicMock(text="payload")]
        mocks["attacker"].deliver.return_value = "response"
        mocks["evaluator"].evaluate.return_value = [_make_finding()]
        mocks["reporter"].generate.return_value = {
            "session": SessionState().summary(), "sarif": {}, "findings": []
        }
        orch = Orchestrator(**mocks)
        return orch, mocks

    def test_run_completes_without_error(self):
        orch, _ = self._make_orch()
        session = SessionState(payloads_budget=10)
        report = orch.run(session)
        assert report is not None

    def test_run_transitions_to_complete(self):
        orch, _ = self._make_orch()
        session = SessionState(payloads_budget=10)
        orch.run(session)
        assert session.phase == ScanPhase.COMPLETE

    def test_run_calls_planner_initialize(self):
        orch, mocks = self._make_orch()
        session = SessionState(payloads_budget=10)
        orch.run(session)
        mocks["planner"].initialize.assert_called_once()

    def test_run_calls_reporter_generate(self):
        orch, mocks = self._make_orch()
        session = SessionState(payloads_budget=10)
        orch.run(session)
        mocks["reporter"].generate.assert_called_once_with(session)

    def test_failed_phase_on_exception(self):
        orch, mocks = self._make_orch()
        mocks["attacker"].profile_target.side_effect = RuntimeError("target unreachable")
        session = SessionState(payloads_budget=10)
        with pytest.raises(RuntimeError):
            orch.run(session)
        assert session.phase == ScanPhase.FAILED
