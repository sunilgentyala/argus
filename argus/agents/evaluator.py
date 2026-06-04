"""Evaluator Agent — orchestrates the three-layer detection stack."""
from __future__ import annotations
from argus.agents.base import Agent, AgentRole
from argus.detectors.llm_judge import LLMJudgeDetector
from argus.payloads.synthesizer import Payload
from argus.scoring.cvss4 import CVSSv4Scorer, build_vector
from argus.compliance.mapper import ComplianceMapper
from argus.core.session import SessionState, Finding

class EvaluatorAgent(Agent):
    role = AgentRole.EVALUATOR
    def __init__(self, judge: LLMJudgeDetector, scorer: CVSSv4Scorer,
                 mapper: ComplianceMapper) -> None:
        self._judge = judge
        self._scorer = scorer
        self._mapper = mapper

    def evaluate(self, payload: Payload, response: str,
                 session: SessionState) -> list[Finding]:
        verdict = self._judge.judge(payload.text, response, payload.owasp_category)
        if not self._judge.is_hit(verdict):
            return []
        fid = Finding.new_id()
        vector = build_vector(
            payload.owasp_category,
            {"description": verdict.reasoning, "finding_id": fid},
            session.target_profile.get("deployment_context", "general"),
        )
        score, severity = self._scorer.score(vector)
        tags = self._mapper.tag_strings(payload.owasp_category)
        return [Finding(
            finding_id=fid,
            owasp_category=payload.owasp_category,
            surface=payload.surface,
            strategy=payload.strategy,
            payload_text=payload.text,
            response_text=response,
            detection_layer="llm_judge",
            cvss_vector=vector.to_vector_string(),
            cvss_base_score=score,
            cvss_severity=severity,
            confirmed=True,
            compliance_tags=tags,
        )]
