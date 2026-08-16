"""Evaluator Agent: orchestrates the three-layer detection stack.

Layer 1 (semantic) gates Layer 2 (judge) when an exemplar corpus has been
loaded for the category, matching paper Section V.E: "Layer 2 ... evaluates
each Layer 1 candidate". If no exemplars are registered for a category the
gate is skipped (fail-open) so the evaluator still functions with judge-only
configuration. Layer 3 (behavioral trace) is independent of Layers 1-2 and
requires a pipeline target that exposes tool-call telemetry on the session's
target_profile; see Section VIII.C for the honest scope of that dependency.
"""
from __future__ import annotations

from argus.agents.base import Agent, AgentRole
from argus.compliance.mapper import ComplianceMapper
from argus.core.session import Finding, SessionState
from argus.detectors.llm_judge import LLMJudgeDetector
from argus.detectors.semantic import SemanticProximityDetector
from argus.payloads.synthesizer import Payload
from argus.scoring.cvss4 import CVSSv4Scorer, build_vector


class EvaluatorAgent(Agent):
    role = AgentRole.EVALUATOR
    def __init__(self, judge: LLMJudgeDetector, scorer: CVSSv4Scorer,
                 mapper: ComplianceMapper,
                 semantic: SemanticProximityDetector | None = None,
                 frameworks: list[str] | None = None) -> None:
        self._judge = judge
        self._scorer = scorer
        self._mapper = mapper
        self._semantic = semantic or SemanticProximityDetector()
        self._frameworks = frameworks

    def evaluate(self, payload: Payload, response: str,
                 session: SessionState) -> list[Finding]:
        semantic_verdict = self._semantic.detect(payload.owasp_category, response)
        has_exemplars = self._semantic.has_exemplars(payload.owasp_category)
        if has_exemplars and not semantic_verdict.is_hit:
            return []

        verdict = self._judge.judge(payload.text, response, payload.owasp_category)
        if not self._judge.is_hit(verdict):
            return []

        detection_layer = "semantic+llm_judge" if has_exemplars else "llm_judge"
        fid = Finding.new_id()
        vector = build_vector(
            payload.owasp_category,
            {"description": verdict.reasoning, "finding_id": fid},
            session.target_profile.get("deployment_context", "general"),
        )
        score, severity = self._scorer.score(vector)
        tags = self._mapper.tag_strings(payload.owasp_category, self._frameworks)
        finding = Finding(
            finding_id=fid,
            owasp_category=payload.owasp_category,
            surface=payload.surface,
            strategy=payload.strategy,
            payload_text=payload.text,
            response_text=response,
            detection_layer=detection_layer,
            cvss_vector=vector.to_vector_string(),
            cvss_base_score=score,
            cvss_severity=severity,
            confirmed=True,
            compliance_tags=tags,
        )
        self._semantic.add_exemplar(payload.owasp_category, response)
        return [finding]
