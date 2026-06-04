"""
Multi-agent orchestrator — coordinates the Planner → Attacker → Evaluator → Reporter cycle.
"""

from __future__ import annotations

import logging
from typing import Any

from argus.agents.planner import PlannerAgent, AttackPlan
from argus.agents.attacker import AttackerAgent
from argus.agents.evaluator import EvaluatorAgent
from argus.agents.reporter import ReporterAgent
from argus.core.session import SessionState, ScanPhase
from argus.memory.episodic import EpisodicMemory
from argus.memory.hitlog import HitLog

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Drives a complete ARGUS scan session through the closed-loop
    Planner → Attacker → Evaluator → Reporter cycle.
    """

    def __init__(
        self,
        planner: PlannerAgent,
        attacker: AttackerAgent,
        evaluator: EvaluatorAgent,
        reporter: ReporterAgent,
        memory: EpisodicMemory,
        hitlog: HitLog,
    ) -> None:
        self._planner   = planner
        self._attacker  = attacker
        self._evaluator = evaluator
        self._reporter  = reporter
        self._memory    = memory
        self._hitlog    = hitlog

    def run(self, session: SessionState) -> dict[str, Any]:
        """Execute a full scan session. Returns the final report dict."""
        logger.info("Scan started: session=%s", session.session_id)

        try:
            # Phase 1: target profiling
            session.transition(ScanPhase.PROFILING)
            session.target_profile = self._attacker.profile_target(session)

            # Phase 2: initial attack plan
            session.transition(ScanPhase.PLANNING)
            plan: AttackPlan = self._planner.initialize(
                session, self._memory, budget=session.payloads_budget
            )

            # Phase 3: attack → evaluate loop
            session.transition(ScanPhase.ATTACKING)
            while not session.budget_exhausted() and plan.priority_queue:
                task = plan.pop_task()
                if task is None:
                    break

                logger.info(
                    "Executing task rank=%d %s/%s via %s",
                    task.rank, task.owasp_category, task.strategy, task.surface,
                )

                # Generate payloads
                payloads = self._attacker.generate_payloads(task, session)
                session.payloads_sent += len(payloads)

                # Evaluate each payload
                session.transition(ScanPhase.EVALUATING)
                cycle_findings = []
                for payload in payloads:
                    response = self._attacker.deliver(payload, session)
                    findings = self._evaluator.evaluate(payload, response, session)
                    for f in findings:
                        session.add_finding(f)
                        if f.confirmed:
                            self._hitlog.record(f, session)
                    cycle_findings.extend(findings)

                # Revise plan based on cycle results
                session.transition(ScanPhase.ATTACKING)
                plan = self._planner.revise(session, task, cycle_findings)

            # Phase 4: report generation
            session.transition(ScanPhase.REPORTING)
            report = self._reporter.generate(session)

            session.transition(ScanPhase.COMPLETE)
            logger.info(
                "Scan complete: %d confirmed findings, %d payloads sent",
                len(session.confirmed_findings()), session.payloads_sent,
            )
            return report

        except Exception as exc:
            session.transition(ScanPhase.FAILED)
            logger.exception("Scan failed: %s", exc)
            raise
