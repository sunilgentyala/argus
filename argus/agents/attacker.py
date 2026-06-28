"""Attacker Agent — wraps PayloadSynthesizer, MutationEngine, and target delivery."""
from __future__ import annotations
from argus.agents.base import Agent, AgentRole
from argus.payloads.synthesizer import PayloadSynthesizer, Payload
from argus.payloads.mutator import MutationEngine
from argus.agents.planner import AttackTask
from argus.core.session import SessionState
from argus.targets.profiler import TargetProfiler


class AttackerAgent(Agent):
    role = AgentRole.ATTACKER

    def __init__(
        self,
        synthesizer: PayloadSynthesizer,
        profiler: TargetProfiler,
        target,
        mutation_budget: int = 3,
        enable_mutations: bool = True,
    ) -> None:
        self._synth = synthesizer
        self._profiler = profiler
        self._target = target
        self._mutator = MutationEngine(budget=mutation_budget) if enable_mutations else None

    def profile_target(self, session: SessionState) -> dict:
        return self._profiler.profile(self._target, session)

    def generate_payloads(self, task: AttackTask, session: SessionState) -> list[Payload]:
        base_payloads = self._synth.generate_batch(
            owasp_category=task.owasp_category,
            surface=task.surface,
            strategy=task.strategy,
            target_profile=session.target_profile,
            batch_size=10,
            session_id=session.session_id,
        )
        if self._mutator:
            return self._mutator.mutate_batch(base_payloads)
        return base_payloads

    def deliver(self, payload: Payload, session: SessionState) -> str:
        return self._target.send(payload.text)
