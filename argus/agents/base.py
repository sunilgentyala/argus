"""Base agent interface for all ARGUS agents."""
from __future__ import annotations

from abc import ABC
from enum import StrEnum


class AgentRole(StrEnum):
    PLANNER   = "planner"
    ATTACKER  = "attacker"
    EVALUATOR = "evaluator"
    REPORTER  = "reporter"


class Agent(ABC):
    role: AgentRole

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(role={self.role})"
