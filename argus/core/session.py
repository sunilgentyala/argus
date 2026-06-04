"""
Scan session state machine.

SessionState is the single source of truth for a running scan:
target profile, phase, findings, budget consumption, and timing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ScanPhase(str, Enum):
    INIT       = "init"
    PROFILING  = "profiling"
    PLANNING   = "planning"
    ATTACKING  = "attacking"
    EVALUATING = "evaluating"
    REPORTING  = "reporting"
    COMPLETE   = "complete"
    FAILED     = "failed"


@dataclass
class Finding:
    finding_id: str
    owasp_category: str
    surface: str
    strategy: str
    payload_text: str
    response_text: str
    detection_layer: str          # semantic | llm_judge | behavioral
    cvss_vector: str = ""
    cvss_base_score: float = 0.0
    cvss_severity: str = "Unknown"
    confirmed: bool = False
    compliance_tags: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "owasp_category": self.owasp_category,
            "surface": self.surface,
            "strategy": self.strategy,
            "detection_layer": self.detection_layer,
            "cvss_vector": self.cvss_vector,
            "cvss_base_score": self.cvss_base_score,
            "cvss_severity": self.cvss_severity,
            "confirmed": self.confirmed,
            "compliance_tags": self.compliance_tags,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def new_id() -> str:
        return f"ARG-{uuid.uuid4().hex[:8].upper()}"


@dataclass
class SessionState:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_profile: dict[str, Any] = field(default_factory=dict)
    phase: ScanPhase = ScanPhase.INIT
    findings: list[Finding] = field(default_factory=list)
    payloads_sent: int = 0
    payloads_budget: int = 100
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str = ""
    scan_profile: str = "full"

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.confirmed]

    def budget_exhausted(self) -> bool:
        return self.payloads_sent >= self.payloads_budget

    def transition(self, phase: ScanPhase) -> None:
        self.phase = phase
        if phase == ScanPhase.COMPLETE:
            self.completed_at = datetime.now(timezone.utc).isoformat()

    def summary(self) -> dict[str, Any]:
        confirmed = self.confirmed_findings()
        return {
            "session_id": self.session_id,
            "phase": self.phase,
            "total_findings": len(confirmed),
            "critical": sum(1 for f in confirmed if f.cvss_severity == "Critical"),
            "high":     sum(1 for f in confirmed if f.cvss_severity == "High"),
            "medium":   sum(1 for f in confirmed if f.cvss_severity == "Medium"),
            "low":      sum(1 for f in confirmed if f.cvss_severity == "Low"),
            "payloads_sent": self.payloads_sent,
            "budget_remaining": self.payloads_budget - self.payloads_sent,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
