"""Reporter Agent — generates compliance-mapped output."""
from __future__ import annotations
from argus.agents.base import Agent, AgentRole
from argus.reporting.sarif import SARIFReporter
from argus.core.session import SessionState

class ReporterAgent(Agent):
    role = AgentRole.REPORTER
    def __init__(self, output_dir: str = "./argus-reports") -> None:
        self._sarif = SARIFReporter()
        self._output_dir = output_dir

    def generate(self, session: SessionState) -> dict:
        import json, pathlib
        pathlib.Path(self._output_dir).mkdir(parents=True, exist_ok=True)
        sarif = self._sarif.generate(
            session,
            output_path=f"{self._output_dir}/{session.session_id}.sarif.json"
        )
        summary = session.summary()
        report = {"session": summary, "sarif": sarif,
                  "findings": [f.to_dict() for f in session.confirmed_findings()]}
        p = pathlib.Path(self._output_dir) / f"{session.session_id}.report.json"
        p.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
