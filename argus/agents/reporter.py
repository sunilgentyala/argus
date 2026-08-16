"""Reporter Agent: generates compliance-mapped output."""
from __future__ import annotations

from typing import Any

from argus.agents.base import Agent, AgentRole
from argus.core.session import SessionState
from argus.reporting.html_reporter import HTMLReporter
from argus.reporting.sarif import SARIFReporter


class ReporterAgent(Agent):
    role = AgentRole.REPORTER

    def __init__(
        self,
        output_dir: str = "./argus-reports",
        sarif_path: str | None = None,
    ) -> None:
        self._sarif = SARIFReporter()
        self._html = HTMLReporter()
        self._output_dir = output_dir
        self._sarif_path = sarif_path

    def generate(self, session: SessionState) -> dict[str, Any]:
        import json
        import pathlib
        out = pathlib.Path(self._output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # SARIF: write to explicit path if given, else to output-dir
        sarif_out = self._sarif_path or str(out / f"{session.session_id}.sarif.json")
        sarif = self._sarif.generate(session, output_path=sarif_out)

        # HTML report
        self._html.generate(session, output_path=str(out / f"{session.session_id}.report.html"))

        summary = session.summary()
        report = {
            "session": summary,
            "sarif": sarif,
            "findings": [f.to_dict() for f in session.confirmed_findings()],
        }
        p = out / f"{session.session_id}.report.json"
        p.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
