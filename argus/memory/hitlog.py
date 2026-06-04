"""HitLog — append-only confirmed-finding ledger in AVID-compatible JSONL."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from argus.core.session import Finding, SessionState


class HitLog:
    def __init__(self, path: str = "argus.hitlog.jsonl") -> None:
        self._path = Path(path)

    def record(self, finding: Finding, session: SessionState) -> None:
        record = {
            "schema_version": "argus/1.0",
            "avid_compatible": True,
            "session_id": session.session_id,
            "finding_id": finding.finding_id,
            "owasp_category": finding.owasp_category,
            "surface": finding.surface,
            "strategy": finding.strategy,
            "cvss_vector": finding.cvss_vector,
            "cvss_base_score": finding.cvss_base_score,
            "cvss_severity": finding.cvss_severity,
            "detection_layer": finding.detection_layer,
            "compliance_tags": finding.compliance_tags,
            "target_model_family": session.target_profile.get("model_family", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
