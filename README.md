# ARGUS

[![ARGUS CI](https://github.com/sunilgentyala/argus/actions/workflows/argus-ci.yaml/badge.svg)](https://github.com/sunilgentyala/argus/actions/workflows/argus-ci.yaml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)

**Agentic Red-team and Governance Unified Scanner** for LLM security.

ARGUS replaces static probe-and-detect pipelines with a closed-loop multi-agent architecture that reasons about attack strategy, synthesizes novel payloads, evaluates results through a three-layer detection stack, and maps every confirmed finding to CVSSv4.0 vectors and global regulatory frameworks.

> Companion paper (in preparation): *"ARGUS: An Agentic Red-Team Framework for Autonomous LLM Vulnerability Discovery and Regulatory Compliance Mapping"* — Sunil Gentyala, HCLTech, Dallas TX

---

## Architecture

```
Target LLM / Pipeline
        |
        v
  ┌─────────────────────────────────────────────────┐
  │              Orchestrator                       │
  │                                                  │
  │   Planner ──> Attacker ──> Evaluator            │
  │      ^            |             |               │
  │      |            v             v               │
  │      └──── Revision <── Findings + CVSS         │
  │                                    |            │
  │                               Reporter          │
  └─────────────────────────────────────────────────┘
        |
        v
  SARIF + JSON reports  ──>  CI/CD / GRC tooling
```

### Agents

| Agent | Role |
|---|---|
| **Planner** | Reasoning-model (Claude Opus) formulates and revises attack strategy based on live target behavioral signals and episodic memory |
| **Attacker** | Synthesizes novel payloads via embedding-space diversity constraint; delivers them to the target |
| **Evaluator** | Three-layer detection: semantic proximity, LLM-as-judge panel, behavioral trace analysis |
| **Reporter** | Generates SARIF v2.1 and JSON reports; maps findings to compliance frameworks |

### Attack Surface Coverage

- Direct completion endpoints
- RAG pipeline traversal (indirect cross-prompt injection)
- Model Context Protocol (MCP) server meshes
- Multi-agent pipeline propagation
- Tool-use / function-calling interfaces

### Detection Stack

1. **Semantic proximity** — cosine distance against confirmed-attack embedding space
2. **LLM-as-judge panel** — multi-model verdict with configurable affirmative threshold
3. **Behavioral trace analysis** — pipeline telemetry anomaly detection

### Scoring and Compliance

- CVSSv4.0 vectors for all 10 OWASP LLM Top 10 (2025) categories
- Compliance mapping: NIST AI RMF, EU AI Act, US EO 14110, UK AISI, India CERT-In, ISO 42001, APAC/EMEA/African digital governance frameworks

---

## Quick Start

```bash
pip install -e .

# Scan an Anthropic model (quick profile, 20 payloads)
argus scan --target anthropic --model claude-sonnet-4-6 --profile quick

# Full scan with custom config
argus scan --target anthropic --model claude-opus-4-7 --profile full \
           --config configs/argus.default.yaml --output-dir ./my-reports

# Scan with a system prompt
argus scan --target openai --model gpt-4o \
           --system-prompt "You are a helpful customer service agent." \
           --profile compliance

# View a saved report
argus show ./argus-reports/<session-id>.report.json
```

API key resolution order: `--api-key` flag → `ARGUS_API_KEY` env var → `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.

---

## Scan Profiles

| Profile | Payload Budget | Focus |
|---|---|---|
| `quick` | 20 | Highest-severity OWASP categories only |
| `full` | 100 | All 10 OWASP LLM Top 10 categories across all surfaces |
| `pipeline` | 50 | RAG, MCP, multi-agent, tool-use surfaces |
| `compliance` | 80 | All categories with full compliance mapping output |

---

## Configuration

Edit `configs/argus.default.yaml` or pass `--config path/to/custom.yaml`:

```yaml
agents:
  planner:
    model: claude-opus-4-7-20251101
    max_tokens: 2048
  synthesizer:
    model: claude-sonnet-4-6
  judge:
    model: claude-sonnet-4-6
    min_affirmative: 2        # votes needed to confirm a finding
    min_confidence: 0.75

compliance:
  frameworks:
    - NIST_AI_RMF
    - EU_AI_ACT
    - UK_AISI
    - US_EO_14110

reporting:
  formats: [jsonl, html, sarif]
  output_dir: ./argus-reports
  include_payload_text: false   # set true only in isolated lab environments
```

---

## Project Structure

```
argus/
├── argus/
│   ├── agents/
│   │   ├── planner.py        # LLM-backed attack strategy planner (AttackPlan, AttackTask)
│   │   ├── attacker.py       # Payload generation and target delivery
│   │   ├── evaluator.py      # Three-layer detection orchestration
│   │   └── reporter.py       # SARIF + JSON report generation
│   ├── core/
│   │   ├── orchestrator.py   # Main scan loop (Planner -> Attacker -> Evaluator cycle)
│   │   └── session.py        # SessionState, Finding, ScanPhase state machine
│   ├── compliance/
│   │   └── mapper.py         # 8-framework compliance tag engine
│   ├── detectors/
│   │   └── llm_judge.py      # LLM-as-judge multi-model verdict panel
│   ├── memory/
│   │   ├── episodic.py       # Cross-session attack memory (ChromaDB / in-memory)
│   │   └── hitlog.py         # Confirmed-hit append-only log
│   ├── payloads/
│   │   └── synthesizer.py    # Diversity-constrained payload synthesis
│   ├── reporting/
│   │   └── sarif.py          # SARIF v2.1 output
│   ├── scoring/
│   │   └── cvss4.py          # CVSSv4.0 vector engine
│   ├── targets/
│   │   ├── anthropic_target.py
│   │   ├── openai_target.py
│   │   ├── base.py           # Target ABC
│   │   └── profiler.py       # Target behavioral profiling
│   └── cli.py                # Click CLI entry point
├── configs/
│   ├── argus.default.yaml
│   └── profiles/             # quick, pipeline scan profiles
├── tests/
│   └── unit/
│       ├── test_session.py
│       └── test_orchestrator.py
└── pyproject.toml
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
```

---

## Extending ARGUS

### Custom Target

```python
from argus.targets.base import Target

class MyTarget(Target):
    @property
    def name(self) -> str:
        return "my-custom-target"

    def send(self, prompt: str) -> str:
        # call your endpoint
        return response_text
```

### Custom Compliance Framework

Add an entry to `ComplianceMapper` in `argus/compliance/mapper.py` following the existing framework pattern.

---

## Author

**Sunil Gentyala** — IEEE Senior Member  
Cybersecurity and AI Security, HCLTech, Dallas, TX, USA  
sunil.gentyala@ieee.org

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
