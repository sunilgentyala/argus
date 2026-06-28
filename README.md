# ARGUS

[![ARGUS CI](https://github.com/sunilgentyala/argus/actions/workflows/argus-ci.yaml/badge.svg)](https://github.com/sunilgentyala/argus/actions/workflows/argus-ci.yaml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-orange)](https://github.com/sunilgentyala/argus/releases)
[![GitHub Stars](https://img.shields.io/github/stars/sunilgentyala/argus?style=social)](https://github.com/sunilgentyala/argus/stargazers)
[![Website](https://img.shields.io/badge/website-live-brightgreen)](https://sunilgentyala.github.io/argus/)

**Agentic Red-team and Governance Unified Scanner** for LLM security.

ARGUS replaces static probe-and-detect pipelines with a closed-loop multi-agent architecture that reasons about attack strategy, synthesizes novel payloads, evaluates results through a three-layer detection stack, and maps every confirmed finding to CVSSv4.0 vectors and global regulatory frameworks.

> Companion paper (in preparation): *"ARGUS: An Agentic Red-Team Framework for Autonomous LLM Vulnerability Discovery and Regulatory Compliance Mapping"* — Sunil Gentyala, HCLTech, Dallas TX

**[Live demo site](https://sunilgentyala.github.io/argus/) — [Star on GitHub](https://github.com/sunilgentyala/argus) — [Connect on LinkedIn](https://www.linkedin.com/in/sunilgentyala/)**

---

## What's New in v1.1.0

- **HTML reports** — self-contained HTML output alongside SARIF and JSON
- **`--sarif` flag** — direct SARIF file path for CI/CD (`argus scan ... --sarif argus.sarif`)
- **Threat intelligence module** — curated LLM attack signal database in `argus/intelligence/`
- **Model update** — Planner now defaults to `claude-opus-4-8`
- **Apache 2.0 LICENSE** file added
- **CONTRIBUTING.md** — community contribution guide

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
  SARIF + HTML + JSON reports  ──>  CI/CD / GRC tooling
```

### Agents

| Agent | Role |
|---|---|
| **Planner** | Reasoning-model (Claude Opus 4.8) formulates and revises attack strategy based on live target behavioral signals and episodic memory |
| **Attacker** | Synthesizes novel payloads via embedding-space diversity constraint; delivers them to the target |
| **Evaluator** | Three-layer detection: semantic proximity, LLM-as-judge panel, behavioral trace analysis |
| **Reporter** | Generates SARIF v2.1, HTML, and JSON reports; maps findings to compliance frameworks |

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
git clone https://github.com/sunilgentyala/argus
cd argus
pip install -e .

# Scan an Anthropic model (quick profile, 20 payloads)
argus scan --target anthropic --model claude-sonnet-4-6 --profile quick

# Full scan with SARIF output for CI/CD
argus scan --target anthropic --model claude-opus-4-8 --profile full \
           --sarif argus.sarif --output-dir ./my-reports

# Scan with a system prompt
argus scan --target openai --model gpt-4o \
           --system-prompt "You are a helpful customer service agent." \
           --profile compliance

# View a saved report
argus show ./argus-reports/<session-id>.report.json
```

API key resolution order: `--api-key` flag → `ARGUS_API_KEY` env var → `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`.

---

## CI/CD Integration

Add ARGUS to your GitHub Actions pipeline:

```yaml
- name: Run ARGUS LLM security scan
  run: argus scan --target openai --model gpt-4o --profile full --sarif argus.sarif

- name: Upload findings to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
```

Critical and High findings block the PR and appear in the Security tab within ~45 seconds.

---

## Scan Profiles

| Profile | Payload Budget | Focus |
|---|---|---|
| `quick` | 20 | Highest-severity OWASP categories only |
| `full` | 100 | All 10 OWASP LLM Top 10 categories across all surfaces |
| `pipeline` | 150 | RAG, MCP, multi-agent, tool-use surfaces |
| `compliance` | 80 | All categories with full compliance mapping output |

---

## Configuration

Edit `configs/argus.default.yaml` or pass `--config path/to/custom.yaml`:

```yaml
agents:
  planner:
    model: claude-opus-4-8
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
│   │   └── reporter.py       # SARIF + HTML + JSON report generation
│   ├── core/
│   │   ├── orchestrator.py   # Main scan loop (Planner -> Attacker -> Evaluator cycle)
│   │   └── session.py        # SessionState, Finding, ScanPhase state machine
│   ├── compliance/
│   │   └── mapper.py         # 8-framework compliance tag engine
│   ├── detectors/
│   │   └── llm_judge.py      # LLM-as-judge multi-model verdict panel
│   ├── intelligence/
│   │   └── __init__.py       # LLM threat intelligence database
│   ├── memory/
│   │   ├── episodic.py       # Cross-session attack memory (ChromaDB / in-memory)
│   │   └── hitlog.py         # Confirmed-hit append-only log
│   ├── payloads/
│   │   └── synthesizer.py    # Diversity-constrained payload synthesis
│   ├── reporting/
│   │   ├── sarif.py          # SARIF v2.1 output
│   │   └── html_reporter.py  # Self-contained HTML report
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

## How ARGUS Compares

| Feature | Garak | PyRIT | ARGUS |
|---|---|---|---|
| Multi-agent adaptive strategy | No | No | Yes |
| Cross-session episodic memory | No | No | Yes |
| OWASP LLM Top 10 (2025) | Partial | Partial | All 10 |
| RAG / MCP attack surface | No | Partial | Yes |
| CVSSv4.0 scoring | No | No | Yes |
| SARIF v2.1 CI/CD output | No | No | Yes |
| 8-framework compliance mapping | No | No | Yes |
| HTML reports | No | No | Yes |

---

## Citation

If you use ARGUS in research or cite this framework, please use:

```bibtex
@misc{gentyala2026argus,
  title        = {{ARGUS}: An Agentic Red-Team Framework for Autonomous {LLM}
                  Vulnerability Discovery and Regulatory Compliance Mapping},
  author       = {Gentyala, Sunil},
  year         = {2026},
  institution  = {HCLTech, Dallas TX},
  note         = {In preparation. \url{https://github.com/sunilgentyala/argus}}
}
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Author

**Sunil Gentyala** — IEEE Senior Member
Cybersecurity and AI Security, HCLTech, Dallas, TX, USA
sunil.gentyala@ieee.org

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?logo=linkedin)](https://www.linkedin.com/in/sunilgentyala/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?logo=github)](https://github.com/sunilgentyala)
[![Website](https://img.shields.io/badge/Website-sunilgentyala.github.io-orange)](https://sunilgentyala.github.io/argus/)

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

For authorized security testing only.
