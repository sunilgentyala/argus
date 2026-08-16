"""
ARGUS CLI entry point.

Usage:
    argus scan --target anthropic --model claude-sonnet-4-6 --profile quick
    argus scan --target openai --model gpt-4o --config configs/argus.default.yaml
    argus scan --target http://localhost:8080/v1/chat --profile compliance
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from argus.agents.attacker import AttackerAgent
from argus.agents.evaluator import EvaluatorAgent
from argus.agents.planner import PlannerAgent
from argus.agents.reporter import ReporterAgent
from argus.compliance.mapper import ComplianceMapper
from argus.core.orchestrator import Orchestrator
from argus.core.session import SessionState
from argus.detectors.llm_judge import LLMJudgeDetector
from argus.memory.episodic import EpisodicMemory
from argus.memory.hitlog import HitLog
from argus.payloads.synthesizer import PayloadSynthesizer
from argus.scoring.cvss4 import CVSSv4Scorer
from argus.targets.base import Target
from argus.targets.profiler import TargetProfiler


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


def _load_config(config_path: str | None) -> dict[str, Any]:
    default = Path(__file__).parent.parent / "configs" / "argus.default.yaml"
    path = Path(config_path) if config_path else default
    if not path.exists():
        raise click.ClickException(f"Config not found: {path}")
    with open(path, encoding="utf-8") as f:
        loaded: dict[str, Any] = yaml.safe_load(f)
    return loaded


def _build_target(
    target: str, model: str | None, system_prompt: str, api_key: str | None
) -> Target:
    if target == "anthropic":
        from argus.targets.anthropic_target import AnthropicTarget
        return AnthropicTarget(
            model=model or "claude-sonnet-4-6",
            api_key=api_key,
            system_prompt=system_prompt,
        )
    if target == "openai":
        from argus.targets.openai_target import OpenAITarget
        return OpenAITarget(
            model=model or "gpt-4o",
            api_key=api_key,
            system_prompt=system_prompt,
        )
    if target == "ollama":
        from argus.targets.ollama_target import OllamaTarget
        return OllamaTarget(
            model=model or "llama3",
            system_prompt=system_prompt,
        )
    raise click.ClickException(
        f"Unknown target '{target}'. Supported: anthropic, openai, ollama. "
        "For custom endpoints implement argus.targets.base.Target."
    )


@click.group()
@click.version_option(version="1.1.0", prog_name="argus")
def main() -> None:
    """ARGUS: Agentic Red-team and Governance Unified Scanner for LLM security."""


@main.command()
@click.option("--target", "-t", required=True,
              help="Target type: anthropic | openai | ollama")
@click.option("--model", "-m", default=None,
              help="Model name (overrides config default)")
@click.option("--system-prompt", default="",
              help="System prompt to inject into target (optional)")
@click.option("--profile", "-p",
              type=click.Choice(["quick", "full", "pipeline", "compliance"]),
              default="full", show_default=True,
              help="Scan profile (payload budget and surface coverage)")
@click.option("--budget", "-b", default=None, type=int,
              help="Payload budget override (number of payloads)")
@click.option("--config", "-c", default=None,
              help="Path to YAML config (default: configs/argus.default.yaml)")
@click.option("--output-dir", "-o", default="./argus-reports",
              help="Output directory for reports")
@click.option("--sarif", default=None,
              help="Direct path for SARIF output file (e.g. --sarif argus.sarif)")
@click.option("--api-key", default=None, envvar="ARGUS_API_KEY",
              help="API key for target (or set ARGUS_API_KEY env var)")
@click.option("--verbose", "-v", is_flag=True, default=False)
def scan(
    target: str,
    model: str | None,
    system_prompt: str,
    profile: str,
    budget: int | None,
    config: str | None,
    output_dir: str,
    sarif: str | None,
    api_key: str | None,
    verbose: bool,
) -> None:
    """Run an ARGUS vulnerability scan against a target LLM."""
    _setup_logging(verbose)
    cfg = _load_config(config)

    profile_budgets = {"quick": 20, "full": 100, "pipeline": 50, "compliance": 80}
    payload_budget = budget or profile_budgets.get(profile, 100)

    click.echo(f"[ARGUS] target={target}  profile={profile}  budget={payload_budget}")

    target_obj = _build_target(target, model, system_prompt, api_key)

    agents_cfg = cfg.get("agents", {})
    planner = PlannerAgent(
        model=agents_cfg.get("planner", {}).get("model", "claude-opus-4-8"),
        max_tokens=agents_cfg.get("planner", {}).get("max_tokens", 2048),
    )
    synthesizer = PayloadSynthesizer(
        synthesis_model=agents_cfg.get("synthesizer", {}).get("model", "claude-sonnet-4-6"),
    )
    judge = LLMJudgeDetector(
        model=agents_cfg.get("judge", {}).get("model", "claude-sonnet-4-6"),
        min_affirmative=agents_cfg.get("judge", {}).get("min_affirmative", 2),
    )
    scorer = CVSSv4Scorer()
    mapper = ComplianceMapper()
    frameworks = cfg.get("compliance", {}).get("frameworks")
    memory = EpisodicMemory(
        persist_path=cfg.get("memory", {}).get("persist_path", "./argus-memory.json"),
    )
    hitlog = HitLog(
        path=cfg.get("memory", {}).get("hitlog_path", "./argus.hitlog.jsonl"),
    )
    profiler = TargetProfiler()

    mutation_budget = cfg.get("attack", {}).get("mutation_budget", 3)
    attacker = AttackerAgent(
        synthesizer=synthesizer,
        profiler=profiler,
        target=target_obj,
        mutation_budget=mutation_budget,
        enable_mutations=mutation_budget > 0,
    )
    evaluator = EvaluatorAgent(judge=judge, scorer=scorer, mapper=mapper, frameworks=frameworks)
    reporter = ReporterAgent(output_dir=output_dir, sarif_path=sarif)

    orchestrator = Orchestrator(
        planner=planner,
        attacker=attacker,
        evaluator=evaluator,
        reporter=reporter,
        memory=memory,
        hitlog=hitlog,
    )

    session = SessionState(
        payloads_budget=payload_budget,
        scan_profile=profile,
    )

    report = orchestrator.run(session)
    summary = report["session"]

    click.echo("\n" + "=" * 60)
    click.echo("  ARGUS SCAN COMPLETE")
    click.echo(f"  Session : {summary['session_id']}")
    click.echo(f"  Findings: {summary['total_findings']}  "
               f"(Critical={summary['critical']}  High={summary['high']}  "
               f"Medium={summary['medium']}  Low={summary['low']})")
    click.echo(f"  Payloads: {summary['payloads_sent']} sent")
    click.echo(f"  Reports : {output_dir}/")
    click.echo("=" * 60 + "\n")

    sys.exit(1 if summary["critical"] > 0 else 0)


@main.command()
@click.argument("report_path", type=click.Path(exists=True))
def show(report_path: str) -> None:
    """Pretty-print a saved ARGUS JSON report."""
    import json

    from rich.console import Console
    from rich.table import Table

    console = Console()
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    s = report["session"]
    console.print(f"\n[bold cyan]ARGUS Report[/]: session {s['session_id']}")
    console.print(f"Phase: {s['phase']}  |  Payloads sent: {s['payloads_sent']}")

    table = Table(title="Confirmed Findings")
    table.add_column("ID", style="cyan")
    table.add_column("OWASP", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("CVSS", style="magenta")
    table.add_column("Surface")

    for f in report.get("findings", []):
        sev = f.get("cvss_severity", "?")
        color = {"Critical": "bold red", "High": "red", "Medium": "yellow"}.get(sev, "white")
        table.add_row(
            f["finding_id"],
            f["owasp_category"],
            f"[{color}]{sev}[/]",
            str(f.get("cvss_base_score", "")),
            f["surface"],
        )
    console.print(table)
