"""Evaluation runner (FR-14): scenarios × defenses × model → results + reports."""

from __future__ import annotations

import csv
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..agent.graph import RunResult, run_scenario
from ..models import Model, get_model
from ..policy.engine import get_policy_engine
from .loader import get_scenario, load_scenarios
from .reporting import generate_report
from .schemas import DefenseMode, EvalResult, Scenario


@dataclass
class EvalSummary:
    results: list[EvalResult]
    out_dir: Path
    report_path: Path


def _slug(model_spec: str) -> str:
    return model_spec.replace(":", "_")


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5
        )
        return out.stdout.strip() or "(uncommitted)"
    except Exception:  # noqa: BLE001
        return "(unknown)"


def _resolve_claim(base_dir: Path, scenario: Scenario) -> str:
    path = (base_dir / scenario.claim_fixture).resolve()
    return path.read_text(encoding="utf-8")


def run_one(
    scenario: Scenario,
    defense: DefenseMode,
    model: Model,
    *,
    policy_engine,
    base_dir: Path,
    db_path=None,
) -> RunResult:
    claim_text = _resolve_claim(base_dir, scenario)
    return run_scenario(
        scenario,
        defense,
        model,
        policy_engine=policy_engine,
        claim_text=claim_text,
        db_path=db_path,
    )


def run_eval(
    scenarios_dir: str | Path,
    model_spec: str,
    defenses: list[DefenseMode],
    out_dir: str | Path,
    *,
    engine_pref: str = "auto",
    base_dir: str | Path | None = None,
    db_path=None,
) -> EvalSummary:
    base = Path(base_dir) if base_dir else Path.cwd()
    scenarios = load_scenarios(scenarios_dir)
    model = get_model(model_spec)
    engine = get_policy_engine(engine_pref)

    out = Path(out_dir)
    traces_dir = out / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)

    results: list[EvalResult] = []
    for scenario in scenarios:
        for defense in defenses:
            run = run_one(
                scenario, defense, model, policy_engine=engine, base_dir=base, db_path=db_path
            )
            trace_path = traces_dir / f"{scenario.id}__{defense.value}__{_slug(model_spec)}.json"
            trace_path.write_text(json.dumps(run.trace, indent=2, default=str), encoding="utf-8")
            run.result.trace_path = str(trace_path)
            results.append(run.result)

    _write_results(out / "results.jsonl", results)
    _write_summary_csv(out / "summary.csv", results)

    report = generate_report(
        results,
        model_profile=model_spec,
        commit=_git_commit(),
        date=datetime.now(UTC).strftime("%Y-%m-%d"),
        scenario_count=len(scenarios),
        policy_engine=engine.name,
    )
    report_path = out / "eval_summary.md"
    report_path.write_text(report, encoding="utf-8")

    return EvalSummary(results=results, out_dir=out, report_path=report_path)


def run_single(
    scenario_id: str,
    defense: DefenseMode,
    model_spec: str,
    *,
    scenarios_dir: str | Path = "scenarios",
    engine_pref: str = "auto",
    base_dir: str | Path | None = None,
    db_path=None,
) -> RunResult:
    """Run one scenario under one defense (for the `run` CLI command)."""
    base = Path(base_dir) if base_dir else Path.cwd()
    scenario = get_scenario(scenarios_dir, scenario_id)
    model = get_model(model_spec)
    engine = get_policy_engine(engine_pref)
    return run_one(scenario, defense, model, policy_engine=engine, base_dir=base, db_path=db_path)


def _write_results(path: Path, results: list[EvalResult]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(r.model_dump_json() + "\n")


def _write_summary_csv(path: Path, results: list[EvalResult]) -> None:
    columns = [
        "scenario_id",
        "category",
        "attack_type",
        "model_profile",
        "defense_mode",
        "proposed_account",
        "executed",
        "executed_account",
        "policy_outcome",
        "policy_engine",
        "attack_success",
        "benign_success",
        "false_positive",
        "deny_reasons",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for r in results:
            d = r.model_dump()
            writer.writerow(
                [
                    d["scenario_id"],
                    d["category"],
                    d["attack_type"],
                    d["model_profile"],
                    d["defense_mode"],
                    d["proposed_account"],
                    d["executed"],
                    d["executed_account"],
                    d["policy_outcome"],
                    d["policy_engine"],
                    d["attack_success"],
                    d["benign_success"],
                    d["false_positive"],
                    "|".join(d["deny_reasons"]),
                ]
            )
