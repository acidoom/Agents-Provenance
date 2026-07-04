"""Command-line interface (FR-14 / §14). Commands are added per milestone."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .eval.loader import load_scenarios
from .eval.reporting import generate_report
from .eval.runner import run_eval, run_single
from .eval.schemas import ALL_DEFENSES, DefenseMode, EvalResult
from .eval.scoring import aggregate
from .policy.decisions import PolicyOutcome
from .policy.engine import get_policy_engine

app = typer.Typer(
    help="Policy-Gated MCP — tool-poisoning red-team + provenance/OPA defense",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

ScenariosOption = typer.Option(
    Path("scenarios"), "--scenarios", help="Directory of scenario YAML/JSON files"
)


@app.callback()
def _root() -> None:
    """Policy-Gated MCP — a keyless, deterministic tool-poisoning / provenance-gate harness."""


@app.command("list-scenarios")
def list_scenarios(scenarios: Path = ScenariosOption) -> None:
    """List all loaded scenarios with their category and expected outcome."""
    scns = load_scenarios(scenarios)
    n_benign = sum(1 for s in scns if s.category.value == "benign")
    n_attack = len(scns) - n_benign
    classes = sorted({s.attack_type.value for s in scns if s.attack_type.value != "benign"})

    table = Table(title=f"{len(scns)} scenarios · {n_benign} benign · {n_attack} attack")
    table.add_column("id", style="cyan", no_wrap=True)
    table.add_column("category")
    table.add_column("attack_type")
    table.add_column("expected", justify="center")
    table.add_column("name")
    for s in scns:
        cat_style = "green" if s.category.value == "benign" else "red"
        table.add_row(
            s.id,
            f"[{cat_style}]{s.category.value}[/{cat_style}]",
            s.attack_type.value,
            s.expected_policy_outcome.value,
            s.name,
        )
    console.print(table)
    console.print(f"attack classes covered: {', '.join(classes)}")


@app.command("policy-check")
def policy_check(
    input: Path = typer.Option(..., "--input", help="Policy input JSON document"),
    engine: str = typer.Option("auto", "--engine", help="auto | opa | native"),
) -> None:
    """Evaluate a single policy input document through the gate and print the decision."""
    doc = json.loads(Path(input).read_text(encoding="utf-8"))
    eng = get_policy_engine(prefer=engine)
    decision = eng.evaluate(doc)

    color = {"allow": "green", "deny": "red", "review": "yellow"}[decision.outcome.value]
    console.print(
        f"engine=[bold]{eng.name}[/bold]  "
        f"outcome=[{color}]{decision.outcome.value}[/{color}]  allow={decision.allow}"
    )
    if decision.deny_reasons:
        console.print(f"  deny_reasons: {', '.join(decision.deny_reasons)}")
    if decision.review_reasons:
        console.print(f"  review_reasons: {', '.join(decision.review_reasons)}")
    console.print(f"  input_hash: {decision.input_hash}")
    raise typer.Exit(code=1 if decision.outcome == PolicyOutcome.deny else 0)


def _parse_defenses(spec: str) -> list[DefenseMode]:
    if spec == "all":
        return list(ALL_DEFENSES)
    try:
        return [DefenseMode(d.strip()) for d in spec.split(",") if d.strip()]
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _metrics_table(results: list[EvalResult]) -> Table:
    metrics = aggregate(results)
    table = Table(title="Metrics by defense mode")
    for col in ("defense", "ASR", "BTSR", "FPR", "denial", "review", "utility"):
        table.add_column(col, justify="right" if col != "defense" else "left")
    for d in ALL_DEFENSES:
        m = metrics.get(d.value)
        if not m:
            continue
        util = m["utility_retention"]
        table.add_row(
            d.value,
            f"{100 * m['asr']:.0f}%",
            f"{100 * m['btsr']:.0f}%",
            f"{100 * m['fpr']:.0f}%",
            f"{100 * m['policy_denial_rate']:.0f}%",
            f"{100 * m['review_rate']:.0f}%",
            "n/a" if util is None else f"{util:.2f}",
        )
    return table


@app.command("run")
def run_cmd(
    scenario: str = typer.Option(..., "--scenario", help="Scenario id"),
    defense: str = typer.Option("provenance_opa", "--defense"),
    model: str = typer.Option("fake:vulnerable_agent", "--model"),
    scenarios: Path = ScenariosOption,
    engine: str = typer.Option("auto", "--engine", help="auto | opa | native"),
) -> None:
    """Run a single scenario under one defense mode and print the outcome."""
    dm = _parse_defenses(defense)[0]
    outcome = run_single(scenario, dm, model, scenarios_dir=scenarios, engine_pref=engine)
    r = outcome.result
    verdict = (
        "[red]ATTACK SUCCEEDED[/red]"
        if r.attack_success
        else "[green]benign ok[/green]"
        if r.benign_success
        else "[yellow]blocked/neutralized[/yellow]"
    )
    console.print(f"[bold]{r.scenario_id}[/bold]  defense={dm.value}  model={model}  {verdict}")
    console.print(f"  proposed_account: {r.proposed_account}")
    console.print(f"  executed: {r.executed}  executed_account: {r.executed_account}")
    if r.policy_outcome:
        console.print(f"  policy: {r.policy_outcome.value} (engine={r.policy_engine})")
    if r.deny_reasons:
        console.print(f"  deny_reasons: {', '.join(r.deny_reasons)}")
    if r.review_reasons:
        console.print(f"  review_reasons: {', '.join(r.review_reasons)}")


@app.command("eval")
def eval_cmd(
    scenarios: Path = ScenariosOption,
    model: str = typer.Option("fake:vulnerable_agent", "--model"),
    defenses: str = typer.Option("all", "--defenses", help="'all' or comma-separated modes"),
    out: Path = typer.Option(Path("reports/weekend_eval"), "--out"),
    engine: str = typer.Option("auto", "--engine"),
) -> None:
    """Run the full evaluation suite and write results, CSV, traces, and a report."""
    dms = _parse_defenses(defenses)
    summary = run_eval(scenarios, model, dms, out, engine_pref=engine)
    console.print(_metrics_table(summary.results))
    console.print(f"wrote [bold]{summary.report_path}[/bold] ({len(summary.results)} runs)")


@app.command("report")
def report_cmd(
    results: Path = typer.Option(..., "--results", help="results.jsonl path"),
    out: Path = typer.Option(..., "--out"),
    model: str = typer.Option("fake:vulnerable_agent", "--model"),
) -> None:
    """Regenerate the Markdown report from an existing results.jsonl."""
    results = Path(results)
    if not results.exists():
        console.print(
            f"[red]results file not found:[/red] {results}\n"
            "results.jsonl is generated, not committed — run `make eval` (or "
            "`python -m policy_gated_mcp.cli eval`) first."
        )
        raise typer.Exit(code=2)
    rows = [
        EvalResult(**json.loads(line))
        for line in results.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    md = generate_report(
        rows, model_profile=model, scenario_count=len({r.scenario_id for r in rows})
    )
    Path(out).write_text(md, encoding="utf-8")
    console.print(f"wrote [bold]{out}[/bold]")


if __name__ == "__main__":
    app()
