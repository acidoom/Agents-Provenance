"""Command-line interface (FR-14 / §14). Commands are added per milestone."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .eval.loader import load_scenarios
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


if __name__ == "__main__":
    app()
