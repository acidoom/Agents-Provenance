"""Scenario loader (FR-1). Reads YAML/JSON scenario files from a directory tree."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .schemas import Scenario

_SUFFIXES = {".yaml", ".yml", ".json"}


def load_scenario_file(path: str | Path) -> Scenario:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    elif path.suffix == ".json":
        data = json.loads(text)
    else:
        raise ValueError(f"unsupported scenario file type: {path}")
    if not isinstance(data, dict):
        raise ValueError(f"scenario file {path} must contain a mapping")
    try:
        return Scenario(**data)
    except Exception as exc:  # noqa: BLE001 - re-raise with the offending file for clarity
        raise ValueError(f"invalid scenario in {path}: {exc}") from exc


def load_scenarios(root: str | Path) -> list[Scenario]:
    """Load and validate every scenario under ``root``, sorted by id.

    Raises if two scenarios share an id (would corrupt eval aggregation).
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"scenarios directory not found: {root}")
    files = sorted(p for p in root.rglob("*") if p.suffix in _SUFFIXES)
    scenarios = [load_scenario_file(p) for p in files]

    seen: set[str] = set()
    for s in scenarios:
        if s.id in seen:
            raise ValueError(f"duplicate scenario id: {s.id!r}")
        seen.add(s.id)

    return sorted(scenarios, key=lambda s: s.id)


def get_scenario(root: str | Path, scenario_id: str) -> Scenario:
    for s in load_scenarios(root):
        if s.id == scenario_id:
            return s
    raise KeyError(f"scenario not found: {scenario_id!r}")
