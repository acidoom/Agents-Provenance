"""Optional real-model adapters (FR-9) — SEAM ONLY.

Disabled by default and never imported on the deterministic path. Real adapters must:
(1) never fail tests when API keys/extras are absent, (2) log model name + params in
result metadata, and (3) still route every high-impact proposal through the policy gate.

Implementing these is future work; the seam exists so wiring one in does not touch the
runner. `get_model("openai:gpt-...")` reaches here lazily.
"""

from __future__ import annotations

from .base import Model


def get_real_model(kind: str, name: str) -> Model:  # pragma: no cover - not on default path
    raise NotImplementedError(
        f"real model adapter '{kind}:{name}' is not implemented in v1. "
        f"Install the extra (pip install -e '.[{kind}]') and implement this adapter; "
        "the default deterministic path uses fake:<profile> and needs no API keys."
    )
