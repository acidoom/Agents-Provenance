"""Model adapters. Fake profiles are the default; optional real adapters (FR-9) are
loaded lazily and never required for tests/eval."""

from __future__ import annotations

from .base import FakeProfile, Model, ModelContext, PoisonSignal, parse_model_spec
from .fake import FakeModel

__all__ = [
    "Model",
    "ModelContext",
    "PoisonSignal",
    "FakeProfile",
    "FakeModel",
    "parse_model_spec",
    "get_model",
]


def get_model(spec: str) -> Model:
    """Resolve a model spec such as ``fake:vulnerable_agent`` to a Model instance.

    Real adapters (``openai:``, ``anthropic:``, ``ollama:``) are imported lazily so
    their optional dependencies never affect the default path.
    """
    kind, name = parse_model_spec(spec)
    if kind == "fake":
        try:
            profile = FakeProfile(name)
        except ValueError as exc:
            valid = ", ".join(p.value for p in FakeProfile)
            raise ValueError(f"unknown fake profile {name!r}; valid: {valid}") from exc
        return FakeModel(profile)

    if kind in {"openai", "anthropic", "ollama"}:
        from .adapters import get_real_model  # lazy; may raise if extra not installed

        return get_real_model(kind, name)

    raise ValueError(f"unknown model kind {kind!r} (expected fake/openai/anthropic/ollama)")
