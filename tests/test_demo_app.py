"""Smoke test for the Streamlit demo. Skipped unless the `demo` extra (streamlit) is
installed, so it never affects the default keyless test path or CI's `.[dev]` install."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / "demo" / "app.py")


def _radio(at, label):
    for r in at.radio:
        if r.label == label:
            return r
    raise AssertionError(f"radio {label!r} not found")


def test_demo_boots_and_defense_flips_outcome():
    at = AppTest.from_file(APP, default_timeout=120).run()
    assert not at.exception, at.exception

    # Default: an attack scenario, no defense, vulnerable model -> attack succeeds.
    assert any("ATTACK SUCCEEDED" in e.value for e in at.error)

    # Flip on the provenance/OPA gate -> the same attack is blocked.
    _radio(at, "Defense mode").set_value("provenance_opa")
    at.run()
    assert not at.exception, at.exception
    assert any("blocked" in s.value.lower() for s in at.success)
    assert any("Deny reasons" in e.value for e in at.error)
