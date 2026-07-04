"""Deterministic value hashing for provenance and policy-input integrity."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def hash_value(value: Any) -> str:
    """Return a stable ``sha256:<hex>`` digest for a scalar or JSON-serializable value.

    Strings hash by their UTF-8 bytes; everything else hashes by its canonical
    (sorted-key) JSON encoding so that dict ordering never changes the digest.
    """
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
