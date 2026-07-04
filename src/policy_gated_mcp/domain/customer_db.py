"""Synthetic verified customer database (FR-4).

Deterministic lookups from a JSON fixture. A missing customer returns a safe
"not found" result — never fabricated data. The verified account is a *trusted*
source for the refund ``account_number``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel

_DEFAULT_DB_PATH = Path(__file__).resolve().parents[3] / "fixtures" / "customer_db.json"


class CustomerRecord(BaseModel):
    customer_id: str
    verified_account: str
    status: str


class CustomerLookup(BaseModel):
    found: bool
    customer_id: str
    record: CustomerRecord | None = None
    error: str | None = None


@lru_cache(maxsize=8)
def _load_db(path: str) -> dict[str, dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lookup_customer_record(customer_id: str, *, db_path: str | Path | None = None) -> CustomerLookup:
    """Return the verified record for ``customer_id`` or a safe not-found result."""
    path = str(db_path or _DEFAULT_DB_PATH)
    db = _load_db(path)
    raw = db.get(customer_id)
    if raw is None:
        return CustomerLookup(
            found=False,
            customer_id=customer_id,
            error=f"customer {customer_id} not found in verified database",
        )
    return CustomerLookup(found=True, customer_id=customer_id, record=CustomerRecord(**raw))
