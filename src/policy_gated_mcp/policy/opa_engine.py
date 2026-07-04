"""OPA CLI policy engine adapter.

Shells out to `opa eval --stdin-input --format=json -d <policy_dir> 'data.mcp.refund'`
and parses the decision at result[0].expressions[0].value. This is the authoritative
engine when the `opa` binary is available.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..provenance.hashing import hash_value
from .decisions import PolicyDecision
from .engine import POLICY_ID

QUERY = "data.mcp.refund"


class OpaError(RuntimeError):
    pass


def opa_available(opa_path: str | None = None) -> bool:
    return (opa_path or shutil.which("opa")) is not None


class OpaPolicyEngine:
    name = "opa"

    def __init__(
        self,
        policy_dir: str | Path,
        *,
        query: str = QUERY,
        opa_path: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.policy_dir = Path(policy_dir)
        self.query = query
        self.opa_path = opa_path or shutil.which("opa")
        self.timeout = timeout
        if not self.opa_path:
            raise OpaError("opa binary not found on PATH (install with `make install-opa`)")

    def evaluate(self, policy_input: dict) -> PolicyDecision:
        proc = subprocess.run(
            [
                self.opa_path,
                "eval",
                "--stdin-input",
                "--format=json",
                "-d",
                str(self.policy_dir),
                self.query,
            ],
            input=json.dumps(policy_input),
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            raise OpaError(f"opa eval failed: {proc.stderr.strip() or proc.stdout.strip()}")
        try:
            data = json.loads(proc.stdout)
            decision = data["result"][0]["expressions"][0]["value"]
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            raise OpaError(f"unexpected opa output: {proc.stdout[:500]!r}") from exc
        return PolicyDecision.from_rego(
            decision,
            policy_id=POLICY_ID,
            input_hash=hash_value(policy_input),
            engine=self.name,
        )
