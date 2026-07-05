# A no-local-install path: bundles the `opa` CLI + the harness so `docker run` executes
# the real OPA/Rego gate with no local Python/opa/uv needed.
FROM python:3.11-slim

ARG OPA_VERSION=1.18.2
ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates make git \
 && rm -rf /var/lib/apt/lists/* \
 && case "$TARGETARCH" in \
        arm64) OPA_ASSET=opa_linux_arm64_static ;; \
        *) OPA_ASSET=opa_linux_amd64_static ;; \
    esac \
 && curl -sSL -o /usr/local/bin/opa \
        "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/${OPA_ASSET}" \
 && chmod +x /usr/local/bin/opa \
 && opa version

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e ".[dev]"

# Default: run the deterministic evaluation (real OPA engine) and print the report.
CMD ["sh", "-c", "python -m policy_gated_mcp.cli eval --out reports/weekend_eval && cat reports/weekend_eval/eval_summary.md"]
