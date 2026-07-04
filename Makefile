# Policy-Gated MCP — developer tasks
#
# The .venv is kept OUT of iCloud Drive (avoids file-sync locking) by pointing
# UV_PROJECT_ENVIRONMENT at a local path. Override by exporting it yourself.

OPA_VERSION ?= 1.18.2
LOCAL_BIN := $(CURDIR)/bin
export PATH := $(LOCAL_BIN):$(PATH)
export UV_PROJECT_ENVIRONMENT ?= $(HOME)/.uv-envs/policy-gated-mcp

# Detect uv; fall back to plain python/pip if absent.
UV := $(shell command -v uv 2>/dev/null)
ifeq ($(UV),)
  PY := python3
  RUN :=
else
  PY := uv run python
  RUN := uv run
endif

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Create env and install the package with dev extras
ifeq ($(UV),)
	$(PY) -m pip install -e ".[dev]"
else
	uv sync --extra dev
endif

.PHONY: test
test: ## Run the full test suite (OPA tests skip if `opa` is absent)
	$(RUN) pytest

.PHONY: lint
lint: ## Ruff + mypy
	$(RUN) ruff check src tests
	$(RUN) mypy

.PHONY: eval
eval: ## Run the full evaluation and write reports/weekend_eval/
	$(RUN) python -m policy_gated_mcp.cli eval \
	  --scenarios scenarios \
	  --model fake:vulnerable_agent \
	  --defenses all \
	  --out reports/weekend_eval

.PHONY: report
report: ## Regenerate the Markdown summary from existing results
	$(RUN) python -m policy_gated_mcp.cli report \
	  --results reports/weekend_eval/results.jsonl \
	  --out reports/weekend_eval/eval_summary.md

.PHONY: list-scenarios
list-scenarios: ## List all loaded scenarios
	$(RUN) python -m policy_gated_mcp.cli list-scenarios

.PHONY: opa-test
opa-test: ## Run Rego unit tests (requires opa)
	opa test policy -v

.PHONY: install-opa
install-opa: ## Install the opa CLI (brew if available, else pinned binary into ./bin)
	@if command -v opa >/dev/null 2>&1; then \
	  echo "opa already installed: $$(opa version | head -1)"; \
	elif command -v brew >/dev/null 2>&1; then \
	  brew install opa; \
	else \
	  mkdir -p $(LOCAL_BIN); \
	  arch=$$(uname -m); os=$$(uname -s | tr 'A-Z' 'a-z'); \
	  if [ "$$arch" = "arm64" ]; then arch=arm64; else arch=amd64; fi; \
	  url="https://github.com/open-policy-agent/opa/releases/download/v$(OPA_VERSION)/opa_$${os}_$${arch}"; \
	  echo "Downloading $$url"; \
	  curl -sSL -o $(LOCAL_BIN)/opa "$$url"; \
	  chmod +x $(LOCAL_BIN)/opa; \
	  echo "Installed $$($(LOCAL_BIN)/opa version | head -1) into $(LOCAL_BIN)"; \
	fi

.PHONY: clean
clean: ## Remove caches and generated eval output
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__
	rm -rf reports/weekend_eval/results.jsonl reports/weekend_eval/summary.csv reports/weekend_eval/traces
