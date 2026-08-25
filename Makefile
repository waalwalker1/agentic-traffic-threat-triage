.PHONY: help setup data train dev api web lint typecheck test test-integration test-e2e eval red-team demo security build docker-smoke verify-local release-check clean-generated

PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
MYPY ?= .venv/bin/mypy
PIP_AUDIT ?= .venv/bin/pip-audit
BANDIT ?= .venv/bin/bandit
DETECT_SECRETS ?= .venv/bin/detect-secrets

COVERAGE_FAIL_UNDER ?= 80

help:
	@echo "Agentic Traffic Threat Triage - Command Interface"
	@echo ""
	@echo "Development:"
	@echo "  make setup            - Install Python and Node dependencies"
	@echo "  make data             - Generate deterministic synthetic traffic dataset"
	@echo "  make train            - Train ML and PyTorch baseline models"
	@echo "  make dev              - Start API and Web servers concurrently"
	@echo "  make api              - Start FastAPI backend service"
	@echo "  make web              - Start Vite frontend development server"
	@echo ""
	@echo "Verification & Quality:"
	@echo "  make lint             - Run Python and frontend linters"
	@echo "  make typecheck        - Run Python mypy and TypeScript typecheck"
	@echo "  make test             - Run unit and protocol tests"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-e2e         - Run frontend Playwright / API E2E tests"
	@echo "  make eval             - Run complete evaluation suite"
	@echo "  make red-team         - Run adversarial prompt-injection test suite"
	@echo "  make demo             - Run offline CLI triage demo"
	@echo "  make security         - Run dependency security audit & defensive boundary check"
	@echo "  make build            - Build frontend and verify wheel build"
	@echo "  make docker-smoke     - Test container builds and run full transaction"
	@echo "  make verify-local     - Developer verification (allows missing Docker)"
	@echo "  make release-check    - Strict release gating verification (requires Docker)"
	@echo "  make clean-generated  - Remove generated synthetic data, models, and temp caches"

setup:
	uv sync --extra dev --extra cloud --extra agents
	npm install

data:
	$(PYTHON) -m tools.synthetic_traffic.generator --seed 42 --output-dir data/fixtures --sample-dir data/samples

train:
	$(PYTHON) -m src.traffic_triage.detection.train --data-dir data/fixtures --output-dir artifacts/model_cards

api:
	$(PYTHON) -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

web:
	npm run dev

dev:
	@echo "Run 'make api' and 'make web' in separate terminals or use docker-compose up."

lint:
	$(RUFF) check src tests tools evals apps scripts
	$(RUFF) format --check src tests tools evals apps scripts
	npm run lint

typecheck:
	$(MYPY)
	npm run typecheck

test:
	$(PYTEST) tests/unit tests/protocol tests/security

test-integration:
	$(PYTEST) tests/integration

test-e2e:
	npm run test:e2e

eval:
	$(PYTHON) -m evals.runners.benchmark --data-dir data/fixtures --output-dir artifacts/evals/latest
	$(PYTHON) scripts/generate_model_card.py
	$(PYTHON) scripts/sync_public_metrics.py --write
	$(PYTHON) scripts/generate_security_release_audit.py --write

red-team:
	$(PYTEST) tests/security/test_prompt_injection.py tests/security/test_defensive_boundary.py

demo:
	$(PYTHON) -m scripts.run_demo

security:
	$(PYTHON) scripts/check_defensive_boundary.py
	$(PYTHON) scripts/check_public_normalization.py
	$(PYTHON) scripts/check_doc_links.py
	$(PYTHON) scripts/sync_public_metrics.py --check
	$(PYTHON) scripts/generate_security_release_audit.py --check
	$(PIP_AUDIT)
	npm audit --audit-level=high
	$(BANDIT) -r src/ -ll

build:
	npm run build
	uv build

docker-smoke:
	$(PYTHON) scripts/docker_smoke.py

verify-local:
	@echo "=== Stage 01: Data Generation & Model Training ==="
	$(PYTHON) -m tools.synthetic_traffic.generator --seed 42 --output-dir data/fixtures --sample-dir data/samples
	$(PYTHON) -m src.traffic_triage.detection.train --data-dir data/fixtures --output-dir artifacts/model_cards
	@echo "=== Stage 02: Python & Frontend Linting ==="
	$(RUFF) check src tests tools evals apps scripts
	$(RUFF) format --check src tests tools evals apps scripts
	npm run lint
	@echo "=== Stage 03: Static Type Checking ==="
	$(MYPY)
	npm run typecheck
	@echo "=== Stage 04: Python Tests with Coverage ==="
	$(PYTEST) tests/unit tests/protocol tests/security tests/integration --cov=src/traffic_triage --cov-branch --cov-report=term-missing --cov-fail-under=$(COVERAGE_FAIL_UNDER)
	@echo "=== Stage 05: Benchmark & Public Metrics Synchronization ==="
	$(PYTHON) -m evals.runners.benchmark --data-dir data/fixtures --output-dir artifacts/evals/latest
	$(PYTHON) scripts/generate_model_card.py
	$(PYTHON) scripts/sync_public_metrics.py --check
	$(PYTHON) scripts/generate_security_release_audit.py --check
	@echo "=== Stage 06: Frontend Tests & Production Build ==="
	npm run test
	npm run build
	@echo "=== Stage 07: Security & Public Hygiene Audits ==="
	$(PYTHON) scripts/check_defensive_boundary.py
	$(PYTHON) scripts/check_public_normalization.py
	$(PYTHON) scripts/check_doc_links.py
	$(PIP_AUDIT)
	npm audit --audit-level=high
	$(BANDIT) -r src/ -ll
	@echo "=== Stage 08: Local Docker Smoke (--allow-missing-docker) ==="
	$(PYTHON) scripts/docker_smoke.py --allow-missing-docker
	@echo "=== LOCAL VERIFICATION PASSED ==="

release-check:
	@echo "=== Stage 01: Clean-room Data Generation & Model Training ==="
	$(PYTHON) -m tools.synthetic_traffic.generator --seed 42 --output-dir data/fixtures --sample-dir data/samples
	$(PYTHON) -m src.traffic_triage.detection.train --data-dir data/fixtures --output-dir artifacts/model_cards
	@echo "=== Stage 02: Python & Frontend Linting ==="
	$(RUFF) check src tests tools evals apps scripts
	$(RUFF) format --check src tests tools evals apps scripts
	npm run lint
	@echo "=== Stage 03: Static Type Checking ==="
	$(MYPY)
	npm run typecheck
	@echo "=== Stage 04: Unit, Protocol, Security & Integration Tests with Coverage ==="
	$(PYTEST) tests/unit tests/protocol tests/security tests/integration --cov=src/traffic_triage --cov-branch --cov-report=term-missing --cov-fail-under=$(COVERAGE_FAIL_UNDER)
	@echo "=== Stage 05: Complete Benchmark Suite ==="
	$(PYTHON) -m evals.runners.benchmark --data-dir data/fixtures --output-dir artifacts/evals/latest
	$(PYTHON) scripts/generate_model_card.py
	@echo "=== Stage 06: Metrics, Audit & Model Card Drift Checks ==="
	$(PYTHON) scripts/sync_public_metrics.py --check
	$(PYTHON) scripts/generate_security_release_audit.py --check
	@echo "=== Stage 07: Frontend Tests & Production Build ==="
	npm run test
	npm run build
	@echo "=== Stage 08: Browser Playwright E2E ==="
	npm run test:e2e
	@echo "=== Stage 09: Security Scanning (pip-audit, npm audit, bandit, detect-secrets) ==="
	$(PIP_AUDIT)
	npm audit --audit-level=high
	$(BANDIT) -r src/ -ll
	@echo "=== Stage 10: Public Hygiene & Boundary Checks ==="
	$(PYTHON) scripts/check_defensive_boundary.py
	$(PYTHON) scripts/check_public_normalization.py
	$(PYTHON) scripts/check_doc_links.py
	@echo "=== Stage 11: Strict Docker Smoke (Requires Running Docker) ==="
	$(PYTHON) scripts/docker_smoke.py
	@echo "=== ALL STRICT RELEASE QUALITY GATES PASSED! ==="

clean-generated:
	rm -rf data/fixtures/*.parquet data/fixtures/*.duckdb artifacts/evals/latest/* .pytest_cache .mypy_cache .ruff_cache apps/web/dist
