.PHONY: help setup data train dev api web lint typecheck test test-integration test-e2e eval red-team demo security build docker-smoke release-check clean-generated

PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
MYPY ?= .venv/bin/mypy

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
	@echo "  make test             - Run unit tests"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-e2e         - Run frontend / API E2E tests"
	@echo "  make eval             - Run complete evaluation suite (detection, groundedness, injection, ablations)"
	@echo "  make red-team         - Run adversarial prompt-injection test suite"
	@echo "  make demo             - Run offline CLI triage demo"
	@echo "  make security         - Run dependency security audit & defensive boundary check"
	@echo "  make build            - Build frontend and verify wheel build"
	@echo "  make docker-smoke     - Test container builds and run API/web health check"
	@echo "  make release-check    - Execute full verification pipeline for release gating"
	@echo "  make clean-generated  - Remove generated synthetic data, models, and temp caches"

setup:
	uv sync --extra dev --extra cloud
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
	$(RUFF) check src tests tools evals apps
	$(RUFF) format --check src tests tools evals apps

typecheck:
	$(MYPY)
	npm run typecheck

test:
	$(PYTEST) tests/unit tests/protocol

test-integration:
	$(PYTEST) tests/integration

test-e2e:
	$(PYTHON) tests/e2e/test_api_e2e.py

eval:
	$(PYTHON) -m evals.runners.benchmark --data-dir data/fixtures --output-dir artifacts/evals/latest

red-team:
	$(PYTEST) tests/security/test_prompt_injection.py tests/security/test_defensive_boundary.py

demo:
	$(PYTHON) -m scripts.run_demo

security:
	$(PYTHON) scripts/check_defensive_boundary.py
	$(PYTHON) scripts/check_public_normalization.py
	$(PYTHON) scripts/check_doc_links.py
	$(PYTHON) scripts/sync_public_metrics.py --check

build:
	npm run build
	uv build

docker-smoke:
	$(PYTHON) scripts/docker_smoke.py

release-check:
	@echo "=== Stage 01: Data Generation & Model Training ==="
	$(PYTHON) -m tools.synthetic_traffic.generator --seed 42 --output-dir data/fixtures --sample-dir data/samples
	$(PYTHON) -m src.traffic_triage.detection.train --data-dir data/fixtures --output-dir artifacts/model_cards
	@echo "=== Stage 02: Python & Frontend Linting ==="
	$(RUFF) check src tests tools evals apps
	$(RUFF) format --check src tests tools evals apps
	npm run lint
	@echo "=== Stage 03: Static Type Checking ==="
	$(MYPY)
	npm run typecheck
	@echo "=== Stage 04: Unit, Protocol & Security Tests ==="
	$(PYTEST) tests/unit tests/protocol tests/security
	@echo "=== Stage 05: Integration Tests ==="
	$(PYTEST) tests/integration
	@echo "=== Stage 06: Full Benchmark Suite ==="
	$(PYTHON) -m evals.runners.benchmark --data-dir data/fixtures --output-dir artifacts/evals/latest
	$(PYTHON) scripts/generate_model_card.py
	@echo "=== Stage 07: Public Metrics Synchronization Check ==="
	$(PYTHON) scripts/sync_public_metrics.py --check
	@echo "=== Stage 08: Frontend Tests & Production Build ==="
	npm run test
	npm run build
	@echo "=== Stage 09: Security & Public Hygiene Audits ==="
	$(PYTHON) scripts/check_defensive_boundary.py
	$(PYTHON) scripts/check_public_normalization.py
	$(PYTHON) scripts/check_doc_links.py
	@echo "=== Stage 10: Docker Smoke Validation ==="
	$(PYTHON) scripts/docker_smoke.py --allow-missing-docker
	@echo "=== ALL RELEASE QUALITY GATES PASSED! ==="

clean-generated:
	rm -rf data/fixtures/*.parquet data/fixtures/*.duckdb artifacts/evals/latest/* .pytest_cache .mypy_cache .ruff_cache apps/web/dist

