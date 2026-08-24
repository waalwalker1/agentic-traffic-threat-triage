"""FastAPI production REST API service for Agentic Traffic Threat Triage."""

import json
import logging
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
from src.traffic_triage.detection.calibration import ScoreCalibrator
from src.traffic_triage.detection.model_bundle import (
    ModelBundle,
    ModelBundleError,
    ModelBundleLoader,
)
from src.traffic_triage.detection.pytorch_model import PyTorchThreatDetector
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.detection.supervised import SupervisedThreatClassifier
from src.traffic_triage.detection.unsupervised import UnsupervisedAnomalyDetector
from src.traffic_triage.evidence.collector import EvidenceCollector
from src.traffic_triage.features.extractor import FeatureExtractor
from src.traffic_triage.identity.trust import IdentityEvaluator
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.persistence.duckdb_store import DuckDBStore
from src.traffic_triage.risk.fusion import RiskPolicy
from src.traffic_triage.schemas.detection import DetectionResult
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.incidents import (
    AnalystDisposition,
    DispositionStatus,
    IncidentBrief,
)
from src.traffic_triage.telemetry.sessionizer import TelemetrySessionizer

logger = logging.getLogger(__name__)

# Prometheus Metrics
REQUEST_COUNT = Counter(
    "triage_api_requests_total", "Total API requests", ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram("triage_api_latency_seconds", "API request latency", ["endpoint"])
INCIDENTS_CREATED = Counter(
    "triage_incidents_total", "Total incident briefs created", ["risk_band"]
)


class ServiceContainer:
    def __init__(self) -> None:
        db_path = os.getenv("DUCKDB_PATH", ":memory:")
        self.store = DuckDBStore(db_path=db_path)
        self.sessionizer = TelemetrySessionizer()
        self.feature_extractor = FeatureExtractor()
        self.identity_evaluator = IdentityEvaluator()
        self.mcp_analyzer = MCPSequenceAnalyzer()
        self.rules_detector = RuleBaselineDetector()
        self.risk_policy = RiskPolicy()
        self.evidence_collector = EvidenceCollector()

        # Model bundle lifecycle
        self.model_mode = os.getenv("MODEL_MODE", "trained")
        self.bundle_dir = os.getenv("MODEL_BUNDLE_DIR", "artifacts/model_cards/current")
        self.bundle: ModelBundle | None = None
        self.models_loaded = False
        self.load_error: str | None = None

        self.supervised_classifier: SupervisedThreatClassifier | None = None
        self.unsupervised_detector: UnsupervisedAnomalyDetector | None = None
        self.pytorch_detector: PyTorchThreatDetector | None = None
        self.calibrator: ScoreCalibrator | None = None

        self._initialize_models()

        # Offline deterministic triage crew & supervisor
        self.llm_provider = DeterministicLocalProvider()
        self.crew = SOCTriageCrew(self.llm_provider)
        self.supervisor = DeterministicSupervisor(self.crew)

    def _initialize_models(self) -> None:
        if self.model_mode == "explicit_untrained_demo":
            logger.warning("Running in EXPLICIT UNTRAINED DEMO mode.")
            self.unsupervised_detector = UnsupervisedAnomalyDetector()
            self.supervised_classifier = SupervisedThreatClassifier()
            self.pytorch_detector = PyTorchThreatDetector()
            self.calibrator = ScoreCalibrator()
            self.models_loaded = False
            return

        try:
            self.bundle = ModelBundleLoader.load(self.bundle_dir)
            self.supervised_classifier = self.bundle.supervised
            self.unsupervised_detector = self.bundle.anomaly
            self.pytorch_detector = self.bundle.pytorch
            self.calibrator = self.bundle.calibrator
            self.models_loaded = True
            logger.info("Successfully loaded trained ModelBundle from %s", self.bundle_dir)
        except (ModelBundleError, FileNotFoundError, Exception) as err:
            self.load_error = str(err)
            self.models_loaded = False
            logger.error("Failed to load ModelBundle from %s: %s", self.bundle_dir, err)


container = ServiceContainer()


def lifespan(app: FastAPI):
    parquet_path = Path("data/fixtures/traffic_dataset.parquet")
    if parquet_path.exists():
        from src.traffic_triage.detection.train import load_parquet_events

        events = load_parquet_events(str(parquet_path))
        container.store.save_events(events)
        sessions = container.sessionizer.sessionize(events)
        for s in sessions:
            container.store.save_session(s)
            fv = container.feature_extractor.extract_features(s.events, s.session_id)
            container.store.save_features(fv)
    yield
    container.store.close()


app = FastAPI(
    title="Agentic Traffic Threat Triage API",
    version="0.1.0",
    description="Defensive Traffic Threat Analysis and SOC Incident Briefing Service",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_and_correlate(request: Request, call_next: Any) -> Response:
    trace_id = request.headers.get("X-Correlation-ID", f"req_{uuid.uuid4().hex[:12]}")
    start_time = time.time()
    response = await call_next(request)
    latency = time.time() - start_time
    response.headers["X-Correlation-ID"] = trace_id
    REQUEST_COUNT.labels(
        method=request.method, endpoint=request.url.path, status=str(response.status_code)
    ).inc()
    REQUEST_LATENCY.labels(endpoint=request.url.path).observe(latency)
    return response


# --- Health, Readiness, and Metrics ---


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.get("/ready", tags=["System"])
def readiness_check() -> dict[str, Any]:
    if container.model_mode == "trained" and not container.models_loaded:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "model_mode": container.model_mode,
                "models_loaded": False,
                "error": container.load_error or "Model bundle failed to load",
                "database": "connected",
            },
        )
    return {
        "status": "ready",
        "model_mode": container.model_mode,
        "models_loaded": container.models_loaded,
        "bundle_version": container.bundle.manifest.bundle_version if container.bundle else "none",
        "feature_schema_version": "1.0.0",
        "risk_policy_version": container.risk_policy.version,
        "database": "connected",
    }


@app.get("/metrics", tags=["System"])
def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/system/models", tags=["System"])
def get_system_models() -> dict[str, Any]:
    if not container.bundle:
        return {
            "model_mode": container.model_mode,
            "models_loaded": False,
            "error": container.load_error,
            "manifest": None,
        }
    return {
        "model_mode": container.model_mode,
        "models_loaded": True,
        "bundle_version": container.bundle.manifest.bundle_version,
        "feature_schema_version": container.bundle.manifest.feature_schema_version,
        "risk_policy_version": container.bundle.manifest.risk_policy_version,
        "dataset_sha256": container.bundle.manifest.dataset_sha256,
        "trained_at": container.bundle.manifest.trained_at,
        "component_versions": {
            "rules": "1.0.0",
            "supervised": container.bundle.manifest.supervised_model_version,
            "anomaly": container.bundle.manifest.anomaly_model_version,
            "pytorch": container.bundle.manifest.pytorch_model_version,
            "calibrator": container.bundle.manifest.calibrator_version,
        },
    }


# --- Request/Response DTOs ---


class IngestRequest(BaseModel):
    events: list[TrafficEvent]


class IngestResponse(BaseModel):
    events_ingested: int
    sessions_updated: list[str]


class DispositionRequest(BaseModel):
    disposition: DispositionStatus
    notes: str = Field(default="", max_length=2000)


# --- API Endpoints ---


@app.post("/api/v1/ingest", response_model=IngestResponse, tags=["Ingest"])
def ingest_events(payload: IngestRequest) -> IngestResponse:
    if not payload.events:
        raise HTTPException(status_code=400, detail="Empty event batch")
    container.store.save_events(payload.events)
    sessions = container.sessionizer.sessionize(payload.events)
    session_ids = []
    for s in sessions:
        container.store.save_session(s)
        fv = container.feature_extractor.extract_features(s.events, s.session_id)
        container.store.save_features(fv)
        session_ids.append(s.session_id)
    return IngestResponse(events_ingested=len(payload.events), sessions_updated=session_ids)


@app.get("/api/v1/sessions", tags=["Sessions"])
def list_sessions(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    return container.store.list_sessions(limit=limit, offset=offset)


@app.get("/api/v1/sessions/{session_id}", tags=["Sessions"])
def get_session(session_id: str) -> dict[str, Any]:
    sess = container.store.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    events = container.store.get_events_for_session(session_id)
    evidence = container.store.get_evidence_for_session(session_id)
    return {
        "session": sess,
        "event_count": len(events),
        "events": [e.model_dump(mode="json") for e in events[:50]],
        "evidence_items": evidence,
    }


@app.post(
    "/api/v1/sessions/{session_id}/detect", response_model=DetectionResult, tags=["Detection"]
)
def run_detection(session_id: str) -> DetectionResult:
    events = container.store.get_events_for_session(session_id)
    if not events:
        raise HTTPException(status_code=404, detail="Session not found or has no events")

    fv = container.feature_extractor.extract_features(events, session_id)
    id_eval = container.identity_evaluator.evaluate_session_identity(events)
    mcp_m = container.mcp_analyzer.analyze_session(events)

    ev_items = container.evidence_collector.collect_evidence(session_id, fv, events, id_eval, mcp_m)
    container.store.save_evidence_items(ev_items)

    if container.bundle:
        det = container.bundle.evaluate_session(fv, container.rules_detector, container.risk_policy)
        det.evidence_ids = [e.evidence_id for e in ev_items]
    else:
        # Explicit untrained / fallback
        rules_res = container.rules_detector.evaluate(fv)
        iso_score = (
            container.unsupervised_detector.predict_score(fv)
            if container.unsupervised_detector
            else 0.5
        )
        sup_score = (
            container.supervised_classifier.predict_proba(fv)
            if container.supervised_classifier
            else 0.5
        )
        pyt_score = (
            container.pytorch_detector.predict_score(fv) if container.pytorch_detector else 0.5
        )

        det = container.risk_policy.fuse_scores(
            session_id=session_id,
            fv=fv,
            rules_score=rules_res.score,
            supervised_score=sup_score,
            anomaly_score=iso_score,
            pytorch_score=pyt_score,
            reason_codes=rules_res.reason_codes,
            evidence_ids=[e.evidence_id for e in ev_items],
        )

    container.store.save_detection_result(det)
    return det


@app.post("/api/v1/sessions/{session_id}/triage", response_model=IncidentBrief, tags=["Triage"])
async def run_triage(session_id: str) -> IncidentBrief:
    events = container.store.get_events_for_session(session_id)
    if not events:
        raise HTTPException(status_code=404, detail="Session not found")

    fv = container.feature_extractor.extract_features(events, session_id)
    id_eval = container.identity_evaluator.evaluate_session_identity(events)
    mcp_m = container.mcp_analyzer.analyze_session(events)

    ev_items = container.evidence_collector.collect_evidence(session_id, fv, events, id_eval, mcp_m)
    container.store.save_evidence_items(ev_items)

    if container.bundle:
        det = container.bundle.evaluate_session(fv, container.rules_detector, container.risk_policy)
        det.evidence_ids = [e.evidence_id for e in ev_items]
    else:
        rules_res = container.rules_detector.evaluate(fv)
        iso_score = (
            container.unsupervised_detector.predict_score(fv)
            if container.unsupervised_detector
            else 0.5
        )
        sup_score = (
            container.supervised_classifier.predict_proba(fv)
            if container.supervised_classifier
            else 0.5
        )
        pyt_score = (
            container.pytorch_detector.predict_score(fv) if container.pytorch_detector else 0.5
        )

        det = container.risk_policy.fuse_scores(
            session_id=session_id,
            fv=fv,
            rules_score=rules_res.score,
            supervised_score=sup_score,
            anomaly_score=iso_score,
            pytorch_score=pyt_score,
            reason_codes=rules_res.reason_codes,
            evidence_ids=[e.evidence_id for e in ev_items],
        )

    container.store.save_detection_result(det)

    bundle = container.evidence_collector.build_bundle(session_id, det, ev_items, events)
    brief = await container.supervisor.execute_triage(bundle, det)
    container.store.save_incident(brief)
    INCIDENTS_CREATED.labels(risk_band=brief.risk_band.value).inc()
    return brief


@app.get("/api/v1/incidents", tags=["Incidents"])
def list_incidents(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    return container.store.list_incidents(limit=limit, offset=offset)


@app.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
def get_incident(incident_id: str) -> dict[str, Any]:
    inc = container.store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.post("/api/v1/incidents/{incident_id}/disposition", tags=["Incidents"])
def update_disposition(incident_id: str, payload: DispositionRequest) -> dict[str, str]:
    inc = container.store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    disp = AnalystDisposition(
        disposition=payload.disposition,
        notes=payload.notes,
        applied_at=datetime.now(UTC),
    )
    container.store.update_disposition(incident_id, disp)
    return {"status": "updated", "incident_id": incident_id}


@app.get("/api/v1/evals/latest", tags=["Evaluations"])
def get_latest_eval_summary() -> dict[str, Any]:
    summary_path = Path("artifacts/evals/latest/summary.json")
    if not summary_path.exists():
        return {
            "status": "pending",
            "message": "Benchmark evaluations have not run yet. Run 'make eval' to generate.",
        }
    with open(summary_path) as f:
        return json.load(f)
