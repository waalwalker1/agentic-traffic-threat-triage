"""FastAPI production REST API service for Agentic Traffic Threat Triage."""

import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
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
        self.unsupervised_detector = UnsupervisedAnomalyDetector()
        self.supervised_classifier = SupervisedThreatClassifier()
        self.pytorch_detector = PyTorchThreatDetector()
        self.risk_policy = RiskPolicy()
        self.evidence_collector = EvidenceCollector()

        # Offline deterministic triage crew & supervisor
        self.llm_provider = DeterministicLocalProvider()
        self.crew = SOCTriageCrew(self.llm_provider)
        self.supervisor = DeterministicSupervisor(self.crew)


container = ServiceContainer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize / Seed models if fixtures exist
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
def readiness_check() -> dict[str, str]:
    return {"status": "ready", "database": "connected"}


@app.get("/metrics", tags=["System"])
def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


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
        "events": [e.model_dump(mode="json") for e in events[:50]],  # cap sample
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

    rules_res = container.rules_detector.evaluate(fv)
    iso_score = container.unsupervised_detector.predict_score(fv)
    sup_score = container.supervised_classifier.predict_proba(fv)
    pyt_score = container.pytorch_detector.predict_score(fv)

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

    rules_res = container.rules_detector.evaluate(fv)
    iso_score = container.unsupervised_detector.predict_score(fv)
    sup_score = container.supervised_classifier.predict_proba(fv)
    pyt_score = container.pytorch_detector.predict_score(fv)

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
