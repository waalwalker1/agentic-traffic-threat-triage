import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
from src.traffic_triage.evidence.collector import EvidenceCollector
from src.traffic_triage.features.extractor import FeatureExtractor
from src.traffic_triage.identity.trust import IdentityEvaluator
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.observability.telemetry import setup_observability
from src.traffic_triage.risk.fusion import RiskPolicy
from src.traffic_triage.schemas.detection import DetectionResult, RiskBand
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle, EvidenceItem
from src.traffic_triage.telemetry.sessionizer import TelemetrySessionizer


@pytest.mark.asyncio
async def test_opentelemetry_triage_spans_in_memory():
    exporter = InMemorySpanExporter()
    processor = SimpleSpanProcessor(exporter)
    setup_observability(service_name="test-observability", span_processor=processor)

    crew = SOCTriageCrew(DeterministicLocalProvider())
    supervisor = DeterministicSupervisor(crew)

    bundle = CuratedEvidenceBundle(
        session_id="sess_otel_01",
        risk_score=0.88,
        risk_band="CRITICAL",
        detector_scores={"rules": 0.88},
        model_versions={"rules": "1.0"},
        evidence_items=[
            EvidenceItem(
                evidence_id="E-VOL-sess_otel_01-01",
                session_id="sess_otel_01",
                kind="volumetric",
                feature_name="requests_per_second",
                observed_value=50.0,
                expected_range_or_context="< 5.0 rps",
                human_readable_explanation="High burst rate",
            )
        ],
    )
    det = DetectionResult(
        session_id="sess_otel_01",
        rules_score=0.88,
        supervised_score=0.85,
        anomaly_score=0.80,
        pytorch_score=0.82,
        raw_model_score=0.84,
        calibrated_model_probability=0.86,
        policy_risk_score=0.88,
        calibrated_risk_score=0.88,
        risk_band=RiskBand.CRITICAL,
        evidence_ids=["E-VOL-sess_otel_01-01"],
    )

    brief = await supervisor.execute_triage(bundle, det)
    assert brief.incident_id is not None

    spans = exporter.get_finished_spans()
    span_names = [s.name for s in spans]

    assert "agent_identity" in span_names
    assert "agent_intent" in span_names
    assert "agent_mcp" in span_names
    assert "agent_synthesis" in span_names
    assert "critic" in span_names
    assert "supervisor_validation" in span_names


def test_opentelemetry_pipeline_instrumentation():
    exporter = InMemorySpanExporter()
    processor = SimpleSpanProcessor(exporter)
    setup_observability(service_name="test-pipeline-otel", span_processor=processor)

    event = TrafficEvent(
        event_id="evt_otel_01",
        schema_version="1.0.0",
        timestamp="2026-08-20T10:00:00Z",
        session_id="sess_pipe_otel",
        source_id_hash="src_otel_hash",
        request_method="GET",
        route_template="/api/v1/test",
        status_code=200,
        response_bytes=512,
        latency_ms=25.0,
        user_agent="OTelTestAgent/1.0",
        accept_language="en-US",
        header_names=["Host", "User-Agent"],
        content_type="application/json",
        has_auth_context=True,
    )

    sessionizer = TelemetrySessionizer()
    session = sessionizer.process_event(event)
    assert session is not None

    extractor = FeatureExtractor()
    features = extractor.extract(session)
    assert features is not None

    evaluator = IdentityEvaluator()
    id_ev = evaluator.evaluate(session)
    assert id_ev is not None

    mcp_analyzer = MCPSequenceAnalyzer()
    mcp_ev = mcp_analyzer.analyze(session)
    assert mcp_ev is not None

    policy = RiskPolicy()
    fusion_det = policy.fuse_scores(
        session_id=session.session_id,
        rules_score=0.2,
        supervised_score=0.1,
        anomaly_score=0.0,
        pytorch_score=0.1,
        calibrated_probability=0.15,
        identity_evidence=id_ev,
        mcp_evidence=mcp_ev,
    )
    assert fusion_det is not None

    collector = EvidenceCollector()
    bundle = collector.collect(
        session_id=session.session_id,
        features=features,
        identity_evidence=id_ev,
        mcp_evidence=mcp_ev,
        detection_result=fusion_det,
    )
    assert bundle is not None
