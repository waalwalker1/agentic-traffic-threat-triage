import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.observability.telemetry import setup_observability
from src.traffic_triage.schemas.detection import DetectionResult, RiskBand
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle, EvidenceItem


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
