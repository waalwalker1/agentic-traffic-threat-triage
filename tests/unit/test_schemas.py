from datetime import UTC, datetime

from src.traffic_triage.schemas.detection import DetectionResult, RiskBand
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle, EvidenceItem
from src.traffic_triage.schemas.incidents import (
    AnalystDisposition,
    CriticReview,
    DispositionStatus,
    IncidentBrief,
    IntentHypothesis,
)
from src.traffic_triage.schemas.sessions import TrafficSession


def test_traffic_event_creation():
    event = TrafficEvent(
        event_id="evt_001",
        session_id="sess_001",
        source_id_hash="a1b2c3d4e5f6",
        request_method="GET",
        route_template="/api/v1/products",
        status_code=200,
        response_bytes=1024,
        latency_ms=45.2,
        user_agent="Mozilla/5.0 (DefensiveResearchBot/1.0)",
        accept_language="en-US,en;q=0.9",
        header_names=["User-Agent", "Accept", "Accept-Language"],
        has_auth_context=False,
        identity_claim="research-bot",
        identity_proof_type="ed25519_signature",
        identity_proof_valid=True,
    )
    assert event.event_id == "evt_001"
    assert event.status_code == 200
    assert event.identity_proof_valid is True
    assert event.timestamp.tzinfo is not None


def test_traffic_session_aggregation():
    now = datetime.now(UTC)
    event = TrafficEvent(
        event_id="evt_001",
        session_id="sess_001",
        source_id_hash="a1b2c3d4e5f6",
        request_method="GET",
        route_template="/api/v1/products",
    )
    session = TrafficSession(
        session_id="sess_001",
        start_time=now,
        end_time=now,
        event_count=1,
        duration_seconds=0.0,
        route_count=1,
        actor_claims=["research-bot"],
        events=[event],
    )
    assert session.session_id == "sess_001"
    assert len(session.events) == 1
    assert session.event_count == 1


def test_evidence_item_and_bundle():
    item = EvidenceItem(
        evidence_id="E-VOL-001",
        session_id="sess_001",
        kind="volumetric",
        source_event_ids=["evt_001"],
        feature_name="requests_per_second",
        observed_value=45.0,
        expected_range_or_context="< 5.0 rps for human baseline",
        severity_hint="high",
        human_readable_explanation="Request rate exceeded expected baseline by 9x",
    )
    bundle = CuratedEvidenceBundle(
        session_id="sess_001",
        risk_score=0.82,
        risk_band="HIGH",
        detector_scores={"rules": 0.85, "supervised": 0.80},
        model_versions={"rules": "1.0", "supervised": "1.0"},
        evidence_items=[item],
    )
    assert bundle.session_id == "sess_001"
    assert len(bundle.evidence_items) == 1
    assert bundle.evidence_items[0].evidence_id == "E-VOL-001"


def test_detection_result():
    res = DetectionResult(
        session_id="sess_001",
        rules_score=0.9,
        supervised_score=0.85,
        anomaly_score=0.7,
        pytorch_score=0.75,
        calibrated_risk_score=0.82,
        risk_band=RiskBand.HIGH,
        reason_codes=["BURST_REQUEST_RATE", "UNVERIFIED_AGENT_CLAIM"],
        evidence_ids=["E-VOL-001", "E-ID-001"],
    )
    assert res.risk_band == RiskBand.HIGH
    assert res.calibrated_risk_score == 0.82
    assert "E-VOL-001" in res.evidence_ids


def test_incident_brief_with_critic_and_disposition():
    hypo = IntentHypothesis(
        hypothesis="High-frequency catalog scraping pattern",
        confidence=0.88,
        supporting_evidence_ids=["E-VOL-001"],
        contradicting_evidence_ids=[],
        reasoning="Rapid sequential pagination through product endpoints",
    )
    critic = CriticReview(
        approved=True,
        rejected_reasons=[],
        invalid_evidence_ids=[],
        score_mutation_detected=False,
    )
    disposition = AnalystDisposition(
        disposition=DispositionStatus.CONFIRMED_ABUSE,
        analyst_id="analyst_alice",
        notes="Confirmed automated scraping pattern.",
    )
    brief = IncidentBrief(
        incident_id="inc_001",
        session_ids=["sess_001"],
        risk_score=0.82,
        risk_band=RiskBand.HIGH,
        identity_assessment="Claimed bot with no valid cryptographic signature",
        intent_hypotheses=[hypo],
        key_findings=["45 rps burst rate", "Unverified agent identity"],
        evidence_citations=["E-VOL-001"],
        alternative_explanations=["Bursty CDN caching prefetch"],
        confidence=0.90,
        recommended_analyst_actions=["Inspect IP subnet", "Apply rate limit"],
        known_limitations=["Single session context"],
        agent_trace_id="trace_abc123",
        critic_review=critic,
        analyst_disposition=disposition,
    )
    assert brief.incident_id == "inc_001"
    assert brief.risk_score == 0.82
    assert brief.critic_review is not None
    assert brief.critic_review.approved is True
    assert brief.analyst_disposition.disposition == DispositionStatus.CONFIRMED_ABUSE
