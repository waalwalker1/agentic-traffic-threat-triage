import pytest

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.schemas.detection import DetectionResult, RiskBand
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle, EvidenceItem
from src.traffic_triage.schemas.incidents import IncidentBrief, IntentHypothesis
from src.traffic_triage.security.injection_fixtures import INJECTION_FIXTURES
from src.traffic_triage.security.sanitizer import sanitize_telemetry_string
from src.traffic_triage.security.validator import OutputSecurityValidator


def test_telemetry_sanitizer_escapes_xml_and_strips_control_chars():
    for inj in INJECTION_FIXTURES:
        sanitized = sanitize_telemetry_string(inj)
        # Check that raw unescaped XML angle brackets are not present
        assert "<curated_evidence>" not in sanitized
        assert "</curated_evidence>" not in sanitized
        assert "<script>" not in sanitized
        # Check length bound
        assert len(sanitized) <= 600


def test_validator_rejects_risk_score_mutation():
    bundle = CuratedEvidenceBundle(
        session_id="s1",
        risk_score=0.85,
        risk_band="HIGH",
        detector_scores={"rules": 0.85},
        model_versions={"rules": "1.0"},
        evidence_items=[
            EvidenceItem(
                evidence_id="E-VOL-s1-01",
                session_id="s1",
                kind="volumetric",
                feature_name="rps",
                observed_value=45.0,
                expected_range_or_context="< 5.0",
                human_readable_explanation="High burst rps",
            )
        ],
    )

    # Attempted mutation where brief has score 0.10 instead of 0.85
    mutated_brief = IncidentBrief(
        incident_id="inc_1",
        session_ids=["s1"],
        risk_score=0.10,  # Mutated!
        risk_band=RiskBand.LOW,  # Mutated!
        identity_assessment="Nominal",
        intent_hypotheses=[
            IntentHypothesis(
                hypothesis="Benign",
                confidence=0.9,
                supporting_evidence_ids=["E-VOL-s1-01"],
                contradicting_evidence_ids=[],
                reasoning="Nominal",
            )
        ],
        key_findings=["Clean traffic"],
        evidence_citations=["E-VOL-s1-01"],
        alternative_explanations=[],
        confidence=0.9,
        recommended_analyst_actions=[],
        known_limitations=[],
        agent_trace_id="trace_1",
    )

    violations = OutputSecurityValidator.validate_brief_invariants(mutated_brief, bundle)
    assert any("SCORE_MUTATION_VIOLATION" in v for v in violations)
    assert any("RISK_BAND_MUTATION_VIOLATION" in v for v in violations)


def test_validator_rejects_unknown_evidence_citations():
    bundle = CuratedEvidenceBundle(
        session_id="s1",
        risk_score=0.85,
        risk_band="HIGH",
        detector_scores={"rules": 0.85},
        model_versions={"rules": "1.0"},
        evidence_items=[
            EvidenceItem(
                evidence_id="E-VOL-s1-01",
                session_id="s1",
                kind="volumetric",
                feature_name="rps",
                observed_value=45.0,
                expected_range_or_context="< 5.0",
                human_readable_explanation="High burst rps",
            )
        ],
    )

    brief_with_hallucinated_evidence = IncidentBrief(
        incident_id="inc_1",
        session_ids=["s1"],
        risk_score=0.85,
        risk_band=RiskBand.HIGH,
        identity_assessment="Nominal",
        intent_hypotheses=[
            IntentHypothesis(
                hypothesis="Threat",
                confidence=0.9,
                supporting_evidence_ids=["E-VOL-s1-01"],
                contradicting_evidence_ids=[],
                reasoning="Nominal",
            )
        ],
        key_findings=["Alert findings"],
        evidence_citations=["E-VOL-s1-01", "E-FAKE-001", "E-HALLUCINATED-999"],
        alternative_explanations=[],
        confidence=0.9,
        recommended_analyst_actions=[],
        known_limitations=[],
        agent_trace_id="trace_1",
    )

    violations = OutputSecurityValidator.validate_brief_invariants(
        brief_with_hallucinated_evidence, bundle
    )
    assert any("E-FAKE-001" in v for v in violations)
    assert any("E-HALLUCINATED-999" in v for v in violations)


@pytest.mark.asyncio
async def test_supervisor_immune_to_all_28_injected_fixtures():
    """Execute every single one of the 28 adversarial injection payloads through the full triage pipeline."""
    supervisor = DeterministicSupervisor(SOCTriageCrew(DeterministicLocalProvider()))
    assert len(INJECTION_FIXTURES) == 28

    for idx, inj in enumerate(INJECTION_FIXTURES):
        sanitized_inj = sanitize_telemetry_string(inj)
        ev_item = EvidenceItem(
            evidence_id=f"E-VOL-test-{idx:02d}",
            session_id=f"sess_inj_{idx:02d}",
            kind="volumetric",
            feature_name="requests_per_second",
            observed_value=50.0,
            expected_range_or_context="< 5.0 rps",
            human_readable_explanation=f"High rate with injected snippet: {sanitized_inj}",
        )
        bundle = CuratedEvidenceBundle(
            session_id=f"sess_inj_{idx:02d}",
            risk_score=0.88,
            risk_band="CRITICAL",
            detector_scores={"rules": 0.88},
            model_versions={"rules": "1.0"},
            evidence_items=[ev_item],
        )
        det_result = DetectionResult(
            session_id=f"sess_inj_{idx:02d}",
            rules_score=0.88,
            supervised_score=0.85,
            anomaly_score=0.80,
            pytorch_score=0.82,
            raw_model_score=0.84,
            calibrated_model_probability=0.86,
            policy_risk_score=0.88,
            calibrated_risk_score=0.88,
            risk_band=RiskBand.CRITICAL,
            evidence_ids=[f"E-VOL-test-{idx:02d}"],
        )

        brief = await supervisor.execute_triage(bundle, det_result)

        # Invariant checks:
        assert brief.risk_score == 0.88, f"Score mutated on fixture {idx}: {inj}"
        assert brief.risk_band == RiskBand.CRITICAL
        assert f"E-VOL-test-{idx:02d}" in brief.evidence_citations
        assert not any("FAKE" in c for c in brief.evidence_citations)
        assert not any("FORGED" in c for c in brief.evidence_citations)
        # Ensure system instructions remain intact
        assert len(brief.recommended_analyst_actions) > 0
