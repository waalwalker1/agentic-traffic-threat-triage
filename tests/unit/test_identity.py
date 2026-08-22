from datetime import UTC, datetime

from src.traffic_triage.identity.signature import (
    IdentityRegistry,
    build_canonical_request_payload,
    generate_keypair,
    sign_payload,
    verify_signature,
)
from src.traffic_triage.identity.trust import (
    IdentityEvaluator,
    IdentityStrength,
)
from src.traffic_triage.schemas.events import TrafficEvent


def test_ed25519_signature_lifecycle():
    kp = generate_keypair()
    payload = build_canonical_request_payload("src_123", "/api/v1/test", "2026-08-22T10:00:00Z")
    sig = sign_payload(kp.private_key_b64, payload)

    assert verify_signature(kp.public_key_b64, payload, sig) is True
    assert verify_signature(kp.public_key_b64, payload + "_tampered", sig) is False

    wrong_kp = generate_keypair()
    assert verify_signature(wrong_kp.public_key_b64, payload, sig) is False


def test_identity_evaluator_verified_fixture():
    reg = IdentityRegistry()
    kp = generate_keypair()
    agent_id = "trusted-crawler-01"
    reg.register(agent_id, kp.public_key_b64)
    evaluator = IdentityEvaluator(registry=reg)

    now = datetime.now(UTC)
    payload = build_canonical_request_payload("src_abc", "/api/v1/data", now.isoformat())
    sig = sign_payload(kp.private_key_b64, payload)

    event = TrafficEvent(
        event_id="evt_01",
        session_id="sess_01",
        timestamp=now,
        source_id_hash="src_abc",
        request_method="GET",
        route_template="/api/v1/data",
        identity_claim=agent_id,
        identity_proof_type="ed25519_signature",
        identity_proof_value=sig,
    )

    res = evaluator.evaluate_session_identity([event])
    assert res.identity_strength == IdentityStrength.LOCALLY_VERIFIED_FIXTURE
    assert res.identity_confidence_score > 0.9
    assert res.proof_valid is True
    assert res.mismatch_detected is False


def test_identity_evaluator_mismatch_case():
    reg = IdentityRegistry()
    kp = generate_keypair()
    agent_id = "trusted-crawler-01"
    reg.register(agent_id, kp.public_key_b64)
    evaluator = IdentityEvaluator(registry=reg)

    now = datetime.now(UTC)
    # Tampered signature
    event = TrafficEvent(
        event_id="evt_01",
        session_id="sess_01",
        timestamp=now,
        source_id_hash="src_abc",
        request_method="GET",
        route_template="/api/v1/data",
        identity_claim=agent_id,
        identity_proof_type="ed25519_signature",
        identity_proof_value="invalid_base64_sig==",
    )

    res = evaluator.evaluate_session_identity([event])
    assert res.identity_strength == IdentityStrength.CLAIM_PROOF_MISMATCH
    assert res.proof_valid is False
    assert res.mismatch_detected is True
    assert res.identity_confidence_score <= 0.3


def test_identity_evaluator_claimed_only():
    evaluator = IdentityEvaluator()
    event = TrafficEvent(
        event_id="evt_01",
        session_id="sess_01",
        source_id_hash="src_abc",
        request_method="GET",
        route_template="/api/v1/data",
        identity_claim="unverified-ai-bot",
        identity_proof_type=None,
    )
    res = evaluator.evaluate_session_identity([event])
    assert res.identity_strength == IdentityStrength.CLAIMED_ONLY
    assert res.identity_confidence_score == 0.4
    assert res.mismatch_detected is False
