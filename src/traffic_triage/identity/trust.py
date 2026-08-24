"""Identity evaluation, verification status, and confidence assessment."""

from enum import StrEnum

from pydantic import BaseModel, Field

from src.traffic_triage.identity.signature import (
    IdentityRegistry,
    build_canonical_request_payload,
    get_default_registry,
    verify_signature,
)
from src.traffic_triage.schemas.events import TrafficEvent


class IdentityStrength(StrEnum):
    ANONYMOUS = "ANONYMOUS"
    CLAIMED_ONLY = "CLAIMED_ONLY"
    LOCALLY_VERIFIED_FIXTURE = "LOCALLY_VERIFIED_FIXTURE"
    VERIFIED_BUT_BEHAVIOR_SHIFTED = "VERIFIED_BUT_BEHAVIOR_SHIFTED"
    CLAIM_PROOF_MISMATCH = "CLAIM_PROOF_MISMATCH"


class IdentityEvaluation(BaseModel):
    identity_claim: str | None
    proof_type: str | None
    proof_valid: bool | None
    identity_strength: IdentityStrength
    identity_confidence_score: float = Field(..., ge=0.0, le=1.0)
    identity_changes_count: int = 0
    mismatch_detected: bool = False
    details: str = ""


class IdentityEvaluator:
    """Evaluates identity claims and cryptographic signatures across session events."""

    def __init__(self, registry: IdentityRegistry | None = None) -> None:
        self.registry = registry or get_default_registry()

    def evaluate_session_identity(self, events: list[TrafficEvent]) -> IdentityEvaluation:
        if not events:
            return IdentityEvaluation(
                identity_claim=None,
                proof_type=None,
                proof_valid=None,
                identity_strength=IdentityStrength.ANONYMOUS,
                identity_confidence_score=0.0,
                details="No events in session",
            )

        claims = {e.identity_claim for e in events if e.identity_claim}
        proof_types = {e.identity_proof_type for e in events if e.identity_proof_type}

        # Track changes
        identity_changes = 0
        last_claim = None
        for e in events:
            if e.identity_claim:
                if last_claim is not None and e.identity_claim != last_claim:
                    identity_changes += 1
                last_claim = e.identity_claim

        if not claims:
            return IdentityEvaluation(
                identity_claim=None,
                proof_type=None,
                proof_valid=None,
                identity_strength=IdentityStrength.ANONYMOUS,
                identity_confidence_score=0.1,
                identity_changes_count=0,
                details="Anonymous traffic with no claimed identity",
            )

        primary_claim = list(claims)[0] if len(claims) == 1 else "multiple_claims"
        primary_proof_type = list(proof_types)[0] if proof_types else "none"

        # Check signature proofs
        valid_signatures = 0
        invalid_signatures = 0
        total_signed_events = 0

        for e in events:
            if (
                e.identity_proof_type in ("ed25519_signature", "Ed25519", "ed25519")
                and e.identity_proof_value
                and e.identity_claim
            ):
                total_signed_events += 1
                pub_key = self.registry.get_public_key(e.identity_claim)
                if not pub_key:
                    invalid_signatures += 1
                else:
                    canonical_payload = build_canonical_request_payload(
                        source_id_hash=e.source_id_hash,
                        route_template=e.route_template,
                        timestamp_iso=e.timestamp,
                    )
                    if verify_signature(pub_key, canonical_payload, e.identity_proof_value):
                        valid_signatures += 1
                    else:
                        invalid_signatures += 1

        if len(claims) > 1 or invalid_signatures > 0:
            return IdentityEvaluation(
                identity_claim=primary_claim,
                proof_type=primary_proof_type,
                proof_valid=False if invalid_signatures > 0 else None,
                identity_strength=IdentityStrength.CLAIM_PROOF_MISMATCH,
                identity_confidence_score=0.2,
                identity_changes_count=identity_changes,
                mismatch_detected=True,
                details="Claimed identity changed mid-session or cryptographic proof failed verification",
            )

        if total_signed_events > 0 and valid_signatures == total_signed_events:
            return IdentityEvaluation(
                identity_claim=primary_claim,
                proof_type=primary_proof_type,
                proof_valid=True,
                identity_strength=IdentityStrength.LOCALLY_VERIFIED_FIXTURE,
                identity_confidence_score=0.95,
                identity_changes_count=identity_changes,
                mismatch_detected=False,
                details="Cryptographic identity verified via local Ed25519 public key registry",
            )

        # Claimed without proof
        return IdentityEvaluation(
            identity_claim=primary_claim,
            proof_type=None,
            proof_valid=None,
            identity_strength=IdentityStrength.CLAIMED_ONLY,
            identity_confidence_score=0.4,
            identity_changes_count=identity_changes,
            mismatch_detected=False,
            details="Actor claimed identity string (e.g. User-Agent / header) without cryptographic proof",
        )
