"""Deterministic evidence generator and curated evidence bundle builder."""

from datetime import UTC, datetime

from src.traffic_triage.features.extractor import SessionFeatureVector
from src.traffic_triage.identity.trust import IdentityEvaluation, IdentityStrength
from src.traffic_triage.mcp_activity.analyzer import MCPActivityMetrics
from src.traffic_triage.schemas.detection import DetectionResult
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle, EvidenceItem


class EvidenceCollector:
    """Extracts immutable, verifiable evidence items from session features and events."""

    def collect_evidence(
        self,
        session_id: str,
        fv: SessionFeatureVector,
        events: list[TrafficEvent],
        id_eval: IdentityEvaluation,
        mcp_metrics: MCPActivityMetrics,
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        f = fv.features
        event_ids = [e.event_id for e in events]
        now = datetime.now(UTC)

        # 1. Volumetric Evidence
        rps = f.get("requests_per_second", 0.0)
        if rps >= 15.0:
            items.append(
                EvidenceItem(
                    evidence_id=f"E-VOL-{session_id[:6]}-01",
                    session_id=session_id,
                    kind="volumetric",
                    source_event_ids=event_ids[:5],
                    feature_name="requests_per_second",
                    observed_value=rps,
                    expected_range_or_context="< 5.0 rps for standard human browsing",
                    severity_hint="high" if rps >= 30.0 else "medium",
                    human_readable_explanation=f"Measured request rate of {rps:.2f} rps indicates high-volume automation.",
                    provenance="EvidenceCollector_v1",
                    created_at=now,
                )
            )

        # 2. Identity Evidence
        if id_eval.identity_strength == IdentityStrength.LOCALLY_VERIFIED_FIXTURE:
            items.append(
                EvidenceItem(
                    evidence_id=f"E-ID-{session_id[:6]}-01",
                    session_id=session_id,
                    kind="identity",
                    source_event_ids=event_ids[:3],
                    feature_name="identity_proof_valid",
                    observed_value=True,
                    expected_range_or_context="Valid cryptographic signature matching registered public key",
                    severity_hint="informational",
                    human_readable_explanation=f"Agent '{id_eval.identity_claim}' cryptographically verified via Ed25519 signature.",
                    provenance="EvidenceCollector_v1",
                    created_at=now,
                )
            )
        elif id_eval.identity_strength == IdentityStrength.CLAIM_PROOF_MISMATCH:
            items.append(
                EvidenceItem(
                    evidence_id=f"E-ID-{session_id[:6]}-02",
                    session_id=session_id,
                    kind="identity",
                    source_event_ids=event_ids[:3],
                    feature_name="identity_claim_proof_match",
                    observed_value=False,
                    expected_range_or_context="Signature verification failure or conflicting identity claims",
                    severity_hint="critical",
                    human_readable_explanation=f"Identity proof for '{id_eval.identity_claim}' failed cryptographic verification.",
                    provenance="EvidenceCollector_v1",
                    created_at=now,
                )
            )
        elif id_eval.identity_strength == IdentityStrength.CLAIMED_ONLY:
            items.append(
                EvidenceItem(
                    evidence_id=f"E-ID-{session_id[:6]}-03",
                    session_id=session_id,
                    kind="identity",
                    source_event_ids=event_ids[:2],
                    feature_name="identity_claim_present",
                    observed_value=id_eval.identity_claim,
                    expected_range_or_context="Unverified user-agent/header claim",
                    severity_hint="low",
                    human_readable_explanation=f"Actor claimed identity '{id_eval.identity_claim}' without cryptographic signature proof.",
                    provenance="EvidenceCollector_v1",
                    created_at=now,
                )
            )

        # 3. Authentication & Error Evidence
        auth_fail = f.get("auth_failure_ratio", 0.0)
        if auth_fail >= 0.20:
            items.append(
                EvidenceItem(
                    evidence_id=f"E-BEH-{session_id[:6]}-01",
                    session_id=session_id,
                    kind="behavioral",
                    source_event_ids=[e.event_id for e in events if e.status_code in (401, 403)][
                        :5
                    ],
                    feature_name="auth_failure_ratio",
                    observed_value=auth_fail,
                    expected_range_or_context="< 5.0% auth failure rate under normal operations",
                    severity_hint="high" if auth_fail >= 0.50 else "medium",
                    human_readable_explanation=f"Auth failure ratio of {auth_fail:.1%} observed across session requests.",
                    provenance="EvidenceCollector_v1",
                    created_at=now,
                )
            )

        # 4. MCP Activity Evidence
        if mcp_metrics.has_mcp_traffic:
            if (
                mcp_metrics.sequence_validity_score < 1.0
                or mcp_metrics.repeated_enumeration_score >= 0.4
            ):
                items.append(
                    EvidenceItem(
                        evidence_id=f"E-MCP-{session_id[:6]}-01",
                        session_id=session_id,
                        kind="mcp",
                        source_event_ids=[e.event_id for e in events if e.mcp_method is not None][
                            :5
                        ],
                        feature_name="mcp_sequence_validity_score",
                        observed_value=mcp_metrics.sequence_validity_score,
                        expected_range_or_context="Standard initialize -> tools/list sequence",
                        severity_hint="high"
                        if mcp_metrics.sequence_validity_score < 0.7
                        else "medium",
                        human_readable_explanation=f"MCP sequence flags: {', '.join(mcp_metrics.anomaly_flags) if mcp_metrics.anomaly_flags else 'Irregular method cadence'}.",
                        provenance="EvidenceCollector_v1",
                        created_at=now,
                    )
                )
            else:
                items.append(
                    EvidenceItem(
                        evidence_id=f"E-MCP-{session_id[:6]}-02",
                        session_id=session_id,
                        kind="mcp",
                        source_event_ids=[e.event_id for e in events if e.mcp_method is not None][
                            :3
                        ],
                        feature_name="mcp_lifecycle_state",
                        observed_value=mcp_metrics.lifecycle_state,
                        expected_range_or_context="Normal protocol discovery and tool execution",
                        severity_hint="informational",
                        human_readable_explanation=f"Conforming MCP activity observed in state '{mcp_metrics.lifecycle_state}'.",
                        provenance="EvidenceCollector_v1",
                        created_at=now,
                    )
                )

        if not items:
            items.append(
                EvidenceItem(
                    evidence_id=f"E-BEH-{session_id[:6]}-00",
                    session_id=session_id,
                    kind="behavioral",
                    source_event_ids=event_ids[:2],
                    feature_name="baseline_conformance",
                    observed_value="nominal",
                    expected_range_or_context="Nominal human/client browsing patterns",
                    severity_hint="informational",
                    human_readable_explanation="All observed features conform to baseline expectations.",
                    provenance="EvidenceCollector_v1",
                    created_at=now,
                )
            )

        return items

    def build_bundle(
        self,
        session_id: str,
        detection_result: DetectionResult,
        evidence_items: list[EvidenceItem],
        events: list[TrafficEvent],
    ) -> CuratedEvidenceBundle:
        # Sanitize event excerpts (never include raw unescaped payloads or headers)
        sanitized_excerpts = []
        for e in events[:5]:
            sanitized_excerpts.append(
                {
                    "event_id": e.event_id,
                    "method": e.request_method,
                    "route": e.route_template,
                    "status": e.status_code,
                    "mcp_method": e.mcp_method,
                }
            )

        return CuratedEvidenceBundle(
            session_id=session_id,
            risk_score=detection_result.calibrated_risk_score,
            risk_band=detection_result.risk_band.value,
            detector_scores={
                "rules": detection_result.rules_score,
                "supervised": detection_result.supervised_score,
                "anomaly": detection_result.anomaly_score,
                "pytorch": detection_result.pytorch_score,
            },
            model_versions=detection_result.model_versions,
            evidence_items=evidence_items,
            sanitized_event_excerpts=sanitized_excerpts,
            created_at=datetime.now(UTC),
        )
