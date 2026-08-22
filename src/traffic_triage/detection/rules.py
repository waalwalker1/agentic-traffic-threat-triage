"""Deterministic explainable rules baseline for traffic anomaly and threat scoring."""

from typing import NamedTuple

from src.traffic_triage.features.extractor import SessionFeatureVector


class RuleEvaluation(NamedTuple):
    score: float
    reason_codes: list[str]
    rule_details: list[str]


class RuleBaselineDetector:
    """Heuristic rule-based detection engine mapping forensic features to explainable signals."""

    def evaluate(self, fv: SessionFeatureVector) -> RuleEvaluation:
        f = fv.features
        score = 0.0
        reasons: list[str] = []
        details: list[str] = []

        # 1. Burst request rate
        rps = f.get("requests_per_second", 0.0)
        if rps >= 30.0:
            score += 0.40
            reasons.append("HIGH_FREQUENCY_BURST_RATE")
            details.append(f"Request rate of {rps:.1f} rps strongly indicates automated scraping")
        elif rps >= 15.0:
            score += 0.20
            reasons.append("ELEVATED_REQUEST_RATE")
            details.append(f"Request rate of {rps:.1f} rps is elevated above human baseline")

        # 2. Authentication failure / credential abuse
        auth_fail = f.get("auth_failure_ratio", 0.0)
        if auth_fail >= 0.50:
            score += 0.45
            reasons.append("REPETITIVE_AUTH_FAILURES")
            details.append(
                f"Authentication failure ratio of {auth_fail:.1%} indicates credential abuse"
            )
        elif auth_fail >= 0.20:
            score += 0.20
            reasons.append("ELEVATED_AUTH_FAILURES")
            details.append(f"Authentication failure ratio of {auth_fail:.1%}")

        # 3. Identity verification mismatch
        id_match = f.get("identity_claim_proof_match", 1.0)
        id_proof_pres = f.get("identity_proof_present", 0.0)
        id_proof_val = f.get("identity_proof_valid", 0.0)
        if id_proof_pres == 1.0 and id_proof_val == 0.0:
            score += 0.50
            reasons.append("CRYPTOGRAPHIC_SIGNATURE_INVALID")
            details.append("Identity proof was supplied but failed cryptographic verification")
        elif id_match == 0.0:
            score += 0.35
            reasons.append("IDENTITY_CLAIM_MISMATCH")
            details.append("Actor identity claims fluctuated or conflicted within session")

        # 4. MCP sequence anomalies
        mcp_ratio = f.get("mcp_event_ratio", 0.0)
        if mcp_ratio > 0.0:
            seq_val = f.get("mcp_sequence_validity_score", 1.0)
            rep_enum = f.get("mcp_repeated_enumeration_score", 0.0)
            unk_m = f.get("mcp_unknown_method_count", 0.0)

            if seq_val < 0.7:
                score += 0.35
                reasons.append("MCP_PROTOCOL_VIOLATION")
                details.append(
                    f"MCP sequence validity score {seq_val:.2f} (calls prior to initialization)"
                )
            if rep_enum >= 0.5:
                score += 0.30
                reasons.append("MCP_REPEATED_DISCOVERY_PROBE")
                details.append("Repeated rapid discovery loops without subsequent execution")
            if unk_m > 0:
                score += 0.25
                reasons.append("MCP_UNKNOWN_METHODS")
                details.append(f"Observed {int(unk_m)} unrecognized MCP RPC methods")

        # 5. Low-and-slow traversal / enumeration
        duration = f.get("session_duration_s", 0.0)
        uniq_routes = f.get("unique_route_ratio", 0.0)
        err_ratio = f.get("error_ratio", 0.0)
        if duration > 10.0 and uniq_routes > 0.85 and err_ratio > 0.30:
            score += 0.25
            reasons.append("ANOMALOUS_ENDPOINT_ENUMERATION")
            details.append(
                f"High unique route ratio ({uniq_routes:.1%}) with high error rate ({err_ratio:.1%})"
            )

        final_score = min(1.0, max(0.0, score))
        if not reasons:
            reasons.append("BENIGN_BEHAVIORAL_PROFILE")
            details.append(
                "All observed volumetric, temporal, and protocol features within benign baselines"
            )

        return RuleEvaluation(
            score=round(final_score, 4),
            reason_codes=reasons,
            rule_details=details,
        )
