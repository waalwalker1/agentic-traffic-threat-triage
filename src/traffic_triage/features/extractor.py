"""Deterministic session feature extraction with mathematical rigor and provenance."""

import math

import numpy as np
from pydantic import BaseModel, Field

from src.traffic_triage.identity.trust import IdentityEvaluator
from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.schemas.events import TrafficEvent

FEATURE_SCHEMA_VERSION = "1.0.0"

FEATURE_NAMES = [
    "requests_per_second",
    "interarrival_mean_ms",
    "interarrival_cv",
    "burstiness_index",
    "route_entropy",
    "unique_route_ratio",
    "error_ratio",
    "status_4xx_ratio",
    "status_5xx_ratio",
    "auth_failure_ratio",
    "response_byte_mean",
    "response_byte_cv",
    "session_duration_s",
    "repeated_route_ratio",
    "user_agent_stability_score",
    "header_count_mean",
    "identity_claim_present",
    "identity_proof_present",
    "identity_proof_valid",
    "identity_claim_proof_match",
    "identity_changes_count",
    "identity_confidence",
    "mcp_event_ratio",
    "mcp_initialize_count",
    "mcp_tools_list_count",
    "mcp_prompts_list_count",
    "mcp_resources_list_count",
    "mcp_tools_call_count",
    "mcp_discovery_to_action_ratio",
    "mcp_repeated_enumeration_score",
    "mcp_unknown_method_count",
    "mcp_sequence_validity_score",
]


class SessionFeatureVector(BaseModel):
    session_id: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    features: dict[str, float]
    provenance: dict[str, str] = Field(default_factory=dict)

    def to_array(self) -> np.ndarray:
        """Convert ordered features to 1D float array."""
        return np.array([self.features.get(k, 0.0) for k in FEATURE_NAMES], dtype=np.float32)


class FeatureExtractor:
    """Extracts deterministic behavioral, identity, and MCP features for a session."""

    def __init__(
        self,
        identity_evaluator: IdentityEvaluator | None = None,
        mcp_analyzer: MCPSequenceAnalyzer | None = None,
    ) -> None:
        self.identity_evaluator = identity_evaluator or IdentityEvaluator()
        self.mcp_analyzer = mcp_analyzer or MCPSequenceAnalyzer()

    def extract_features(self, events: list[TrafficEvent], session_id: str) -> SessionFeatureVector:
        if not events:
            zero_dict = dict.fromkeys(FEATURE_NAMES, 0.0)
            return SessionFeatureVector(session_id=session_id, features=zero_dict)

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        n = len(sorted_events)

        # Timestamps and interarrival intervals
        ts_list = [e.timestamp.timestamp() for e in sorted_events]
        duration_s = max(0.001, ts_list[-1] - ts_list[0]) if n > 1 else 1.0

        if n > 1:
            diffs_ms = [(ts_list[i] - ts_list[i - 1]) * 1000.0 for i in range(1, n)]
            mean_ia_ms = float(np.mean(diffs_ms))
            std_ia_ms = float(np.std(diffs_ms))
            cv_ia = (std_ia_ms / mean_ia_ms) if mean_ia_ms > 0 else 0.0
            # Burstiness index: (std - mean) / (std + mean)
            burstiness = (
                (std_ia_ms - mean_ia_ms) / (std_ia_ms + mean_ia_ms)
                if (std_ia_ms + mean_ia_ms) > 0
                else 0.0
            )
        else:
            mean_ia_ms = 0.0
            cv_ia = 0.0
            burstiness = 0.0

        rps = float(n / duration_s)

        # Route analysis
        routes = [e.route_template for e in sorted_events]
        unique_routes = set(routes)
        unique_route_ratio = len(unique_routes) / n

        # Route Shannon entropy
        route_counts: dict[str, int] = {}
        for r in routes:
            route_counts[r] = route_counts.get(r, 0) + 1
        entropy = 0.0
        for cnt in route_counts.values():
            p = cnt / n
            entropy -= p * math.log2(p)

        repeated_count = sum(cnt - 1 for cnt in route_counts.values() if cnt > 1)
        repeated_route_ratio = repeated_count / n if n > 0 else 0.0

        # Status and errors
        status_codes = [e.status_code for e in sorted_events]
        err_4xx = sum(1 for s in status_codes if 400 <= s < 500)
        err_5xx = sum(1 for s in status_codes if 500 <= s < 600)
        auth_err = sum(1 for s in status_codes if s in (401, 403))
        total_err = err_4xx + err_5xx

        # Response bytes
        resp_bytes = [float(e.response_bytes) for e in sorted_events]
        mean_bytes = float(np.mean(resp_bytes))
        std_bytes = float(np.std(resp_bytes))
        cv_bytes = (std_bytes / mean_bytes) if mean_bytes > 0 else 0.0

        # User-Agent stability
        uas = {e.user_agent for e in sorted_events if e.user_agent}
        ua_stability = 1.0 if len(uas) <= 1 else max(0.0, 1.0 - (len(uas) - 1) * 0.25)

        # Header counts
        hdr_counts = [len(e.header_names) for e in sorted_events]
        mean_hdr_count = float(np.mean(hdr_counts)) if hdr_counts else 0.0

        # Identity Evaluation
        id_eval = self.identity_evaluator.evaluate_session_identity(sorted_events)
        id_claim_pres = 1.0 if id_eval.identity_claim is not None else 0.0
        id_proof_pres = 1.0 if id_eval.proof_type not in (None, "none") else 0.0
        id_proof_val = 1.0 if id_eval.proof_valid is True else 0.0
        id_match = 0.0 if id_eval.mismatch_detected else (1.0 if id_proof_pres else 0.5)

        # MCP Analysis
        mcp_res = self.mcp_analyzer.analyze_session(sorted_events)

        feat_dict: dict[str, float] = {
            "requests_per_second": round(rps, 4),
            "interarrival_mean_ms": round(mean_ia_ms, 2),
            "interarrival_cv": round(cv_ia, 4),
            "burstiness_index": round(burstiness, 4),
            "route_entropy": round(entropy, 4),
            "unique_route_ratio": round(unique_route_ratio, 4),
            "error_ratio": round(total_err / n, 4),
            "status_4xx_ratio": round(err_4xx / n, 4),
            "status_5xx_ratio": round(err_5xx / n, 4),
            "auth_failure_ratio": round(auth_err / n, 4),
            "response_byte_mean": round(mean_bytes, 2),
            "response_byte_cv": round(cv_bytes, 4),
            "session_duration_s": round(duration_s, 2),
            "repeated_route_ratio": round(repeated_route_ratio, 4),
            "user_agent_stability_score": round(ua_stability, 4),
            "header_count_mean": round(mean_hdr_count, 2),
            "identity_claim_present": id_claim_pres,
            "identity_proof_present": id_proof_pres,
            "identity_proof_valid": id_proof_val,
            "identity_claim_proof_match": id_match,
            "identity_changes_count": float(id_eval.identity_changes_count),
            "identity_confidence": round(id_eval.identity_confidence_score, 4),
            "mcp_event_ratio": mcp_res.mcp_event_ratio,
            "mcp_initialize_count": float(mcp_res.initialize_count),
            "mcp_tools_list_count": float(mcp_res.tools_list_count),
            "mcp_prompts_list_count": float(mcp_res.prompts_list_count),
            "mcp_resources_list_count": float(mcp_res.resources_list_count),
            "mcp_tools_call_count": float(mcp_res.tools_call_count),
            "mcp_discovery_to_action_ratio": mcp_res.discovery_to_action_ratio,
            "mcp_repeated_enumeration_score": mcp_res.repeated_enumeration_score,
            "mcp_unknown_method_count": float(mcp_res.unknown_method_count),
            "mcp_sequence_validity_score": mcp_res.sequence_validity_score,
        }

        provenance = dict.fromkeys(feat_dict, "FeatureExtractor_v1.0.0")

        return SessionFeatureVector(
            session_id=session_id,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            features=feat_dict,
            provenance=provenance,
        )
