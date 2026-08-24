"""Integration test verifying DuckDB analytical persistence and restart durability."""

from datetime import UTC, datetime
from pathlib import Path
import tempfile

from src.traffic_triage.features.extractor import SessionFeatureVector
from src.traffic_triage.persistence.duckdb_store import DuckDBStore
from src.traffic_triage.schemas.detection import DetectionResult, RiskBand
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.evidence import EvidenceItem
from src.traffic_triage.schemas.incidents import (
    AnalystDisposition,
    DispositionStatus,
    GroundedFinding,
    IncidentBrief,
    IntentHypothesis,
)
from src.traffic_triage.schemas.sessions import TrafficSession


def test_duckdb_restart_durability():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "persistent_triage.duckdb")

        # 1. Instantiate store and ingest data
        store1 = DuckDBStore(db_path=db_path)

        now = datetime.now(UTC)
        evt = TrafficEvent(
            event_id="evt_durability_001",
            schema_version="1.0.0",
            timestamp=now,
            session_id="sess_durability_001",
            source_id_hash="src_abcdef01",
            request_method="POST",
            route_template="/api/v1/auth/login",
            status_code=401,
            response_bytes=2450,
            latency_ms=120,
            user_agent="TestAgent/1.0",
            accept_language="en-US",
            header_names=["Host", "User-Agent", "Authorization"],
            content_type="application/json",
            has_auth_context=True,
            identity_claim="test-user",
            identity_proof_type="Ed25519",
            identity_proof_value="test_sig_val",
            identity_proof_valid=False,
            actor_hint="test_actor",
            mcp_method=None,
            mcp_tool_category=None,
            synthetic_scenario_id="repetitive_login_failure",
            synthetic_ground_truth="threat",
        )
        store1.save_events([evt])

        session = TrafficSession(
            session_id="sess_durability_001",
            events=[evt],
            start_time=now,
            end_time=now,
            event_count=1,
            source_id_hash="src_abcdef01",
        )
        store1.save_session(session)

        fv = SessionFeatureVector(
            session_id="sess_durability_001",
            features={"requests_per_second": 15.0, "auth_failure_ratio": 1.0},
        )
        store1.save_features(fv)

        ev_item = EvidenceItem(
            evidence_id="E-VOL-sess_durability_001-01",
            session_id="sess_durability_001",
            kind="volumetric",
            feature_name="requests_per_second",
            observed_value=15.0,
            expected_range_or_context="< 5.0 rps",
            human_readable_explanation="High burst rate observed",
        )
        store1.save_evidence_items([ev_item])

        det = DetectionResult(
            session_id="sess_durability_001",
            rules_score=0.80,
            supervised_score=0.85,
            anomaly_score=0.75,
            pytorch_score=0.78,
            raw_model_score=0.82,
            calibrated_model_probability=0.84,
            policy_risk_score=0.85,
            calibrated_risk_score=0.85,
            risk_band=RiskBand.CRITICAL,
            policy_override_codes=["OVERRIDE_REPEATED_AUTH_FAILURES"],
            reason_codes=["REPEATED_AUTH_FAILURES"],
            evidence_ids=["E-VOL-sess_durability_001-01"],
        )
        store1.save_detection_result(det)

        brief = IncidentBrief(
            incident_id="inc_durability_001",
            session_ids=["sess_durability_001"],
            risk_score=0.85,
            risk_band=RiskBand.CRITICAL,
            identity_assessment="Mismatched identity proof",
            intent_hypotheses=[
                IntentHypothesis(
                    hypothesis="Credential abuse brute-force",
                    confidence=0.90,
                    supporting_evidence_ids=["E-VOL-sess_durability_001-01"],
                    contradicting_evidence_ids=[],
                    reasoning="High auth failure cadence",
                )
            ],
            grounded_findings=[
                GroundedFinding(
                    finding="High request rate and authentication failure.",
                    evidence_ids=["E-VOL-sess_durability_001-01"],
                    is_factual=True,
                )
            ],
            key_findings=["High request rate and authentication failure."],
            evidence_citations=["E-VOL-sess_durability_001-01"],
            alternative_explanations=["Misconfigured client retry loop."],
            confidence=0.88,
            recommended_analyst_actions=["Block IP range"],
            known_limitations=["Synthetic fixture test"],
            agent_trace_id="trace_durability_001",
        )
        store1.save_incident(brief)

        disp = AnalystDisposition(
            disposition=DispositionStatus.CONFIRMED_ABUSE,
            analyst_id="analyst_soc_lead",
            notes="Durability validation disposition test.",
        )
        store1.update_disposition("inc_durability_001", disp)

        # 2. Close store connection
        store1.close()

        # 3. Instantiate fresh new DuckDBStore against the same on-disk path
        store2 = DuckDBStore(db_path=db_path)

        # 4. Verify all objects survived restart and match expected values
        events_read = store2.get_events_for_session("sess_durability_001")
        assert len(events_read) == 1
        assert events_read[0].event_id == "evt_durability_001"
        assert events_read[0].synthetic_ground_truth == "threat"

        session_read = store2.get_session("sess_durability_001")
        assert session_read is not None
        assert session_read["session_id"] == "sess_durability_001"
        assert session_read["event_count"] == 1

        ev_read = store2.get_evidence_for_session("sess_durability_001")
        assert len(ev_read) == 1
        assert ev_read[0]["evidence_id"] == "E-VOL-sess_durability_001-01"
        assert ev_read[0]["observed_value"] == 15.0

        inc_read = store2.get_incident("inc_durability_001")
        assert inc_read is not None
        assert inc_read["incident_id"] == "inc_durability_001"
        assert inc_read["risk_score"] == 0.85
        assert inc_read["risk_band"] == "CRITICAL"
        assert inc_read["analyst_disposition"]["disposition"] == "CONFIRMED_ABUSE"
        assert inc_read["analyst_disposition"]["analyst_id"] == "analyst_soc_lead"

        store2.close()
