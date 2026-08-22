from datetime import UTC, datetime

from fastapi.testclient import TestClient

from apps.api.main import app
from src.traffic_triage.schemas.events import TrafficEvent

client = TestClient(app)


def test_api_health_and_ready():
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"

    r_ready = client.get("/ready")
    assert r_ready.status_code == 200
    assert r_ready.json()["status"] == "ready"


def test_api_metrics():
    r_metrics = client.get("/metrics")
    assert r_metrics.status_code == 200
    assert "triage_api_requests_total" in r_metrics.text


def test_api_ingest_detect_triage_flow():
    now = datetime.now(UTC)
    test_events = [
        TrafficEvent(
            event_id="evt_test_01",
            session_id="sess_integration_01",
            timestamp=now,
            source_id_hash="src_test_hash",
            request_method="GET",
            route_template="/api/v1/products",
            status_code=200,
            response_bytes=1500,
            latency_ms=35.0,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            actor_hint="human",
            synthetic_scenario_id="human_browsing",
            synthetic_ground_truth="benign",
        ).model_dump(mode="json"),
        TrafficEvent(
            event_id="evt_test_02",
            session_id="sess_integration_01",
            timestamp=now,
            source_id_hash="src_test_hash",
            request_method="GET",
            route_template="/api/v1/products/item-1",
            status_code=200,
            response_bytes=2200,
            latency_ms=45.0,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            actor_hint="human",
            synthetic_scenario_id="human_browsing",
            synthetic_ground_truth="benign",
        ).model_dump(mode="json"),
    ]

    # 1. Ingest
    r_ingest = client.post("/api/v1/ingest", json={"events": test_events})
    assert r_ingest.status_code == 200
    assert r_ingest.json()["events_ingested"] == 2

    # 2. Get session
    r_sess = client.get("/api/v1/sessions/sess_integration_01")
    assert r_sess.status_code == 200
    assert r_sess.json()["event_count"] == 2

    # 3. Detect
    r_detect = client.post("/api/v1/sessions/sess_integration_01/detect")
    assert r_detect.status_code == 200
    det = r_detect.json()
    assert 0.0 <= det["calibrated_risk_score"] <= 1.0
    assert det["risk_band"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    # 4. Triage
    r_triage = client.post("/api/v1/sessions/sess_integration_01/triage")
    assert r_triage.status_code == 200
    brief = r_triage.json()
    assert brief["incident_id"].startswith("inc_sess_integration_01")
    assert len(brief["key_findings"]) > 0
    assert len(brief["evidence_citations"]) > 0

    inc_id = brief["incident_id"]

    # 5. Disposition
    r_disp = client.post(
        f"/api/v1/incidents/{inc_id}/disposition",
        json={"disposition": "BENIGN", "notes": "Verified standard human browsing pattern"},
    )
    assert r_disp.status_code == 200
    assert r_disp.json()["status"] == "updated"

    # 6. Retrieve Incident
    r_inc = client.get(f"/api/v1/incidents/{inc_id}")
    assert r_inc.status_code == 200
    assert r_inc.json()["analyst_disposition"]["disposition"] == "BENIGN"
