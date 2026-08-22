"""End-to-end workflow verification for API and analytical data plane."""

from fastapi.testclient import TestClient

from apps.api.main import app
from src.traffic_triage.detection.train import run_training_pipeline


def main() -> None:
    print("=== E2E 1/6: Health & Readiness Checks ===")
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200, f"Health check failed: {r.text}"
        r_ready = client.get("/ready")
        assert r_ready.status_code == 200, f"Readiness check failed: {r_ready.text}"
        print("Health & Readiness: OK")

        print("=== E2E 2/6: Model Training & Artifact Verification ===")
        metrics = run_training_pipeline(
            data_dir="data/fixtures", output_dir="artifacts/model_cards"
        )
        assert "brier_score" in metrics
        print(f"Training Pipeline OK. Brier score: {metrics['brier_score']:.4f}")

        print("=== E2E 3/6: Session Retrieval & Detection ===")
        r_sessions = client.get("/api/v1/sessions?limit=5")
        assert r_sessions.status_code == 200
        sessions = r_sessions.json()
        assert len(sessions) > 0, "No sessions found"
        test_session_id = sessions[0]["session_id"]

        r_detect = client.post(f"/api/v1/sessions/{test_session_id}/detect")
        assert r_detect.status_code == 200
        det = r_detect.json()
        assert 0.0 <= det["calibrated_risk_score"] <= 1.0
        print(
            f"Session {test_session_id} Detection: Score={det['calibrated_risk_score']}, Band={det['risk_band']}"
        )

        print("=== E2E 4/6: 6-Agent Triage Crew Execution ===")
        r_triage = client.post(f"/api/v1/sessions/{test_session_id}/triage")
        assert r_triage.status_code == 200
        brief = r_triage.json()
        assert brief["incident_id"].startswith("inc_")
        assert len(brief["key_findings"]) > 0
        assert len(brief["evidence_citations"]) > 0
        inc_id = brief["incident_id"]
        print(
            f"Triage Brief OK. Incident ID: {inc_id}, Citations: {len(brief['evidence_citations'])}"
        )

        print("=== E2E 5/6: Human Analyst Disposition Update ===")
        r_disp = client.post(
            f"/api/v1/incidents/{inc_id}/disposition",
            json={"disposition": "CONFIRMED_ABUSE", "notes": "E2E automated validation test."},
        )
        assert r_disp.status_code == 200
        r_get_inc = client.get(f"/api/v1/incidents/{inc_id}")
        assert r_get_inc.json()["analyst_disposition"]["disposition"] == "CONFIRMED_ABUSE"
        print("Disposition Persistence: OK")

        print("=== E2E 6/6: Evaluations Benchmark API ===")
        r_eval = client.get("/api/v1/evals/latest")
        assert r_eval.status_code == 200
        eval_data = r_eval.json()
        assert "detection_metrics" in eval_data
        print(
            f"Evals API OK. F1: {eval_data['detection_metrics']['f1']}, FPR: {eval_data['detection_metrics']['false_positive_rate']}"
        )

        print("=== ALL E2E VERIFICATION CHECKS PASSED ===")


if __name__ == "__main__":
    main()
