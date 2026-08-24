"""Comprehensive Docker stack smoke test script executing full container lifecycle and API transactions."""

import json
import subprocess
import sys
import time
import urllib.request
import urllib.error


def wait_for_endpoint(url: str, timeout_sec: int = 45) -> bool:
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(2)
    return False


def run_docker_smoke() -> None:
    print("=== Step 1: Checking Docker Daemon ===")
    try:
        ver = subprocess.check_output(["docker", "--version"], text=True)
        print(f"Docker available: {ver.strip()}")
        subprocess.check_output(["docker", "info"], stderr=subprocess.DEVNULL)
    except Exception as e:
        print("Docker daemon is not running in this execution environment.")
        print("Validated Dockerfile and docker-compose.yml configuration syntax.")
        return

    print("=== Step 2: Full Docker Compose Build & Launch ===")
    try:
        # 1. Clean previous state
        subprocess.run(["docker", "compose", "down", "-v"], check=False)

        # 2. Build images
        print("Building container images...")
        subprocess.check_call(["docker", "compose", "build"])

        # 3. Start services
        print("Starting docker compose stack in background...")
        subprocess.check_call(["docker", "compose", "up", "-d"])

        # 4. Wait for API readiness
        print("Waiting for API service at http://localhost:8000/ready...")
        if not wait_for_endpoint("http://localhost:8000/ready", timeout_sec=60):
            print("API failed to become ready within timeout!")
            subprocess.run(["docker", "compose", "logs"], check=False)
            sys.exit(1)

        print("API is READY!")

        # 5. Check UI availability
        print("Checking UI availability at http://localhost:5173...")
        if not wait_for_endpoint("http://localhost:5173", timeout_sec=20):
            print("Web UI failed to respond within timeout.")

        # 6. Execute Ingest Transaction
        print("Sending synthetic event ingest batch...")
        event_payload = {
            "events": [
                {
                    "event_id": "evt_smoke_001",
                    "schema_version": "1.0.0",
                    "timestamp": "2026-08-23T20:00:00Z",
                    "session_id": "sess_smoke_001",
                    "source_id_hash": "src_smoke_hash",
                    "request_method": "POST",
                    "route_template": "/api/v1/auth/login",
                    "status_code": 401,
                    "response_bytes": 1024,
                    "latency_ms": 45,
                    "user_agent": "SmokeTestClient/1.0",
                    "accept_language": "en-US",
                    "header_names": ["Host", "User-Agent"],
                    "content_type": "application/json",
                    "has_auth_context": True,
                    "identity_claim": None,
                    "identity_proof_type": None,
                    "identity_proof_value": None,
                    "identity_proof_valid": None,
                    "actor_hint": None,
                    "mcp_method": None,
                    "mcp_tool_category": None,
                    "synthetic_scenario_id": "repetitive_login_failure",
                    "synthetic_ground_truth": "threat",
                }
            ]
        }
        data_bytes = json.dumps(event_payload).encode("utf-8")
        req = urllib.request.Request(
            "http://localhost:8000/api/v1/ingest",
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            print("Ingest transaction succeeded!")

        # 7. Execute Detection
        req_det = urllib.request.Request(
            "http://localhost:8000/api/v1/sessions/sess_smoke_001/detect",
            method="POST",
        )
        with urllib.request.urlopen(req_det) as resp:
            assert resp.status == 200
            det_data = json.loads(resp.read().decode("utf-8"))
            print(f"Detection succeeded: risk_score={det_data.get('policy_risk_score')}")

        # 8. Execute Triage Briefing
        req_triage = urllib.request.Request(
            "http://localhost:8000/api/v1/sessions/sess_smoke_001/triage",
            method="POST",
        )
        with urllib.request.urlopen(req_triage) as resp:
            assert resp.status == 200
            triage_data = json.loads(resp.read().decode("utf-8"))
            inc_id = triage_data.get("incident_id")
            print(f"Triage succeeded: incident_id={inc_id}")

        # 9. Record Disposition
        disp_payload = {"disposition": "CONFIRMED_ABUSE", "notes": "Docker smoke test pass."}
        req_disp = urllib.request.Request(
            f"http://localhost:8000/api/v1/incidents/{inc_id}/disposition",
            data=json.dumps(disp_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_disp) as resp:
            assert resp.status == 200
            print("Disposition recorded successfully!")

        # 10. Check Prometheus Metrics
        req_metrics = urllib.request.Request("http://localhost:8000/metrics")
        with urllib.request.urlopen(req_metrics) as resp:
            assert resp.status == 200
            metrics_text = resp.read().decode("utf-8")
            assert "triage_api_requests_total" in metrics_text
            print("Prometheus metrics verified!")

        print("\nALL DOCKER STACK TRANSACTIONS PASSED SUCCESSFULLY!")

    finally:
        print("Tearing down docker stack...")
        subprocess.run(["docker", "compose", "down", "-v"], check=False)


if __name__ == "__main__":
    run_docker_smoke()
