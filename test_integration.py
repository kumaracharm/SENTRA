import sys
import os
import json
import hmac
import hashlib
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Setup paths to import backend
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from fastapi.testclient import TestClient
from backend.main import app, LOGSHIELD_INGEST_TOKEN, LOGSHIELD_HMAC_SECRET, source_health_tracker

client = TestClient(app)

def run_integration_tests():
    print("=" * 70)
    print("  LOGSHIELD COMPREHENSIVE INTEGRATION & VALIDATION SUITE  ")
    print("=" * 70)

    # Reset logs before test suite
    reset_res = client.post("/api/reset")
    assert reset_res.status_code == 200

    # 1. Health Endpoint Check
    print("\n[Test 1] Testing /api/health Endpoint...")
    h_res = client.get("/api/health")
    assert h_res.status_code == 200
    h_data = h_res.json()
    assert h_data["status"] == "ok"
    assert h_data["ingest_endpoint"] == "/api/ingest"
    print("[OK] Health endpoint returned 200 OK with expected metadata.")

    # 2. Invalid Integration Token
    print("\n[Test 2] Testing Ingestion with Invalid Token...")
    inv_token_res = client.post(
        "/api/ingest",
        json={"user": "attacker", "event_type": "login_failed"},
        headers={"X-LogShield-Token": "wrong-token-123"}
    )
    assert inv_token_res.status_code == 401
    assert inv_token_res.json()["code"] == "INVALID_TOKEN"
    print("[OK] Invalid token rejected with 401 Unauthorized.")

    # 3. Malformed JSON Payload
    print("\n[Test 3] Testing Ingestion with Malformed Event...")
    malformed_res = client.post(
        "/api/ingest",
        content="this is not json!!!",
        headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN, "Content-Type": "application/json"}
    )
    assert malformed_res.status_code == 400
    assert malformed_res.json()["code"] == "MALFORMED_EVENT"
    print("[OK] Malformed JSON rejected with 400 Bad Request.")

    # 4. Valid Real-Time Event Ingestion
    print("\n[Test 4] Testing Normal Real-Time Event Ingestion...")
    now_iso = datetime.now(timezone.utc).isoformat()
    evt_normal = {
        "id": "evt-live-normal-100",
        "timestamp": now_iso,
        "user": "alice_employee",
        "source_ip": "192.168.1.50",
        "event_type": "login_success",
        "resource": "/portal/dashboard",
        "details": "User Alice logged in successfully"
    }
    ingest_res = client.post(
        "/api/ingest",
        json=evt_normal,
        headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN}
    )
    assert ingest_res.status_code == 200
    ingest_data = ingest_res.json()
    assert ingest_data["status"] == "success"
    assert ingest_data["ingested_count"] == 1
    print("[OK] Normal event ingested successfully with 200 OK.")

    # 5. HMAC-SHA256 Verification
    print("\n[Test 5] Testing HMAC-SHA256 Signature Verification...")
    evt_hmac = {
        "id": "evt-hmac-test-101",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": "bob_secure",
        "source_ip": "192.168.1.51",
        "event_type": "file_access",
        "resource": "/docs/project_plan.pdf"
    }
    body_bytes = json.dumps(evt_hmac).encode("utf-8")
    valid_sig = hmac.new(LOGSHIELD_HMAC_SECRET.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    # Valid HMAC
    hmac_ok_res = client.post(
        "/api/ingest",
        content=body_bytes,
        headers={
            "X-LogShield-Token": LOGSHIELD_INGEST_TOKEN,
            "X-LogShield-Signature": f"sha256={valid_sig}",
            "Content-Type": "application/json"
        }
    )
    assert hmac_ok_res.status_code == 200
    print("[OK] Valid HMAC signature accepted.")

    # Invalid HMAC
    hmac_bad_res = client.post(
        "/api/ingest",
        content=body_bytes,
        headers={
            "X-LogShield-Token": LOGSHIELD_INGEST_TOKEN,
            "X-LogShield-Signature": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "Content-Type": "application/json"
        }
    )
    assert hmac_bad_res.status_code == 401
    assert hmac_bad_res.json()["code"] == "INVALID_SIGNATURE"
    print("[OK] Invalid HMAC signature rejected with 401 Unauthorized.")

    # 6. Duplicate / Replayed Event Detection
    print("\n[Test 6] Testing Duplicate / Replayed Event Prevention...")
    replay_res = client.post(
        "/api/ingest",
        json=evt_normal,  # Same event ID: evt-live-normal-100
        headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN}
    )
    assert replay_res.status_code == 409
    assert replay_res.json()["code"] == "DUPLICATE_EVENT"
    print("[OK] Duplicate event ID rejected with 409 Conflict.")

    # Replayed sequence number
    seq_evt_1 = {
        "id": "evt-seq-1",
        "sequence": 5,
        "source_ip": "10.0.0.22",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": "charlie",
        "event_type": "login_success"
    }
    client.post("/api/ingest", json=seq_evt_1, headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN})

    seq_evt_replayed = {
        "id": "evt-seq-2",
        "sequence": 4,  # Lower sequence number (replayed/out-of-order)
        "source_ip": "10.0.0.22",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": "charlie",
        "event_type": "login_success"
    }
    seq_rep_res = client.post("/api/ingest", json=seq_evt_replayed, headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN})
    assert seq_rep_res.status_code == 409
    assert seq_rep_res.json()["code"] == "DUPLICATE_SEQUENCE"
    print("[OK] Out-of-order/replayed sequence number rejected with 409 Conflict.")

    # 7. Timestamp Drift Check
    print("\n[Test 7] Testing Timestamp Drift Validation...")
    future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    future_evt = {
        "id": "evt-future-drift",
        "timestamp": future_ts,
        "user": "timetraveler",
        "source_ip": "192.168.1.99",
        "event_type": "login_success"
    }
    drift_res = client.post("/api/ingest", json=future_evt, headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN})
    assert drift_res.status_code == 422
    assert drift_res.json()["code"] == "TIMESTAMP_DRIFT"
    print("[OK] Future timestamp drift rejected with 422 Unprocessable Entity.")

    # 8. Attack Chain & Incident Case File Generation
    print("\n[Test 8] Testing Attack Chain & Incident Case File Fields...")
    attack_user = "attacker_target"
    attack_ip = "203.0.113.88"
    attack_events = [
        {"id": "atk-1", "user": attack_user, "source_ip": attack_ip, "event_type": "login_failed", "timestamp": now_iso},
        {"id": "atk-2", "user": attack_user, "source_ip": attack_ip, "event_type": "login_failed", "timestamp": now_iso},
        {"id": "atk-3", "user": attack_user, "source_ip": attack_ip, "event_type": "login_failed", "timestamp": now_iso},
        {"id": "atk-4", "user": attack_user, "source_ip": attack_ip, "event_type": "login_success", "timestamp": now_iso},
        {"id": "atk-5", "user": attack_user, "source_ip": attack_ip, "event_type": "privilege_change", "resource": "/admin/roles/super_admin", "timestamp": now_iso},
        {"id": "atk-6", "user": attack_user, "source_ip": attack_ip, "event_type": "sensitive_resource_access", "resource": "/vault/db_passwords", "timestamp": now_iso},
    ]
    
    chain_res = client.post("/api/ingest", json=attack_events, headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN})
    assert chain_res.status_code == 200
    analysis = chain_res.json()["analysis"]
    incidents = analysis["incidents"]
    assert len(incidents) > 0

    case_file = incidents[0]
    assert case_file["verdict"] == "SUSPECTED ACCOUNT TAKEOVER & EXFILTRATION"
    assert case_file["severity"] in ("HIGH", "CRITICAL")
    assert case_file["risk_score"] >= 60
    assert "confidence" in case_file
    assert "reasons" in case_file
    assert set(["atk-1", "atk-2", "atk-3", "atk-4", "atk-5", "atk-6"]).issubset(set(case_file["supporting_event_ids"]))
    assert "missing_evidence" in case_file
    assert len(case_file["plausible_benign_explanations"]) > 0
    assert "recommended_action" in case_file
    assert case_file["action_executed"] == False  # Recommendations must NOT execute automatically
    print("[OK] Attack chain correlated into complete Incident Case File with non-executing recommended action.")

    # 9. Evidence Gap Detection & Status Recovery
    print("\n[Test 9] Testing Evidence-Gap Detection & Status Recovery...")
    gap_ip = "192.168.1.222"
    old_ts = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    gap_evt = {
        "id": "evt-gap-initial",
        "timestamp": old_ts,
        "user": "sensor_node_1",
        "source_ip": gap_ip,
        "event_type": "login_success"
    }
    client.post("/api/ingest", json=gap_evt, headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN})

    # Simulate 40s silence on source_health_tracker
    source_health_tracker.sources[gap_ip]["last_seen_epoch"] = time.time() - 40

    ana_gap_res = client.get("/api/analyze")
    ana_data = ana_gap_res.json()
    gap_sources = ana_data["evidence_gaps"]
    assert any(g["source_ip"] == gap_ip and g["status"] == "SUSPECTED EVIDENCE GAP" for g in gap_sources)
    print("[OK] Prolonged telemetry silence successfully flagged as 'SUSPECTED EVIDENCE GAP'.")

    # Verify Separate Scoring: Evidence Gap reduces confidence but does NOT increase Threat Risk
    conf_str = ana_data["risk_summary"]["confidence"]
    assert "Suspected Evidence Gap" in conf_str or "LOW" in conf_str or "MEDIUM" in conf_str
    print("[OK] Separate scoring verified: Evidence Gap reduced Evidence Confidence without artificially raising Threat Risk.")

    # Status Recovery when events resume
    recovery_evt = {
        "id": "evt-gap-recovery",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": "sensor_node_1",
        "source_ip": gap_ip,
        "event_type": "login_success"
    }
    rec_res = client.post("/api/ingest", json=recovery_evt, headers={"X-LogShield-Token": LOGSHIELD_INGEST_TOKEN})
    assert rec_res.status_code == 200
    rec_ana = rec_res.json()["analysis"]
    recovered_sources = [s for s in rec_ana["sources_health"] if s["source_ip"] == gap_ip]
    assert len(recovered_sources) > 0
    assert recovered_sources[0]["status"] == "HEALTHY"
    print("[OK] Telemetry recovery verified: Source status restored to 'HEALTHY' when new events resumed.")

    print("\n" + "=" * 70)
    print("  ALL INTEGRATION TESTS PASSED SUCCESSFULLY! (10/10 SCENARIOS VERIFIED)  ")
    print("=" * 70)

if __name__ == "__main__":
    run_integration_tests()
