import urllib.request
import urllib.error
import json
import hmac
import hashlib
import time
from datetime import datetime, timezone, timedelta

SERVER_URL = "http://127.0.0.1:8000"
TOKEN = "logshield-secret-token"
HMAC_SECRET = "logshield-hmac-secret-key"

def http_post(endpoint, payload_dict_or_str, headers=None):
    if headers is None:
        headers = {}
    url = f"{SERVER_URL}{endpoint}"
    
    if isinstance(payload_dict_or_str, (dict, list)):
        data_bytes = json.dumps(payload_dict_or_str).encode("utf-8")
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
    elif isinstance(payload_dict_or_str, str):
        data_bytes = payload_dict_or_str.encode("utf-8")
    else:
        data_bytes = payload_dict_or_str

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}

def http_get(endpoint):
    url = f"{SERVER_URL}{endpoint}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))

def verify_live():
    print("=" * 70)
    print("  LIVE SERVER END-TO-END VERIFICATION AGAINST HTTP://127.0.0.1:8000  ")
    print("=" * 70)

    # 0. Check or auto-launch LogShield server
    try:
        urllib.request.urlopen(f"{SERVER_URL}/api/health", timeout=1)
        print("[OK] LogShield API server is already active on port 8000.")
    except Exception:
        print("[INFO] Launching LogShield API server on port 8000 in background thread...")
        import uvicorn, threading
        from backend.main import app
        srv_thread = threading.Thread(
            target=uvicorn.run,
            args=(app,),
            kwargs={"host": "127.0.0.1", "port": 8000, "log_level": "error"},
            daemon=True
        )
        srv_thread.start()
        time.sleep(1.5)

    # Reset logs
    http_post("/api/reset", {})

    # 1. Health & Analyze check
    s1, h = http_get("/api/health")
    assert s1 == 200 and h["status"] == "ok"
    print("[PASS] 1. Live GET /api/health returned 200 OK.")

    s2, a = http_get("/api/analyze")
    assert s2 == 200 and a["total_events"] == 0
    print("[PASS] 2. Live GET /api/analyze returned 200 OK (0 events initial).")

    # 2. Reject Invalid Token
    code_inv_tok, res_inv_tok = http_post("/api/ingest", {"user": "hacker"}, headers={"X-LogShield-Token": "bad-token"})
    assert code_inv_tok == 401 and res_inv_tok["code"] == "INVALID_TOKEN"
    print("[PASS] 3. Invalid token rejected with HTTP 401 (INVALID_TOKEN).")

    # 3. Reject Invalid HMAC Signature
    body_data = json.dumps({"user": "alice", "event_type": "login_success"}).encode("utf-8")
    code_bad_hmac, res_bad_hmac = http_post(
        "/api/ingest",
        body_data.decode("utf-8"),
        headers={
            "X-LogShield-Token": TOKEN,
            "X-LogShield-Signature": "sha256=invalid000000000000000000000000000000000000000000000000000000000"
        }
    )
    assert code_bad_hmac == 401 and res_bad_hmac["code"] == "INVALID_SIGNATURE"
    print("[PASS] 4. Invalid HMAC signature rejected with HTTP 401 (INVALID_SIGNATURE).")

    # 4. Reject Timestamp Drift
    future_time = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
    code_drift, res_drift = http_post("/api/ingest", {"id": "evt-fut", "event_type": "login_failed", "timestamp": future_time}, headers={"X-LogShield-Token": TOKEN})
    assert code_drift == 422 and res_drift["code"] == "TIMESTAMP_DRIFT"
    print("[PASS] 5. Timestamp drift rejected with HTTP 422 (TIMESTAMP_DRIFT).")

    # 5. Ingest Real Live Events
    now_iso = datetime.now(timezone.utc).isoformat()
    live_events = [
        {
            "id": "live-evt-001",
            "sequence": 1,
            "timestamp": now_iso,
            "user": "live_user_1",
            "source_ip": "198.51.100.77",
            "event_type": "login_failed",
            "resource": "/login"
        },
        {
            "id": "live-evt-002",
            "sequence": 2,
            "timestamp": now_iso,
            "user": "live_user_1",
            "source_ip": "198.51.100.77",
            "event_type": "login_failed",
            "resource": "/login"
        },
        {
            "id": "live-evt-003",
            "sequence": 3,
            "timestamp": now_iso,
            "user": "live_user_1",
            "source_ip": "198.51.100.77",
            "event_type": "login_failed",
            "resource": "/login"
        },
        {
            "id": "live-evt-004",
            "sequence": 4,
            "timestamp": now_iso,
            "user": "live_user_1",
            "source_ip": "198.51.100.77",
            "event_type": "login_success",
            "resource": "/login"
        }
    ]

    code_ingest, res_ingest = http_post("/api/ingest", live_events, headers={"X-LogShield-Token": TOKEN})
    assert code_ingest == 200 and res_ingest["ingested_count"] == 4
    print("[PASS] 6. Live POST /api/ingest accepted 4 security events with HTTP 200.")

    # 6. Reject Duplicate Event ID / Sequence
    code_dup, res_dup = http_post("/api/ingest", live_events[0], headers={"X-LogShield-Token": TOKEN})
    assert code_dup == 409 and res_dup["code"] == "DUPLICATE_EVENT"
    print("[PASS] 7. Duplicate event ID rejected with HTTP 409 (DUPLICATE_EVENT).")

    # 7. Verify Ingested Events appear in GET /api/analyze
    s3, ana = http_get("/api/analyze")
    assert s3 == 200
    assert ana["total_events"] == 4
    assert len(ana["incidents"]) > 0
    inc = ana["incidents"][0]
    assert inc["verdict"] == "CREDENTIAL BRUTE FORCE SUCCESS"
    assert inc["action_executed"] == False
    print("[PASS] 8. Confirmed ingested live events appear in GET /api/analyze with correlated Incident Case File!")

    print("=" * 70)
    print("  ALL LIVE END-TO-END VERIFICATION CHECKS PASSED! (8/8 PASSED)  ")
    print("=" * 70)

if __name__ == "__main__":
    verify_live()
