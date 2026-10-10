import sys
from pathlib import Path

# Setup paths to import backend
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from backend.baseline import EntityBaselineTracker

def run_tests():
    print("--- Running Entity Baseline Tests ---")
    tracker = EntityBaselineTracker()

    # Create baseline with normal known-user behavior
    historical_events = []
    for i in range(10):
        historical_events.append({
            "id": f"hist-{i}",
            "user": "alice",
            "hour": 9,
            "source_ip": "192.168.1.100",
            "event_type": "login_success"
        })
    tracker.fit(historical_events)

    # Test 1: normal known-user behavior
    evt_normal = {
        "id": "test-1", "user": "alice", "hour": 9, "source_ip": "192.168.1.100", "event_type": "login_success"
    }
    res_normal = tracker.analyze_event(evt_normal)
    assert res_normal["baseline_score"] == 0
    print("Test 1 Passed: Normal known-user behavior (0 deviations)")

    # Test 2: unusual login hour
    evt_unusual_hour = {
        "id": "test-2", "user": "alice", "hour": 3, "source_ip": "192.168.1.100", "event_type": "login_success"
    }
    res_hour = tracker.analyze_event(evt_unusual_hour)
    assert any("Unusual login hour" in d for d in res_hour["deviations"])
    print("Test 2 Passed: Unusual login hour detected")

    # Test 3: unknown source IP
    evt_unknown_ip = {
        "id": "test-3", "user": "alice", "hour": 9, "source_ip": "10.0.0.55", "event_type": "login_success"
    }
    res_ip = tracker.analyze_event(evt_unknown_ip)
    assert any("Unknown source IP" in d for d in res_ip["deviations"])
    print("Test 3 Passed: Unknown source IP detected")

    # Test 4: elevated failure rate
    for i in range(10):
        tracker.fit([{"id": f"hist-fail-{i}", "user": "charlie", "hour": 9, "source_ip": "192.168.1.100", "event_type": "login_failed"}])
    evt_failure = {
        "id": "test-4", "user": "charlie", "hour": 9, "source_ip": "192.168.1.100", "event_type": "login_failed"
    }
    res_fail = tracker.analyze_event(evt_failure)
    assert any("Elevated failure rate" in d for d in res_fail["deviations"])
    print("Test 4 Passed: Elevated failure rate detected")

    # Test 5 & 6: new user with insufficient history / peer global fallback
    evt_new_user = {
        "id": "test-5", "user": "bob_new", "hour": 2, "source_ip": "10.0.0.99", "event_type": "login_success"
    }
    res_new = tracker.analyze_event(evt_new_user)
    assert res_new["confidence"] == "LOW"
    assert any("Unusual global login hour" in d for d in res_new["deviations"])
    print("Test 5 & 6 Passed: Cold-start new user detected with LOW confidence & Global hour fallback used")
    print("All tests passed.")

if __name__ == "__main__":
    run_tests()
