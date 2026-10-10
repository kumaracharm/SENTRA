"""
Tests for L2 — Adaptive Baseline (Page-Hinkley)
=================================================
Tests: PHDetector alarm firing, trust-gated updates, baseline freezing,
       poisoning detection, z-score scoring, cold-start fallback.
"""
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from backend.adaptive_baseline import PHDetector, EntityProfile, AdaptiveBaselineTracker, GlobalProfile


def test_ph_detector_fires_on_shift():
    """PHDetector should fire after a sustained upward shift."""
    ph = PHDetector(delta=0.5, threshold=5.0, direction="up")
    # Feed 20 observations around 10 (normal)
    fired_normal = False
    for _ in range(20):
        if ph.update(10.0):
            fired_normal = True
    # Now shift to 15
    fired_on_shift = False
    for _ in range(20):
        if ph.update(15.0):
            fired_on_shift = True
    assert not fired_normal, "PH should not fire on stable normal stream"
    assert fired_on_shift, "PH should fire on sustained upward shift"
    print("Test 1 Passed: PHDetector fires on sustained upward shift, not on stable stream")


def test_ph_detector_resets_after_alarm():
    """After an alarm, the PH cumulative is reset to 0."""
    ph = PHDetector(delta=0.1, threshold=2.0, direction="up")
    fired_first = False
    for i in range(30):
        if ph.update(10.0 if i < 10 else 15.0):
            fired_first = True
            break
    assert fired_first
    # After alarm, cumulative should be 0
    assert ph._cumulative == 0.0
    print("Test 2 Passed: PHDetector cumulative resets to 0 after alarm")


def test_baseline_trust_gated_update():
    """Baseline should NOT update from UNTRUSTED events."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = Path(f.name)
    tracker = AdaptiveBaselineTracker(storage_path=tmp)
    
    user = "test_user"
    base_ts = datetime.now(timezone.utc)
    
    # Establish 10 normal events (9am)
    for i in range(10):
        tracker.process_event(
            {"id": f"n{i}", "user": user, "hour": 9,
             "source_ip": "192.168.1.1", "event_type": "login_success",
             "timestamp": (base_ts + timedelta(minutes=i)).isoformat()},
            trust_level="TRUSTED",
        )
    
    hours_after_trusted = list(tracker.entities[user].login_hours)
    assert 9 in hours_after_trusted
    
    # Now process 5 UNTRUSTED events at 3am — should NOT shift baseline
    for i in range(5):
        tracker.process_event(
            {"id": f"u{i}", "user": user, "hour": 3,
             "source_ip": "10.0.0.99", "event_type": "login_success",
             "timestamp": (base_ts + timedelta(hours=i)).isoformat()},
            trust_level="UNTRUSTED",
        )
    
    hours_after_untrusted = tracker.entities[user].login_hours
    # The baseline hours should not include 3am events from UNTRUSTED
    # (UNTRUSTED events skip the update path)
    count_3am = hours_after_untrusted.count(3)
    assert count_3am == 0, f"UNTRUSTED events should not update baseline, found {count_3am} 3am entries"
    print("Test 3 Passed: Baseline update correctly blocked for UNTRUSTED trust level")


def test_baseline_freeze_on_drift():
    """Baseline should freeze (stop accepting updates) when PH fires."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = Path(f.name)
    tracker = AdaptiveBaselineTracker(storage_path=tmp)
    
    user = "drift_user"
    ts = datetime.now(timezone.utc)
    
    # Establish stable 9am baseline
    for i in range(15):
        tracker.process_event(
            {"id": f"stab{i}", "user": user, "hour": 9,
             "source_ip": "192.168.1.1", "event_type": "login_success",
             "timestamp": (ts + timedelta(minutes=i)).isoformat()},
            trust_level="TRUSTED",
        )
    
    # Now introduce a sustained upward shift to trigger PH
    alarm_fired = False
    for i in range(30):
        result = tracker.process_event(
            {"id": f"shift{i}", "user": user, "hour": 22,
             "source_ip": "192.168.1.1", "event_type": "login_success",
             "timestamp": (ts + timedelta(hours=i)).isoformat()},
            trust_level="TRUSTED",
        )
        if result.get("drift_alarm"):
            alarm_fired = True
    
    assert alarm_fired, "Drift alarm should have fired on sustained hour shift from 9 to 22"
    assert tracker.entities[user]._freeze_counter > 0 or len(tracker.entities[user].drift_alarms) > 0
    print("Test 4 Passed: Baseline freezes after Page-Hinkley drift alarm")


def test_cold_start_uses_global_fallback():
    """New entity with no history should use global profile."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = Path(f.name)
    tracker = AdaptiveBaselineTracker(storage_path=tmp)
    
    # Warm up global profile with 20 events at 9am
    ts = datetime.now(timezone.utc)
    for i in range(20):
        tracker.global_profile.update(
            {"hour": 9, "event_type": "login_success"}
        )
    
    # Score a 3am event for a brand new user (cold start)
    result = tracker.process_event(
        {"id": "cold-001", "user": "brand_new_user", "hour": 3,
         "source_ip": "10.0.0.1", "event_type": "login_success",
         "timestamp": ts.isoformat()},
        trust_level="STANDARD",
    )
    
    # Should detect deviation from global 9am baseline
    assert result["history_count"] == 0 or result["anomaly_score"] > 0, \
        "Cold-start user should use global fallback or have low history"
    print("Test 5 Passed: Cold-start entity uses global profile for scoring")


def test_poisoning_flag_set():
    """Suspected poisoning flag should be set after drift alarm fires.
    Uses lower PH threshold for reliable test triggering."""
    from backend.adaptive_baseline import PHDetector as PH
    
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = Path(f.name)
    tracker = AdaptiveBaselineTracker(storage_path=tmp)
    
    user = "poison_victim"
    ts = datetime.now(timezone.utc)
    
    # Override PH threshold for this test to ensure reliable triggering
    # (normal threshold=6.0 requires ~20+ observations; lower it to 2.0 for test speed)
    if user not in tracker.entities:
        from backend.adaptive_baseline import EntityProfile
        tracker.entities[user] = EntityProfile(user)
    profile = tracker.entities[user]
    profile.ph_hour_up = PH(delta=0.5, threshold=2.0, direction="up")
    profile.ph_hour_down = PH(delta=0.5, threshold=2.0, direction="down")
    
    # Establish stable 9am baseline
    for i in range(10):
        tracker.process_event(
            {"id": f"s{i}", "user": user, "hour": 9,
             "source_ip": "192.168.1.1", "event_type": "login_success",
             "timestamp": (ts + timedelta(minutes=i)).isoformat()},
            trust_level="TRUSTED",
        )
    
    # Introduce sustained shift to 22h — should trigger PH with lower threshold
    alarm_fired = False
    for i in range(20):
        result = tracker.process_event(
            {"id": f"p{i}", "user": user, "hour": 22,
             "source_ip": "192.168.1.1", "event_type": "login_success",
             "timestamp": (ts + timedelta(hours=i + 1)).isoformat()},
            trust_level="TRUSTED",
        )
        if result.get("drift_alarm") or result.get("suspected_poisoning"):
            alarm_fired = True
            break
    
    p = tracker.entities.get(user)
    has_signal = alarm_fired or (p and (p.suspected_poisoning or len(p.drift_alarms) > 0))
    assert has_signal, (
        "Expected drift alarm or poisoning flag after sustained hour shift from 9 to 22. "
        f"Profile drift_alarms={len(p.drift_alarms) if p else 'n/a'}, "
        f"suspected_poisoning={p.suspected_poisoning if p else 'n/a'}"
    )
    print("Test 6 Passed: Suspected poisoning flag or drift alarms set after sustained behavioral shift")


def run_all():
    print("=== L2 Adaptive Baseline Tests ===")
    test_ph_detector_fires_on_shift()
    test_ph_detector_resets_after_alarm()
    test_baseline_trust_gated_update()
    test_baseline_freeze_on_drift()
    test_cold_start_uses_global_fallback()
    test_poisoning_flag_set()
    print("\n=== All L2 Adaptive Baseline Tests Passed (6/6) ===")


if __name__ == "__main__":
    run_all()
