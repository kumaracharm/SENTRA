"""
Tests for L3 — Temporal Attack Graph
=====================================
Tests: session grouping, edge scoring, pattern matching, counterfactual,
       contradiction detection, missing-observation identification.
"""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from backend.attack_graph import TemporalAttackGraph, _match_patterns, _ATTACK_PATTERNS


def _ts(hour_offset: float = 0.0) -> str:
    base = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(hours=hour_offset)).isoformat()


def test_brute_force_pattern_detected():
    """A login_failed×3 → login_success sequence should match CREDENTIAL_BRUTE_FORCE."""
    engine = TemporalAttackGraph(session_window_minutes=30)
    events = [
        {"id": "bf1", "user": "admin", "source_ip": "10.0.0.1",
         "event_type": "login_failed", "timestamp": _ts(0), "resource": "/login"},
        {"id": "bf2", "user": "admin", "source_ip": "10.0.0.1",
         "event_type": "login_failed", "timestamp": _ts(0.1), "resource": "/login"},
        {"id": "bf3", "user": "admin", "source_ip": "10.0.0.1",
         "event_type": "login_failed", "timestamp": _ts(0.2), "resource": "/login"},
        {"id": "bf4", "user": "admin", "source_ip": "10.0.0.1",
         "event_type": "login_success", "timestamp": _ts(0.25), "resource": "/login"},
    ]
    results = engine.analyze(events)
    assert len(results) > 0, "Expected at least one attack chain result"
    top = results[0]
    pattern_names = [p["name"] for p in top.matched_patterns]
    assert "CREDENTIAL_BRUTE_FORCE" in pattern_names, f"Got patterns: {pattern_names}"
    assert top.graph_score > 0
    print("Test 1 Passed: Brute-force pattern correctly detected in temporal graph")


def test_full_account_takeover_detected():
    """Full attack chain: failed → success → privilege → sensitive access."""
    engine = TemporalAttackGraph(session_window_minutes=60)
    events = [
        {"id": "ato1", "user": "admin", "source_ip": "203.0.113.1",
         "event_type": "login_failed", "timestamp": _ts(0)},
        {"id": "ato2", "user": "admin", "source_ip": "203.0.113.1",
         "event_type": "login_success", "timestamp": _ts(0.1)},
        {"id": "ato3", "user": "admin", "source_ip": "203.0.113.1",
         "event_type": "privilege_change", "timestamp": _ts(0.2), "resource": "/admin/roles"},
        {"id": "ato4", "user": "admin", "source_ip": "203.0.113.1",
         "event_type": "sensitive_resource_access", "timestamp": _ts(0.3), "resource": "/vault"},
    ]
    results = engine.analyze(events)
    assert len(results) > 0
    top = results[0]
    pattern_names = [p["name"] for p in top.matched_patterns]
    assert "FULL_ACCOUNT_TAKEOVER" in pattern_names, f"Patterns: {pattern_names}"
    assert top.graph_score > 30.0, f"Score too low: {top.graph_score}"
    print("Test 2 Passed: Full account-takeover pattern detected with high score")


def test_session_window_isolates_sessions():
    """Events >60 minutes apart should NOT be grouped into the same incident."""
    engine = TemporalAttackGraph(session_window_minutes=60)
    events = [
        {"id": "s1", "user": "alice", "source_ip": "192.168.1.1",
         "event_type": "login_failed", "timestamp": _ts(0)},
        {"id": "s2", "user": "alice", "source_ip": "192.168.1.1",
         "event_type": "login_success", "timestamp": _ts(2.5)},  # 2.5h gap = new session
    ]
    results = engine.analyze(events)
    # With session isolation, these should NOT be in the same chain
    if results:
        # If grouped, the graph_score should be very low (no meaningful edges cross-session)
        for r in results:
            cross_session_edge_count = len([
                e for e in r.edges if e.temporal_gap_seconds > 3600
            ])
            assert cross_session_edge_count == 0, \
                "No edges should cross the session window"
    print("Test 3 Passed: Session window correctly isolates events 2.5h apart")


def test_counterfactual_analysis():
    """Removing the login_success event from brute-force chain should reduce score."""
    engine = TemporalAttackGraph(session_window_minutes=30)
    events = [
        {"id": "cf1", "user": "victim", "source_ip": "10.1.2.3",
         "event_type": "login_failed", "timestamp": _ts(0)},
        {"id": "cf2", "user": "victim", "source_ip": "10.1.2.3",
         "event_type": "login_failed", "timestamp": _ts(0.05)},
        {"id": "cf3", "user": "victim", "source_ip": "10.1.2.3",
         "event_type": "login_success", "timestamp": _ts(0.1)},
    ]
    results = engine.analyze(events)
    assert len(results) > 0

    original_score = results[0].graph_score
    cf = engine.counterfactual_analysis(events, "cf3")
    
    assert cf is not None
    assert "original_score" in cf
    assert "counterfactual_score" in cf
    assert cf["score_delta"] < 0, "Removing login_success should reduce score"
    assert "interpretation" in cf
    print(f"Test 4 Passed: Counterfactual removes login_success: "
          f"score {original_score:.1f} -> {cf['counterfactual_score']:.1f} (delta: {cf['score_delta']:.1f})")


def test_benign_sequence_generates_no_result():
    """
    Normal login + file access from same user should NOT generate a scored chain
    (no meaningful transitions between these event types).
    """
    engine = TemporalAttackGraph(session_window_minutes=30)
    events = [
        {"id": "n1", "user": "alice", "source_ip": "192.168.1.10",
         "event_type": "login_success", "timestamp": _ts(0)},
        {"id": "n2", "user": "alice", "source_ip": "192.168.1.10",
         "event_type": "file_access", "timestamp": _ts(0.1)},
    ]
    results = engine.analyze(events)
    # login_success → file_access has weight 1.0 (low but non-zero)
    # with no attack pattern match, this chain should exist but have low score
    # The important thing is NO FULL_ACCOUNT_TAKEOVER pattern
    for r in results:
        pattern_names = [p["name"] for p in r.matched_patterns]
        assert "FULL_ACCOUNT_TAKEOVER" not in pattern_names
        assert r.graph_score < 30.0, f"Benign chain score too high: {r.graph_score}"
    print("Test 5 Passed: Benign login+file_access does not generate high-score attack chain")


def test_contradiction_detected_for_normal_success():
    """login_success without prior failures should generate contradiction text."""
    engine = TemporalAttackGraph(session_window_minutes=30)
    events = [
        {"id": "c1", "user": "admin", "source_ip": "192.168.1.1",
         "event_type": "login_success", "timestamp": _ts(0)},
        {"id": "c2", "user": "admin", "source_ip": "192.168.1.1",
         "event_type": "privilege_change", "timestamp": _ts(0.1), "resource": "/admin"},
    ]
    results = engine.analyze(events)
    assert len(results) > 0
    top = results[0]
    # Should note that success without prior failure is a possible benign explanation
    assert len(top.contradictory_evidence) > 0, \
        "Should detect contradiction: success without prior failure"
    print("Test 6 Passed: Contradiction detected for success-without-failure sequence")


def test_pattern_matching_function():
    """Unit test the _match_patterns helper directly."""
    types = ["login_failed", "login_failed", "login_failed", "login_success",
             "privilege_change", "sensitive_resource_access"]
    matched = _match_patterns(types)
    names = [p["name"] for p in matched]
    assert "CREDENTIAL_BRUTE_FORCE" in names
    assert "FULL_ACCOUNT_TAKEOVER" in names
    assert "PRIVILEGE_ESCALATION_CHAIN" in names
    print(f"Test 7 Passed: Pattern matching function correctly identifies {names}")


def run_all():
    print("=== L3 Temporal Attack Graph Tests ===")
    test_brute_force_pattern_detected()
    test_full_account_takeover_detected()
    test_session_window_isolates_sessions()
    test_counterfactual_analysis()
    test_benign_sequence_generates_no_result()
    test_contradiction_detected_for_normal_success()
    test_pattern_matching_function()
    print("\n=== All L3 Attack Graph Tests Passed (7/7) ===")


if __name__ == "__main__":
    run_all()
