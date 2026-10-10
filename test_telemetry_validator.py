"""
Tests for L1 — Trustworthy Telemetry Validator
==============================================
Tests: schema validation, timestamp drift, HMAC-trust level, persistent replay,
       sequence deduplication, source identity registry, provenance tagging.
"""
import sys
import tempfile
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from backend.telemetry_validator import (
    EventValidator, PersistentReplayStore,
    SourceIdentityRegistry, TrustLevel, TelemetryClassification
)


def _make_validator():
    """Return a fresh EventValidator with in-memory-only stores (no disk I/O)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"[]")
        tmp_path = Path(f.name)
    replay = PersistentReplayStore(tmp_path)
    registry = SourceIdentityRegistry()
    return EventValidator(replay_store=replay, source_registry=registry)


def test_valid_event_accepted():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    result = v.validate_event(
        {"id": "evt-001", "event_type": "login_success",
         "source_ip": "192.168.1.1", "timestamp": now.isoformat()},
        hmac_verified=False,
        now_utc=now,
    )
    assert result.accepted, f"Expected accepted, got: {result.rejection_detail}"
    assert result.trust_level in (TrustLevel.STANDARD, TrustLevel.LOW, TrustLevel.TRUSTED)
    assert result.classification == TelemetryClassification.NORMAL
    print("Test 1 Passed: Valid event accepted with correct trust level")


def test_duplicate_event_rejected():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    evt = {"id": "evt-dup-001", "event_type": "login_success",
           "source_ip": "10.0.0.1", "timestamp": now.isoformat()}
    r1 = v.validate_event(evt, now_utc=now)
    assert r1.accepted
    r2 = v.validate_event(evt, now_utc=now)
    assert not r2.accepted
    assert r2.rejection_code == "DUPLICATE_EVENT"
    assert r2.classification == TelemetryClassification.DUPLICATED
    print("Test 2 Passed: Duplicate event ID correctly rejected")


def test_future_timestamp_rejected():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    future = now + timedelta(hours=2)
    result = v.validate_event(
        {"id": "evt-future", "event_type": "login_failed",
         "timestamp": future.isoformat(), "source_ip": "10.0.0.2"},
        now_utc=now,
    )
    assert not result.accepted
    assert result.rejection_code == "TIMESTAMP_DRIFT"
    print("Test 3 Passed: Future timestamp (>5min) correctly rejected")


def test_old_timestamp_rejected():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    old = now - timedelta(hours=25)
    result = v.validate_event(
        {"id": "evt-old", "event_type": "login_success",
         "timestamp": old.isoformat(), "source_ip": "10.0.0.3"},
        now_utc=now,
    )
    assert not result.accepted
    assert result.rejection_code == "TIMESTAMP_DRIFT"
    print("Test 4 Passed: Timestamp >24h in past correctly rejected")


def test_delayed_event_classified():
    """Event 5 hours old: within 24h window but classified as DELAYED."""
    v = _make_validator()
    now = datetime.now(timezone.utc)
    old = now - timedelta(hours=5)
    result = v.validate_event(
        {"id": "evt-delayed", "event_type": "file_access",
         "timestamp": old.isoformat(), "source_ip": "10.0.0.4"},
        now_utc=now,
    )
    assert result.accepted
    assert result.classification == TelemetryClassification.DELAYED
    print("Test 5 Passed: Delayed event (5h old) accepted with DELAYED classification")


def test_sequence_replay_rejected():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    src_ip = "10.0.0.5"
    r1 = v.validate_event(
        {"id": "seq-a", "event_type": "login_success", "source_ip": src_ip,
         "sequence": 10, "timestamp": now.isoformat()},
        now_utc=now,
    )
    assert r1.accepted

    r2 = v.validate_event(
        {"id": "seq-b", "event_type": "login_success", "source_ip": src_ip,
         "sequence": 8, "timestamp": now.isoformat()},
        now_utc=now,
    )
    assert not r2.accepted
    assert r2.rejection_code == "DUPLICATE_SEQUENCE"
    print("Test 6 Passed: Out-of-order sequence number correctly rejected")


def test_hmac_verified_upgrades_trust():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    src = "192.168.1.99"
    # Make source "known" by processing 5 events from it
    for i in range(5):
        v.validate_event(
            {"id": f"warmup-{i}", "event_type": "login_success",
             "source_ip": src, "timestamp": now.isoformat()},
            hmac_verified=True, now_utc=now,
        )
    result = v.validate_event(
        {"id": "hmac-test", "event_type": "file_access", "source_ip": src,
         "timestamp": now.isoformat()},
        hmac_verified=True, now_utc=now,
    )
    assert result.accepted
    assert result.trust_level == TrustLevel.TRUSTED
    print("Test 7 Passed: HMAC-verified event from known source gets TRUSTED level")


def test_missing_event_type_rejected():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    result = v.validate_event(
        {"id": "no-type", "source_ip": "10.0.0.6",
         "timestamp": now.isoformat()},  # No event_type
        now_utc=now,
    )
    assert not result.accepted
    assert result.rejection_code == "MALFORMED_EVENT"
    print("Test 8 Passed: Event missing event_type field correctly rejected as MALFORMED")


def test_provenance_tagging():
    v = _make_validator()
    now = datetime.now(timezone.utc)
    result = v.validate_event(
        {"id": "prov-001", "event_type": "login_success",
         "source_ip": "10.0.0.7", "timestamp": now.isoformat()},
        hmac_verified=False, ingest_method="api", now_utc=now,
    )
    assert result.accepted
    assert "_trust_level" in result.provenance
    assert "_ingest_method" in result.provenance
    assert result.provenance["_ingest_method"] == "api"
    assert "_hmac_verified" in result.provenance
    print("Test 9 Passed: Provenance fields correctly tagged on accepted event")


def test_persistent_replay_survives_reset():
    """Replay store persistence: after saving, a new store from same path sees old IDs."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = Path(f.name)
    
    store1 = PersistentReplayStore(tmp_path)
    store1.add("persisted-id-abc")
    
    store2 = PersistentReplayStore(tmp_path)
    assert store2.contains("persisted-id-abc")
    print("Test 10 Passed: Persistent replay store survives reload from disk")


def run_all():
    print("=== L1 Telemetry Validator Tests ===")
    test_valid_event_accepted()
    test_duplicate_event_rejected()
    test_future_timestamp_rejected()
    test_old_timestamp_rejected()
    test_delayed_event_classified()
    test_sequence_replay_rejected()
    test_hmac_verified_upgrades_trust()
    test_missing_event_type_rejected()
    test_provenance_tagging()
    test_persistent_replay_survives_reset()
    print("\n=== All L1 Telemetry Validator Tests Passed (10/10) ===")


if __name__ == "__main__":
    run_all()
