"""
L1 — Trustworthy Telemetry and Evidence
========================================
EventValidator: validates, classifies, and tags every incoming event before
it is accepted into the pipeline.

Key design decisions
--------------------
* Each event is assigned a TrustLevel that flows through the full pipeline.
  Downstream layers (baseline, risk engine) gate their decisions on this level.
* Missing-telemetry is a *separate* signal from threat severity. The two must
  never be conflated (per the engineering requirement).
* Persistent replay store writes accepted event IDs to disk so that replay
  protection survives server restarts.
* Provenance fields are non-destructive additions to the existing event schema.

Reference: NIST SP 800-92 "Guide to Computer Security Log Management",
           §3.2 — log integrity and source authentication.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_EVENT_TYPES = {
    "login_failed",
    "login_success",
    "privilege_change",
    "sensitive_resource_access",
    "file_access",
    "unusual_request",
    "data_transfer",
}

# Maximum time an event may be in the future (seconds)
MAX_FUTURE_DRIFT_SEC: int = 300
# Maximum time an event may be in the past (seconds)
MAX_PAST_DRIFT_SEC: int = 86_400  # 24 h

# Persistent replay-store path (relative to the logshield project root)
_REPLAY_STORE_PATH: Path = Path(__file__).resolve().parent.parent / "data" / "seen_ids.json"

# ---------------------------------------------------------------------------
# Trust levels (ordered from most to least trustworthy)
# ---------------------------------------------------------------------------

class TrustLevel:
    TRUSTED = "TRUSTED"       # valid HMAC + fresh timestamp + known source
    STANDARD = "STANDARD"     # valid token but no HMAC, or HMAC not required
    LOW = "LOW"               # missing schema fields or cold-start source
    UNTRUSTED = "UNTRUSTED"   # timestamp drift, failed schema validation, etc.


# ---------------------------------------------------------------------------
# Classification labels for abnormal telemetry states
# ---------------------------------------------------------------------------

class TelemetryClassification:
    NORMAL = "NORMAL"
    MISSING = "MISSING"          # expected event absent from source
    DELAYED = "DELAYED"          # event arrived after MAX_PAST_DRIFT_SEC but accepted anyway
    DUPLICATED = "DUPLICATED"    # event ID or sequence replayed
    MALFORMED = "MALFORMED"      # JSON parse error or missing required field
    UNTRUSTED = "UNTRUSTED"      # timestamp drift or failed HMAC


# ---------------------------------------------------------------------------
# Validation result container
# ---------------------------------------------------------------------------

class ValidationResult:
    """Immutable outcome of a single-event validation pass."""

    __slots__ = (
        "accepted", "trust_level", "classification", "rejection_code",
        "rejection_detail", "provenance", "warnings",
    )

    def __init__(
        self,
        *,
        accepted: bool,
        trust_level: str,
        classification: str,
        rejection_code: Optional[str] = None,
        rejection_detail: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        warnings: Optional[List[str]] = None,
    ):
        self.accepted = accepted
        self.trust_level = trust_level
        self.classification = classification
        self.rejection_code = rejection_code
        self.rejection_detail = rejection_detail
        self.provenance = provenance or {}
        self.warnings = warnings or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "trust_level": self.trust_level,
            "classification": self.classification,
            "rejection_code": self.rejection_code,
            "rejection_detail": self.rejection_detail,
            "provenance": self.provenance,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# Persistent replay store
# ---------------------------------------------------------------------------

class PersistentReplayStore:
    """
    Write-through in-memory + on-disk set of accepted event IDs.

    Prevents replay attacks across server restarts.
    On first load, the in-memory set is populated from disk.
    Writes are synchronous (acceptable for the current throughput; can be
    made async if event rates grow significantly).
    """

    def __init__(self, path: Path):
        self._path = path
        self._seen: set[str] = set()
        self._load()

    def _load(self) -> None:
        """Load persisted IDs from disk into the in-memory set."""
        try:
            if self._path.exists():
                with open(self._path, "r", encoding="utf-8") as f:
                    ids = json.load(f)
                    if isinstance(ids, list):
                        self._seen = set(ids)
        except Exception:
            self._seen = set()

    def _save(self) -> None:
        """Flush the in-memory set to disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(list(self._seen), f)
        except Exception:
            pass  # Non-fatal: in-memory protection still works

    def contains(self, event_id: str) -> bool:
        return event_id in self._seen

    def add(self, event_id: str) -> None:
        self._seen.add(event_id)
        self._save()

    def clear(self) -> None:
        self._seen.clear()
        self._save()

    def __len__(self) -> int:
        return len(self._seen)


# ---------------------------------------------------------------------------
# Source-identity registry
# ---------------------------------------------------------------------------

class SourceIdentityRegistry:
    """
    Tracks per-source-IP identity metadata *independently* of source health.

    Source health (silence detection) lives in SourceHealthTracker.
    This registry tracks first-seen, event volume, trust history, and
    whether the source is known/unknown — all orthogonal to silence gaps.
    """

    def __init__(self):
        self._sources: Dict[str, Dict[str, Any]] = {}

    def record(self, source_ip: str, trust_level: str) -> None:
        if source_ip not in self._sources:
            self._sources[source_ip] = {
                "source_ip": source_ip,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "event_count": 0,
                "trust_history": [],
                "is_known": False,
            }
        s = self._sources[source_ip]
        s["event_count"] += 1
        # Keep last 10 trust levels for trend analysis
        s["trust_history"] = (s["trust_history"] + [trust_level])[-10:]
        # A source becomes "known" after 5 events from it
        if s["event_count"] >= 5:
            s["is_known"] = True

    def get(self, source_ip: str) -> Optional[Dict[str, Any]]:
        return self._sources.get(source_ip)

    def is_known(self, source_ip: str) -> bool:
        s = self._sources.get(source_ip)
        return bool(s and s.get("is_known"))

    def all_sources(self) -> List[Dict[str, Any]]:
        return list(self._sources.values())


# ---------------------------------------------------------------------------
# Main validator
# ---------------------------------------------------------------------------

class EventValidator:
    """
    L1 validation gate for all incoming events.

    Usage
    -----
    validator = EventValidator()
    result = validator.validate_event(raw_event, hmac_verified=True)
    if result.accepted:
        event_with_provenance = {**normalized_event, **result.provenance}
    """

    def __init__(
        self,
        replay_store: Optional[PersistentReplayStore] = None,
        source_registry: Optional[SourceIdentityRegistry] = None,
    ):
        self.replay_store = replay_store if replay_store is not None else PersistentReplayStore(_REPLAY_STORE_PATH)
        self.source_registry = source_registry if source_registry is not None else SourceIdentityRegistry()
        # Sequence tracking per source: source_ip -> highest seen sequence
        self._sequences: Dict[str, int] = {}

    def reset(self) -> None:
        """Clear all state (used in tests and /api/reset)."""
        self.replay_store.clear()
        self.source_registry._sources.clear()
        self._sequences.clear()

    def validate_event(
        self,
        raw_event: Dict[str, Any],
        *,
        hmac_verified: bool = False,
        ingest_method: str = "api",
        now_utc: Optional[datetime] = None,
    ) -> ValidationResult:
        """
        Validate a single raw event dict.

        Parameters
        ----------
        raw_event      : The raw (pre-normalisation) event dict.
        hmac_verified  : Whether the HMAC signature was verified for this batch.
        ingest_method  : "api" | "upload" | "simulator"
        now_utc        : Override current time (for testing).

        Returns
        -------
        ValidationResult with accepted=True/False plus provenance metadata.
        """
        now = now_utc or datetime.now(timezone.utc)
        warnings: List[str] = []

        # ── Schema presence check ────────────────────────────────────────────
        schema_issues = self._check_schema(raw_event)
        if schema_issues:
            return ValidationResult(
                accepted=False,
                trust_level=TrustLevel.UNTRUSTED,
                classification=TelemetryClassification.MALFORMED,
                rejection_code="MALFORMED_EVENT",
                rejection_detail=f"Schema issues: {'; '.join(schema_issues)}",
            )

        # ── Timestamp validation ─────────────────────────────────────────────
        ts_val = (
            raw_event.get("timestamp")
            or raw_event.get("time")
            or raw_event.get("datetime")
        )
        ts_status, dt_obj, ts_warning = self._validate_timestamp(ts_val, now)
        if ts_status == "INVALID":
            return ValidationResult(
                accepted=False,
                trust_level=TrustLevel.UNTRUSTED,
                classification=TelemetryClassification.UNTRUSTED,
                rejection_code="INVALID_TIMESTAMP",
                rejection_detail=f"Unparseable timestamp: {ts_val}",
            )
        if ts_status == "DRIFT":
            return ValidationResult(
                accepted=False,
                trust_level=TrustLevel.UNTRUSTED,
                classification=TelemetryClassification.UNTRUSTED,
                rejection_code="TIMESTAMP_DRIFT",
                rejection_detail=f"Timestamp outside ±{MAX_PAST_DRIFT_SEC}s window: {ts_val}",
            )
        if ts_warning:
            warnings.append(ts_warning)

        # ── Duplicate / replay check ─────────────────────────────────────────
        evt_id = str(raw_event.get("id") or raw_event.get("event_id") or "")
        if evt_id and self.replay_store.contains(evt_id):
            return ValidationResult(
                accepted=False,
                trust_level=TrustLevel.UNTRUSTED,
                classification=TelemetryClassification.DUPLICATED,
                rejection_code="DUPLICATE_EVENT",
                rejection_detail=f"Duplicate event ID '{evt_id}' — replay rejected.",
            )

        # ── Sequence-number check ────────────────────────────────────────────
        src_ip = str(
            raw_event.get("source_ip")
            or raw_event.get("ip")
            or "127.0.0.1"
        )
        seq_num = raw_event.get("sequence")
        seq_rejection = self._validate_sequence(src_ip, seq_num)
        if seq_rejection:
            return ValidationResult(
                accepted=False,
                trust_level=TrustLevel.UNTRUSTED,
                classification=TelemetryClassification.DUPLICATED,
                rejection_code="DUPLICATE_SEQUENCE",
                rejection_detail=seq_rejection,
            )

        # ── Determine trust level ────────────────────────────────────────────
        trust_level = self._determine_trust(
            hmac_verified=hmac_verified,
            source_ip=src_ip,
            has_id=bool(evt_id),
            has_schema_warnings=bool(warnings),
        )

        # ── Classify the event telemetry state ──────────────────────────────
        classification = TelemetryClassification.NORMAL
        if ts_status == "DELAYED":
            classification = TelemetryClassification.DELAYED

        # ── Build provenance record ──────────────────────────────────────────
        provenance = {
            "_trust_level": trust_level,
            "_telemetry_classification": classification,
            "_ingest_method": ingest_method,
            "_hmac_verified": hmac_verified,
            "_source_known": self.source_registry.is_known(src_ip),
            "_ingest_ts": now.isoformat(),
            "_validation_warnings": warnings,
        }

        # ── Accept the event: update replay store, sequence, source registry ─
        if evt_id:
            self.replay_store.add(evt_id)
        if seq_num is not None:
            try:
                self._sequences[src_ip] = max(
                    self._sequences.get(src_ip, -1), int(seq_num)
                )
            except (ValueError, TypeError):
                pass
        self.source_registry.record(src_ip, trust_level)

        return ValidationResult(
            accepted=True,
            trust_level=trust_level,
            classification=classification,
            provenance=provenance,
            warnings=warnings,
        )

    # ── Private helpers ──────────────────────────────────────────────────────

    def _check_schema(self, raw_event: Dict[str, Any]) -> List[str]:
        """Return a list of schema problems (empty = OK)."""
        issues = []
        # Must have at least one identifier
        has_id = any(
            raw_event.get(k) for k in ("id", "event_id")
        )
        # Must have some event type signal
        has_type = any(
            raw_event.get(k) for k in ("event_type", "type", "action", "status")
        )
        if not has_type:
            issues.append("Missing event type field (event_type / type / action)")
        return issues

    def _validate_timestamp(
        self, ts_val: Any, now: datetime
    ) -> Tuple[str, Optional[datetime], str]:
        """
        Returns ("OK"|"DELAYED"|"DRIFT"|"INVALID", dt_obj, warning_str).
        """
        if not ts_val:
            # No timestamp: warn but accept (we will assign ingest time)
            return "OK", now, "No timestamp provided — ingest time used."

        # Attempt to parse
        dt_obj: Optional[datetime] = None
        if isinstance(ts_val, (int, float)):
            try:
                dt_obj = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
            except Exception:
                return "INVALID", None, ""
        else:
            ts_str = str(ts_val).strip()
            for fmt in [
                None,  # fromisoformat
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
                "%b %d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ]:
                try:
                    if fmt is None:
                        dt_obj = datetime.fromisoformat(
                            ts_str.replace("Z", "+00:00")
                        )
                    else:
                        dt_obj = datetime.strptime(
                            ts_str[:19], fmt
                        ).replace(tzinfo=timezone.utc)
                    break
                except Exception:
                    continue
            if dt_obj is None:
                return "INVALID", None, ""

        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)

        drift = (dt_obj - now).total_seconds()

        if drift > MAX_FUTURE_DRIFT_SEC:
            return "DRIFT", dt_obj, ""
        if drift < -MAX_PAST_DRIFT_SEC:
            return "DRIFT", dt_obj, ""
        if drift < -300:
            # Old but within 24h: accept with DELAYED classification
            return "DELAYED", dt_obj, (
                f"Event timestamp is {int(-drift)}s old — classified as DELAYED."
            )
        return "OK", dt_obj, ""

    def _validate_sequence(
        self, source_ip: str, seq_num: Any
    ) -> Optional[str]:
        """Return a rejection reason string if the sequence is replayed, else None."""
        if seq_num is None:
            return None
        try:
            seq_int = int(seq_num)
        except (ValueError, TypeError):
            return None
        last_seq = self._sequences.get(source_ip)
        if last_seq is not None and seq_int <= last_seq:
            return (
                f"Replayed or out-of-order sequence {seq_int} for source "
                f"'{source_ip}' (last accepted: {last_seq})."
            )
        return None

    def _determine_trust(
        self,
        *,
        hmac_verified: bool,
        source_ip: str,
        has_id: bool,
        has_schema_warnings: bool,
    ) -> str:
        if hmac_verified and has_id and self.source_registry.is_known(source_ip):
            return TrustLevel.TRUSTED
        if hmac_verified or has_id:
            return TrustLevel.STANDARD
        if has_schema_warnings:
            return TrustLevel.LOW
        return TrustLevel.STANDARD


# ---------------------------------------------------------------------------
# Module-level singleton (used by main.py)
# ---------------------------------------------------------------------------

_default_validator: Optional[EventValidator] = None


def get_default_validator() -> EventValidator:
    global _default_validator
    if _default_validator is None:
        _default_validator = EventValidator()
    return _default_validator
