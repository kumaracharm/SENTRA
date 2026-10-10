"""
L2 — Adaptive and Poisoning-Resistant Detection
================================================
AdaptiveBaselineTracker: per-entity behavioral baselines with:

  1. Page-Hinkley change-point detection (PHDetector)
     – Detects upward shifts in a stream of real-valued observations.
     – Reference: Page (1954) "Continuous Inspection Schemes", Biometrika 41(1-2).
     – Parameters λ (delta) and threshold θ are configurable per metric.
     – Limitation: detects mean increases only; separate instance needed for
       decreases. We use two detectors (upper/lower) per metric.

  2. Trust-gated baseline adaptation
     – Baseline statistics are updated only when the entity's current
       trust level is TRUSTED or STANDARD *and* no change-point has been
       detected in the last `freeze_window_events` events.
     – This prevents an attacker from slowly drifting the baseline by
       introducing low-trust events.

  3. Persistent storage (data/baselines.json)
     – Baselines survive server restarts.
     – JSON format for auditability (not a binary pickle).

  4. Poisoning detection
     – If Page-Hinkley fires on a slow-moving metric (e.g. login_hour),
       the incident is flagged as SUSPECTED_BASELINE_POISONING.
     – The flag is included in every analysis result for dashboard display.

  5. Calibrated anomaly score
     – Z-score relative to the entity's own historical distribution.
     – Falls back to global distribution for cold-start entities.
     – Returns a value in [0, 100] with explicit reasoning.

Design note
-----------
The existing EntityBaselineTracker (baseline.py) is preserved intact to
maintain backward-compatibility with test_baseline.py and evaluate.py.
This module is a *new* layer that main.py will call in the upgraded
/api/analyze/v2 path.
"""

from __future__ import annotations

import json
import math
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Page-Hinkley Change-Point Detector
# ---------------------------------------------------------------------------

class PHDetector:
    """
    Page-Hinkley test for detecting an upward (or downward) shift in the
    mean of an online sequence of observations.

    Reference: Page, E. S. (1954). Continuous inspection schemes.
               Biometrika, 41(1-2), 100-115.

    Parameters
    ----------
    delta : float
        Minimum magnitude of change to detect (tolerance).
        Smaller → more sensitive, more false positives.
    threshold : float
        Detection threshold θ. Alarm when PH statistic > θ.
        Larger → fewer false positives, larger detection delay.
    alpha : float
        Running-mean forgetting factor (1.0 = no forgetting).
    direction : "up" | "down"
        Which shift direction to detect.

    Limitations
    -----------
    * Detects changes in the mean only, not variance.
    * Requires reasonable stationarity during normal operation.
    * Threshold must be tuned per metric; defaults here are conservative.
    """

    def __init__(
        self,
        delta: float = 0.5,
        threshold: float = 5.0,
        alpha: float = 1.0,
        direction: str = "up",
    ):
        self.delta = delta
        self.threshold = threshold
        self.alpha = alpha
        self.direction = direction
        self._cumulative: float = 0.0
        self._running_mean: float = 0.0
        self._n: int = 0
        self._alarm_count: int = 0

    def update(self, value: float) -> bool:
        """
        Feed one observation. Returns True if a change-point is detected.
        """
        self._n += 1
        # Update running mean (exponential moving average when alpha < 1)
        if self._n == 1:
            self._running_mean = value
        else:
            self._running_mean = (
                self.alpha * self._running_mean + (1 - self.alpha) * value
                if self.alpha < 1.0
                else self._running_mean + (value - self._running_mean) / self._n
            )

        # PH statistic for upward shift
        if self.direction == "up":
            increment = value - self._running_mean - self.delta
        else:
            increment = self._running_mean - value - self.delta

        self._cumulative = max(0.0, self._cumulative + increment)

        if self._cumulative > self.threshold:
            self._alarm_count += 1
            self._cumulative = 0.0  # Reset after alarm
            return True
        return False

    def reset(self) -> None:
        self._cumulative = 0.0
        self._running_mean = 0.0
        self._n = 0
        self._alarm_count = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delta": self.delta,
            "threshold": self.threshold,
            "direction": self.direction,
            "cumulative": round(self._cumulative, 4),
            "running_mean": round(self._running_mean, 4),
            "n": self._n,
            "alarm_count": self._alarm_count,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PHDetector":
        obj = cls(
            delta=d.get("delta", 0.5),
            threshold=d.get("threshold", 5.0),
            direction=d.get("direction", "up"),
        )
        obj._cumulative = d.get("cumulative", 0.0)
        obj._running_mean = d.get("running_mean", 0.0)
        obj._n = d.get("n", 0)
        obj._alarm_count = d.get("alarm_count", 0)
        return obj


# ---------------------------------------------------------------------------
# Per-entity behavioral profile
# ---------------------------------------------------------------------------

class EntityProfile:
    """
    Tracks per-entity behavioral statistics and drift detectors.

    Metrics tracked
    ---------------
    * login_hours : list of hour-of-day values
    * source_ips  : set of known source IPs
    * failure_rate_window : rolling window of 0/1 (0 = success, 1 = failure)
    * event_rate_window : events-per-hour (approximated from timestamps)
    """

    _FREEZE_WINDOW = 10   # Freeze baseline updates for N events after alarm
    _MIN_HISTORY = 5      # Minimum observations before entity-specific z-score

    def __init__(self, entity_id: str):
        self.entity_id = entity_id
        self.login_hours: List[int] = []
        self.source_ips: set[str] = set()
        self.failure_window: List[int] = []   # 0 or 1
        self.event_timestamps: List[str] = []  # ISO strings

        # Page-Hinkley detectors (one per measurable metric)
        self.ph_hour_up = PHDetector(delta=1.0, threshold=6.0, direction="up")
        self.ph_hour_down = PHDetector(delta=1.0, threshold=6.0, direction="down")
        self.ph_fail_rate = PHDetector(delta=0.05, threshold=4.0, direction="up")

        # Freeze counter: >0 means updates are paused
        self._freeze_counter: int = 0
        self.drift_alarms: List[Dict[str, Any]] = []  # History of PH alarms
        self.suspected_poisoning: bool = False

    # ── Baseline update (trust-gated) ────────────────────────────────────────

    def update(
        self,
        event: Dict[str, Any],
        trust_level: str,
        is_suspicious: bool = False,
    ) -> Optional[str]:
        """
        Update the entity profile with one new event.

        Returns a string alarm reason if drift was detected, else None.
        Gates updates on trust level and freeze state.
        """
        from backend.telemetry_validator import TrustLevel  # avoid circular

        # Decay freeze counter
        if self._freeze_counter > 0:
            self._freeze_counter -= 1

        # Gate: do not update baseline from low-trust or suspicious events
        trusted = trust_level in (TrustLevel.TRUSTED, TrustLevel.STANDARD)
        if not trusted or is_suspicious or self._freeze_counter > 0:
            return None

        hour = int(event.get("hour", 12))
        ip = str(event.get("source_ip", "0.0.0.0"))
        etype = str(event.get("event_type", ""))
        ts = str(event.get("timestamp", ""))

        # Run Page-Hinkley BEFORE updating history
        alarm_reason: Optional[str] = None

        if len(self.login_hours) >= self._MIN_HISTORY:
            fired_up = self.ph_hour_up.update(float(hour))
            fired_down = self.ph_hour_down.update(float(hour))
            if fired_up or fired_down:
                direction = "upward" if fired_up else "downward"
                alarm_reason = (
                    f"Page-Hinkley detected {direction} shift in login hours "
                    f"for entity '{self.entity_id}' (current: {hour}h, "
                    f"baseline mean: {self.ph_hour_up._running_mean:.1f}h)"
                )
                self.drift_alarms.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "metric": "login_hour",
                    "direction": direction,
                    "value": hour,
                    "alarm_reason": alarm_reason,
                })
                self._freeze_counter = self._FREEZE_WINDOW
                # Flag as suspected poisoning if drift is slow (alarm on hour)
                self.suspected_poisoning = True

        # Update failure rate PH
        is_failure = 1 if etype == "login_failed" else 0
        self.failure_window.append(is_failure)
        if len(self.failure_window) > 20:
            self.failure_window = self.failure_window[-20:]
        if len(self.failure_window) >= 5:
            current_rate = sum(self.failure_window) / len(self.failure_window)
            fired_fail = self.ph_fail_rate.update(current_rate)
            if fired_fail:
                fail_alarm = (
                    f"Page-Hinkley detected increase in failure rate "
                    f"for entity '{self.entity_id}' "
                    f"(window rate: {current_rate:.1%})"
                )
                self.drift_alarms.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "metric": "failure_rate",
                    "direction": "up",
                    "value": current_rate,
                    "alarm_reason": fail_alarm,
                })
                self._freeze_counter = self._FREEZE_WINDOW
                alarm_reason = alarm_reason or fail_alarm

        # Commit updates to history ONLY if no alarm (don't freeze on alarm)
        if alarm_reason is None:
            self.login_hours.append(hour)
            self.source_ips.add(ip)
            if ts:
                self.event_timestamps.append(ts)
                if len(self.event_timestamps) > 200:
                    self.event_timestamps = self.event_timestamps[-200:]
        else:
            # Do not accept this event into the baseline
            pass

        return alarm_reason

    # ── Anomaly scoring ──────────────────────────────────────────────────────

    def score_event(
        self,
        event: Dict[str, Any],
        global_profile: Optional["GlobalProfile"] = None,
    ) -> Tuple[float, List[str]]:
        """
        Return (anomaly_score [0..100], list_of_reasons).

        Score is a z-score based composite clamped to [0, 100].
        Falls back to the global profile for cold-start entities.
        """
        hour = int(event.get("hour", 12))
        ip = str(event.get("source_ip", "0.0.0.0"))
        etype = str(event.get("event_type", ""))
        reasons: List[str] = []
        score = 0.0

        has_history = len(self.login_hours) >= self._MIN_HISTORY

        if has_history:
            # Hour z-score
            mean_h = statistics.mean(self.login_hours)
            std_h = statistics.pstdev(self.login_hours) or 1.0
            z_hour = abs(hour - mean_h) / std_h
            if z_hour > 2.0:
                contribution = min(40.0, z_hour * 10)
                score += contribution
                reasons.append(
                    f"Login hour {hour}:00 deviates {z_hour:.1f}σ from "
                    f"baseline (mean {mean_h:.1f}h, σ {std_h:.1f}h)"
                )

            # Unknown IP
            if ip not in self.source_ips and len(self.source_ips) > 0:
                score += 25.0
                known_ips_preview = list(self.source_ips)[:3]
                reasons.append(
                    f"Source IP {ip} not in entity's known set "
                    f"{known_ips_preview}{'...' if len(self.source_ips) > 3 else ''}"
                )

            # Elevated failure rate
            if etype == "login_failed" and len(self.failure_window) >= 5:
                rate = sum(self.failure_window) / len(self.failure_window)
                if rate > 0.5:
                    contribution = min(35.0, rate * 40)
                    score += contribution
                    reasons.append(
                        f"Entity failure rate {rate:.1%} exceeds threshold "
                        "(window: last 20 auth events)"
                    )

        elif global_profile is not None:
            # Cold-start: compare against global distribution
            score, reasons = global_profile.score_event_global(event)
            reasons = [f"[Cold-start, global fallback] {r}" for r in reasons]
        else:
            # No data at all
            if etype in ("privilege_change", "sensitive_resource_access"):
                score = 20.0
                reasons.append(
                    f"High-risk event type '{etype}' on cold-start profile"
                )

        # Drift alarm bonus
        if self.suspected_poisoning:
            score = min(100.0, score + 15.0)
            reasons.append(
                "Page-Hinkley drift alarm previously fired — "
                "suspected baseline manipulation"
            )

        return round(min(100.0, max(0.0, score)), 1), reasons

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "login_hours": self.login_hours,
            "source_ips": list(self.source_ips),
            "failure_window": self.failure_window,
            "event_timestamps": self.event_timestamps,
            "ph_hour_up": self.ph_hour_up.to_dict(),
            "ph_hour_down": self.ph_hour_down.to_dict(),
            "ph_fail_rate": self.ph_fail_rate.to_dict(),
            "freeze_counter": self._freeze_counter,
            "drift_alarms": self.drift_alarms[-20:],  # Keep last 20
            "suspected_poisoning": self.suspected_poisoning,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EntityProfile":
        obj = cls(d["entity_id"])
        obj.login_hours = d.get("login_hours", [])
        obj.source_ips = set(d.get("source_ips", []))
        obj.failure_window = d.get("failure_window", [])
        obj.event_timestamps = d.get("event_timestamps", [])
        if "ph_hour_up" in d:
            obj.ph_hour_up = PHDetector.from_dict(d["ph_hour_up"])
        if "ph_hour_down" in d:
            obj.ph_hour_down = PHDetector.from_dict(d["ph_hour_down"])
        if "ph_fail_rate" in d:
            obj.ph_fail_rate = PHDetector.from_dict(d["ph_fail_rate"])
        obj._freeze_counter = d.get("freeze_counter", 0)
        obj.drift_alarms = d.get("drift_alarms", [])
        obj.suspected_poisoning = d.get("suspected_poisoning", False)
        return obj


# ---------------------------------------------------------------------------
# Global profile for cold-start fallback
# ---------------------------------------------------------------------------

class GlobalProfile:
    """Running global statistics across all entities for cold-start fallback."""

    def __init__(self):
        self.all_hours: List[int] = []
        self.global_failure_window: List[int] = []

    def update(self, event: Dict[str, Any]) -> None:
        hour = int(event.get("hour", 12))
        etype = str(event.get("event_type", ""))
        self.all_hours.append(hour)
        if len(self.all_hours) > 1000:
            self.all_hours = self.all_hours[-1000:]
        is_failure = 1 if etype == "login_failed" else 0
        self.global_failure_window.append(is_failure)
        if len(self.global_failure_window) > 500:
            self.global_failure_window = self.global_failure_window[-500:]

    def score_event_global(
        self, event: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        hour = int(event.get("hour", 12))
        reasons: List[str] = []
        score = 0.0
        if len(self.all_hours) >= 10:
            mean_h = statistics.mean(self.all_hours)
            std_h = statistics.pstdev(self.all_hours) or 2.0
            z = abs(hour - mean_h) / std_h
            if z > 2.0:
                score += min(30.0, z * 8)
                reasons.append(
                    f"Login hour {hour}:00 deviates {z:.1f}σ from global mean "
                    f"({mean_h:.1f}h)"
                )
        return round(score, 1), reasons

    def to_dict(self) -> Dict[str, Any]:
        return {
            "all_hours": self.all_hours,
            "global_failure_window": self.global_failure_window,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GlobalProfile":
        obj = cls()
        obj.all_hours = d.get("all_hours", [])
        obj.global_failure_window = d.get("global_failure_window", [])
        return obj


# ---------------------------------------------------------------------------
# Main adaptive tracker
# ---------------------------------------------------------------------------

_BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "baselines.json"


class AdaptiveBaselineTracker:
    """
    L2 adaptive baseline tracker with Page-Hinkley drift detection,
    trust-gated updates, persistent storage, and poisoning detection.

    This replaces the stateless EntityBaselineTracker for the upgraded
    analysis path, while preserving backward compatibility.
    """

    def __init__(self, storage_path: Optional[Any] = None):
        if storage_path is False or storage_path == ":memory:":
            self._path = None
        else:
            self._path = storage_path or _BASELINE_PATH
        self.entities: Dict[str, EntityProfile] = {}
        self.global_profile = GlobalProfile()
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._path is None:
            return
        try:
            if self._path.exists():
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for eid, edata in data.get("entities", {}).items():
                    self.entities[eid] = EntityProfile.from_dict(edata)
                if "global" in data:
                    self.global_profile = GlobalProfile.from_dict(data["global"])
        except Exception:
            self.entities = {}
            self.global_profile = GlobalProfile()

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "entities": {
                    eid: ep.to_dict() for eid, ep in self.entities.items()
                },
                "global": self.global_profile.to_dict(),
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def reset(self) -> None:
        self.entities.clear()
        self.global_profile = GlobalProfile()
        self._save()

    # ── Public API ───────────────────────────────────────────────────────────

    def process_event(
        self,
        event: Dict[str, Any],
        trust_level: str = "STANDARD",
        is_suspicious: bool = False,
    ) -> Dict[str, Any]:
        """
        Process one event:
        1. Score it against the current baseline.
        2. Update the baseline (trust-gated).
        3. Return analysis result dict.
        """
        user = str(event.get("user", "unknown"))
        if user not in self.entities:
            self.entities[user] = EntityProfile(user)

        profile = self.entities[user]

        # Score BEFORE updating
        anomaly_score, reasons = profile.score_event(event, self.global_profile)

        # Update (trust-gated)
        drift_alarm = profile.update(
            event,
            trust_level=trust_level,
            is_suspicious=is_suspicious or anomaly_score >= 50.0,
        )

        # Update global profile unconditionally
        self.global_profile.update(event)

        # Determine if baseline is frozen
        is_frozen = profile._freeze_counter > 0

        result = {
            "event_id": event.get("id", ""),
            "user": user,
            "anomaly_score": anomaly_score,
            "reasons": reasons,
            "drift_alarm": drift_alarm,
            "suspected_poisoning": profile.suspected_poisoning,
            "baseline_frozen": is_frozen,
            "freeze_reason": (
                "Baseline frozen: drift alarm or suspicious activity detected"
                if is_frozen else None
            ),
            "history_count": len(profile.login_hours),
            "trust_level": trust_level,
        }

        # Persist after each event (can be optimised with batching if needed)
        self._save()

        return result

    def evaluate_events(
        self,
        events: List[Dict[str, Any]],
        trust_levels: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Process a batch of events in chronological order.
        Returns only events with anomaly_score > 0 or drift alarms.
        """
        sorted_events = sorted(
            events, key=lambda x: str(x.get("timestamp", ""))
        )
        if trust_levels is None:
            trust_levels = {}

        results = []
        for evt in sorted_events:
            evt_id = str(evt.get("id", ""))
            tl = trust_levels.get(evt_id, "STANDARD")
            res = self.process_event(evt, trust_level=tl)
            if res["anomaly_score"] > 0 or res["drift_alarm"]:
                results.append(res)

        return results

    def get_entity_status(self) -> List[Dict[str, Any]]:
        """Return current baseline status for all tracked entities."""
        out = []
        for eid, profile in self.entities.items():
            out.append({
                "entity_id": eid,
                "history_count": len(profile.login_hours),
                "known_ips": list(profile.source_ips),
                "drift_alarms": len(profile.drift_alarms),
                "suspected_poisoning": profile.suspected_poisoning,
                "baseline_frozen": profile._freeze_counter > 0,
                "recent_alarms": profile.drift_alarms[-3:],
            })
        return out


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_tracker: Optional[AdaptiveBaselineTracker] = None


def get_default_tracker() -> AdaptiveBaselineTracker:
    global _default_tracker
    if _default_tracker is None:
        _default_tracker = AdaptiveBaselineTracker()
    return _default_tracker
