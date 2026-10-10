"""
Reproducible Scenario Runner
=============================
Generates synthetic, labeled event datasets for evaluation.

Eight scenario types (per Phase 3 requirements):
1. normal          — Normal business activity across the day
2. brute_force     — Repeated login failures followed by successful authentication
3. privilege_escalation — Privilege escalation and sensitive-resource access
4. gradual_drift   — Legitimate gradual behavioral change (early → late shift)
5. baseline_poison — Suspicious gradual behavioral manipulation
6. incomplete_telemetry — Missing, delayed, and duplicated events
7. conflicting_evidence — Evidence that supports both attack and benign interpretations
8. novel_sequence  — Previously unseen event type sequence
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

_BASE_TIME = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)


def _evt(
    user: str,
    source_ip: str,
    event_type: str,
    resource: str,
    details: str,
    hour_offset: float = 0.0,
    label_attack: bool = False,
    label_type: str = "normal",
) -> Dict[str, Any]:
    ts = _BASE_TIME + timedelta(hours=hour_offset)
    return {
        "id": f"evt-{uuid.uuid4().hex[:8]}",
        "timestamp": ts.isoformat(),
        "hour": ts.hour,
        "user": user,
        "source_ip": source_ip,
        "event_type": event_type,
        "resource": resource,
        "details": details,
        # Ground-truth labels (stripped before writing to log file)
        "_label_attack": label_attack,
        "_label_type": label_type,
    }


class ScenarioRunner:
    """Generates reproducible synthetic event datasets for each scenario."""

    SCENARIOS = {
        "normal": "One day of normal business activity (no attacks)",
        "brute_force": "Brute-force attack: repeated login failures then success",
        "privilege_escalation": "Privilege escalation followed by sensitive-resource access",
        "data_exfil": "Full account-takeover + data exfiltration chain",
        "gradual_drift": "Legitimate behavioral drift (user switches to night shifts)",
        "baseline_poison": "Slow baseline poisoning: attacker gradually shifts login hours",
        "incomplete_telemetry": "Missing, delayed, and duplicated telemetry events",
        "conflicting_evidence": "Conflicting evidence: suspicious sequence with benign explanation",
        "novel_sequence": "Previously unseen event sequence",
    }

    def run(self, scenario_name: str) -> Dict[str, Any]:
        fn = getattr(self, f"_scenario_{scenario_name}", None)
        if fn is None:
            return {
                "error": f"Unknown scenario '{scenario_name}'. "
                f"Valid: {', '.join(self.SCENARIOS.keys())}"
            }
        events, labels = fn()
        # Strip private labels from events before returning
        clean_events = []
        for e in events:
            clean = {k: v for k, v in e.items() if not k.startswith("_")}
            clean_events.append(clean)
        return {
            "description": self.SCENARIOS.get(scenario_name, ""),
            "events": clean_events,
            "labels": labels,
            "ground_truth": [
                {"event_id": e["id"], "label_attack": e.get("_label_attack", False),
                 "label_type": e.get("_label_type", "normal")}
                for e in events
            ],
        }

    # ── Scenario implementations ──────────────────────────────────────────────

    def _scenario_normal(self):
        """50 normal logins and file accesses across a workday."""
        events = []
        users = [f"user_{i}" for i in range(1, 6)]
        ips = [f"192.168.1.{10 + i}" for i in range(5)]
        for i in range(50):
            u = users[i % 5]
            ip = ips[i % 5]
            events.append(_evt(
                u, ip, "login_success", "/auth/login",
                f"Standard login by {u}", hour_offset=i * 0.2,
                label_attack=False, label_type="normal"
            ))
            events.append(_evt(
                u, ip, "file_access", f"/docs/report_{i % 10}.pdf",
                "Document access", hour_offset=i * 0.2 + 0.1,
                label_attack=False, label_type="normal"
            ))
        labels = {"attack_events": 0, "benign_events": len(events)}
        return events, labels

    def _scenario_brute_force(self):
        """Brute-force scenario: 5 failed logins then success."""
        events = []
        # 30 normal logins as background
        for i in range(30):
            events.append(_evt(
                f"user_{i % 5 + 1}", f"192.168.1.{10 + i % 5}",
                "login_success", "/auth/login", "Normal login",
                hour_offset=8 + i * 0.1, label_attack=False
            ))
        # Attack: brute force admin
        for i in range(5):
            events.append(_evt(
                "admin", "203.0.113.88", "login_failed", "/portal/login",
                f"Bad credentials attempt {i + 1}",
                hour_offset=2 + i * 0.05, label_attack=True, label_type="brute_force"
            ))
        events.append(_evt(
            "admin", "203.0.113.88", "login_success", "/portal/login",
            "Brute-force success after 5 failures",
            hour_offset=2.3, label_attack=True, label_type="brute_force"
        ))
        attack_ids = [e["id"] for e in events if e.get("_label_attack")]
        labels = {"attack_events": len(attack_ids), "benign_events": len(events) - len(attack_ids),
                  "attack_event_ids": attack_ids}
        return events, labels

    def _scenario_privilege_escalation(self):
        """Privilege escalation chain."""
        events = []
        for i in range(20):
            events.append(_evt(
                f"user_{i % 4 + 1}", f"192.168.1.{10 + i % 4}",
                "login_success", "/auth/login", "Normal",
                hour_offset=9 + i * 0.2, label_attack=False
            ))
        # Attack chain
        atk = [
            _evt("dev_user", "10.0.4.12", "login_success", "/dev/login",
                 "Dev session start", hour_offset=14, label_attack=True, label_type="privesc"),
            _evt("dev_user", "10.0.4.12", "unusual_request", "/api/internal/sudo_check",
                 "Internal priv boundary probe", hour_offset=14.1, label_attack=True, label_type="privesc"),
            _evt("dev_user", "10.0.4.12", "privilege_change", "/system/group/wheel",
                 "Added to wheel group", hour_offset=14.2, label_attack=True, label_type="privesc"),
            _evt("dev_user", "10.0.4.12", "sensitive_resource_access", "/etc/shadow",
                 "Shadow file read", hour_offset=14.3, label_attack=True, label_type="privesc"),
        ]
        events.extend(atk)
        attack_ids = [e["id"] for e in events if e.get("_label_attack")]
        labels = {"attack_events": len(attack_ids), "benign_events": len(events) - len(attack_ids),
                  "attack_event_ids": attack_ids}
        return events, labels

    def _scenario_data_exfil(self):
        """Full account-takeover + data exfiltration chain."""
        events = []
        for i in range(40):
            events.append(_evt(
                f"user_{i % 5 + 1}", f"192.168.1.{10 + i % 5}",
                "login_success", "/auth/login", "Normal",
                hour_offset=9 + i * 0.15, label_attack=False
            ))
        user = "admin"
        ip = "203.0.113.88"
        atk = [
            _evt(user, ip, "login_failed", "/portal/login", "Fail 1", 2.0, True, "takeover"),
            _evt(user, ip, "login_failed", "/portal/login", "Fail 2", 2.05, True, "takeover"),
            _evt(user, ip, "login_failed", "/portal/login", "Fail 3", 2.1, True, "takeover"),
            _evt(user, ip, "login_success", "/portal/login", "Brute-force success", 2.15, True, "takeover"),
            _evt(user, ip, "privilege_change", "/admin/roles/grant_super_admin",
                 "Elevated to super admin", 2.2, True, "takeover"),
            _evt(user, ip, "sensitive_resource_access", "/vault/customer_ssn_db",
                 "Accessed customer SSN DB", 2.25, True, "takeover"),
            _evt(user, ip, "data_transfer", "/export/bulk_dl",
                 "Bulk export of 10,000 records", 2.3, True, "takeover"),
        ]
        events.extend(atk)
        attack_ids = [e["id"] for e in events if e.get("_label_attack")]
        labels = {"attack_events": len(attack_ids), "benign_events": len(events) - len(attack_ids),
                  "attack_event_ids": attack_ids}
        return events, labels

    def _scenario_gradual_drift(self):
        """
        Legitimate behavioral drift: user transitions from day (9:00) to night
        shift (22:00) over 20 events. This should NOT trigger an attack alert —
        it tests the system's ability to eventually learn legitimate changes.
        """
        events = []
        user = "night_shift_worker"
        ip = "192.168.1.200"
        # First 10 events: morning hours (9-10)
        for i in range(10):
            h = 9 + (i % 2)
            ts = _BASE_TIME + timedelta(days=i, hours=h)
            events.append({
                "id": f"evt-drift-{uuid.uuid4().hex[:8]}",
                "timestamp": ts.isoformat(),
                "hour": h,
                "user": user,
                "source_ip": ip,
                "event_type": "login_success",
                "resource": "/auth/login",
                "details": f"Day shift login day {i}",
                "_label_attack": False,
                "_label_type": "legitimate_drift",
            })
        # Next 10 events: gradually shifting to night (20-22)
        for i in range(10):
            h = min(22, 10 + i)
            ts = _BASE_TIME + timedelta(days=10 + i, hours=h)
            events.append({
                "id": f"evt-drift-late-{uuid.uuid4().hex[:8]}",
                "timestamp": ts.isoformat(),
                "hour": h,
                "user": user,
                "source_ip": ip,
                "event_type": "login_success",
                "resource": "/auth/login",
                "details": f"Shift transition login day {10 + i}",
                "_label_attack": False,
                "_label_type": "legitimate_drift",
            })
        labels = {"attack_events": 0, "benign_events": len(events),
                  "note": "Legitimate behavioral drift — should not generate high-confidence attack alert"}
        return events, labels

    def _scenario_baseline_poison(self):
        """
        Suspicious gradual manipulation: attacker tries to shift the baseline
        by inserting 3am logins gradually, then exploiting the poisoned baseline.
        """
        events = []
        user = "victim_user"
        attacker_ip = "203.0.113.99"
        normal_ip = "192.168.1.50"
        # 10 legitimate morning logins (establishes baseline)
        for i in range(10):
            events.append(_evt(
                user, normal_ip, "login_success", "/auth/login",
                f"Normal morning login {i}", hour_offset=9 + i * 0.1,
                label_attack=False, label_type="normal"
            ))
        # Attacker inserts gradual 3am logins with stolen credentials
        for i in range(8):
            h = 3 + i * 0.1
            events.append(_evt(
                user, attacker_ip, "login_failed" if i < 3 else "login_success",
                "/auth/login", f"Off-hours attempt {i}",
                hour_offset=24 * (i + 1) + 3, label_attack=True, label_type="poison_attempt"
            ))
        # Final exploit after "baseline poisoning"
        events.append(_evt(
            user, attacker_ip, "sensitive_resource_access", "/vault/payroll",
            "Access payroll DB at 3am", hour_offset=24 * 10 + 3.5,
            label_attack=True, label_type="poison_exploit"
        ))
        attack_ids = [e["id"] for e in events if e.get("_label_attack")]
        labels = {"attack_events": len(attack_ids), "benign_events": len(events) - len(attack_ids),
                  "attack_event_ids": attack_ids,
                  "note": "Tests baseline-poisoning detection via Page-Hinkley"}
        return events, labels

    def _scenario_incomplete_telemetry(self):
        """Missing, delayed, and duplicated telemetry events."""
        events = []
        user = "sensor_target"
        ip = "10.1.1.100"
        # Some normal events
        for i in range(5):
            events.append(_evt(
                user, ip, "login_success", "/auth/login",
                f"Normal event {i}", hour_offset=i,
                label_attack=False, label_type="normal"
            ))
        # A duplicated event (same content, new ID — simulates log duplication)
        events.append({
            **events[0],
            "id": f"evt-dup-{uuid.uuid4().hex[:8]}",
            "_label_attack": False,
            "_label_type": "duplicated",
            "details": "DUPLICATED: same session as above",
        })
        # A delayed event (timestamp 25h in the past — will be rejected by drift check)
        # We include it in the ground truth but note it will be rejected
        old_ts = _BASE_TIME - timedelta(hours=25)
        events.append({
            "id": f"evt-delayed-{uuid.uuid4().hex[:8]}",
            "timestamp": old_ts.isoformat(),
            "hour": old_ts.hour,
            "user": user,
            "source_ip": ip,
            "event_type": "login_success",
            "resource": "/auth/login",
            "details": "DELAYED: timestamp 25h in the past — should be rejected",
            "_label_attack": False,
            "_label_type": "delayed_rejected",
        })
        labels = {
            "attack_events": 0,
            "benign_events": len(events),
            "note": "Delayed event (25h old) will be rejected by timestamp validation.",
            "telemetry_issues": ["duplicated", "delayed_rejected"],
        }
        return events, labels

    def _scenario_conflicting_evidence(self):
        """
        An ambiguous sequence: IT admin doing legitimate privilege escalation
        from an unusual IP. High rule score but benign explanation.
        """
        events = []
        user = "it_admin"
        new_ip = "172.16.5.99"   # New IP for this admin (remote work)
        # The sequence looks suspicious but is explained
        events.extend([
            _evt(user, new_ip, "login_success", "/admin/login",
                 "IT admin logged in from home", hour_offset=22.5, label_attack=False,
                 label_type="conflicting"),
            _evt(user, new_ip, "privilege_change", "/admin/roles/grant_admin",
                 "Authorized admin role grant for new hire", hour_offset=22.6,
                 label_attack=False, label_type="conflicting"),
            _evt(user, new_ip, "sensitive_resource_access", "/hr/personnel_records",
                 "Authorized HR record review", hour_offset=22.7,
                 label_attack=False, label_type="conflicting"),
        ])
        labels = {
            "attack_events": 0,
            "benign_events": len(events),
            "note": "High rule score expected, but all events are authorized. "
                    "Tests false positive rate with conflicting evidence.",
        }
        return events, labels

    def _scenario_novel_sequence(self):
        """
        An event sequence not previously seen: data_transfer → privilege_change
        (reverse of the expected order, unusual but possible attack variant).
        """
        events = []
        user = "novel_attacker"
        ip = "198.51.100.200"
        events.extend([
            _evt(user, ip, "login_success", "/auth/login",
                 "Login from new source", hour_offset=1.0, label_attack=True, label_type="novel"),
            _evt(user, ip, "data_transfer", "/export/raw_logs",
                 "Exported raw security logs", hour_offset=1.1, label_attack=True, label_type="novel"),
            _evt(user, ip, "privilege_change", "/admin/security_config",
                 "Modified security configuration post-export", hour_offset=1.2,
                 label_attack=True, label_type="novel"),
            _evt(user, ip, "unusual_request", "/api/cover_tracks",
                 "API call to disable audit logging", hour_offset=1.3,
                 label_attack=True, label_type="novel"),
        ])
        attack_ids = [e["id"] for e in events if e.get("_label_attack")]
        labels = {"attack_events": len(attack_ids), "benign_events": 0,
                  "attack_event_ids": attack_ids,
                  "note": "Novel sequence: data_transfer → privilege_change — not in standard patterns"}
        return events, labels
