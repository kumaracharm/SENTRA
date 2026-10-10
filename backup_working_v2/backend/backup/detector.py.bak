import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from typing import List, Dict, Any

class RuleEngine:
    """Rule-based Intrusion Detection Engine."""

    def __init__(self):
        pass

    def evaluate_rules(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate security rules on normalized log events.
        Returns a list of matched rule objects containing score contribution, target, and evidence.
        """
        matched_rules = []
        if not events:
            return matched_rules

        # Sort events by timestamp if possible
        sorted_events = sorted(events, key=lambda x: str(x.get("timestamp", "")))

        # Group events by user and source_ip for pattern checks
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        by_ip: Dict[str, List[Dict[str, Any]]] = {}

        for evt in sorted_events:
            u = evt.get("user", "unknown")
            ip = evt.get("source_ip", "0.0.0.0")
            by_user.setdefault(u, []).append(evt)
            by_ip.setdefault(ip, []).append(evt)

        # Rule 1: Repeated Failed Logins (Brute Force Signal)
        for user, u_events in by_user.items():
            failed = [e for e in u_events if e.get("event_type") == "login_failed"]
            if len(failed) >= 3:
                matched_rules.append({
                    "rule_id": "R001",
                    "rule_name": "Repeated Failed Logins",
                    "description": f"User '{user}' accumulated {len(failed)} failed login attempts.",
                    "target_user": user,
                    "target_ip": failed[0].get("source_ip", "0.0.0.0"),
                    "matched_event_ids": [e["id"] for e in failed],
                    "score_contribution": 25,
                    "evidence": f"{len(failed)} failed login attempts detected for account '{user}'"
                })

        # Rule 2: Failed Logins Followed by Success (Credential Stuffing / Brute Force Success)
        for user, u_events in by_user.items():
            has_failed = False
            failed_ids = []
            for evt in u_events:
                etype = evt.get("event_type")
                if etype == "login_failed":
                    has_failed = True
                    failed_ids.append(evt["id"])
                elif etype == "login_success" and has_failed:
                    matched_rules.append({
                        "rule_id": "R002",
                        "rule_name": "Failed Logins Followed by Success",
                        "description": f"User '{user}' successfully logged in after previous failed authentication attempts.",
                        "target_user": user,
                        "target_ip": evt.get("source_ip", "0.0.0.0"),
                        "matched_event_ids": failed_ids + [evt["id"]],
                        "score_contribution": 30,
                        "evidence": f"Successful authentication by '{user}' immediately following {len(failed_ids)} failed attempts"
                    })
                    break  # Flag once per user flow

        # Rule 3: Privilege Change After Suspicious Activity
        for user, u_events in by_user.items():
            suspicious_prior = False
            prior_ids = []
            for evt in u_events:
                etype = evt.get("event_type")
                if etype in ("login_failed", "unusual_request"):
                    suspicious_prior = True
                    prior_ids.append(evt["id"])
                elif etype == "privilege_change" and suspicious_prior:
                    matched_rules.append({
                        "rule_id": "R003",
                        "rule_name": "Privilege Change After Suspicious Login",
                        "description": f"User '{user}' executed a privilege escalation following suspicious activity.",
                        "target_user": user,
                        "target_ip": evt.get("source_ip", "0.0.0.0"),
                        "matched_event_ids": prior_ids + [evt["id"]],
                        "score_contribution": 35,
                        "evidence": f"Privilege change to resource '{evt.get('resource', '/')}' post suspicious activity"
                    })
                    break

        # Rule 4: Sensitive Access After Suspicious / Privilege Escalation Activity
        for user, u_events in by_user.items():
            priv_or_susp = False
            trigger_ids = []
            for evt in u_events:
                etype = evt.get("event_type")
                if etype in ("privilege_change", "login_failed", "unusual_request"):
                    priv_or_susp = True
                    trigger_ids.append(evt["id"])
                elif etype == "sensitive_resource_access" and priv_or_susp:
                    matched_rules.append({
                        "rule_id": "R004",
                        "rule_name": "Sensitive Access After Suspicious Activity",
                        "description": f"User '{user}' accessed sensitive resource '{evt.get('resource')}' following elevated or suspicious events.",
                        "target_user": user,
                        "target_ip": evt.get("source_ip", "0.0.0.0"),
                        "matched_event_ids": trigger_ids + [evt["id"]],
                        "score_contribution": 35,
                        "evidence": f"Accessed sensitive resource '{evt.get('resource')}' after privilege change or failed logins"
                    })
                    break

        # Rule 5: Unusual Login Time (Night Hours: 22:00 - 06:00)
        for evt in sorted_events:
            if evt.get("event_type") in ("login_success", "login_failed", "privilege_change"):
                hour = evt.get("hour", 12)
                if hour >= 22 or hour < 6:
                    matched_rules.append({
                        "rule_id": "R005",
                        "rule_name": "Unusual Login Time",
                        "description": f"Event '{evt.get('event_type')}' performed outside normal operating hours ({hour:02d}:00 UTC).",
                        "target_user": evt.get("user", "unknown"),
                        "target_ip": evt.get("source_ip", "0.0.0.0"),
                        "matched_event_ids": [evt["id"]],
                        "score_contribution": 15,
                        "evidence": f"Activity recorded at off-peak hour {hour:02d}:00"
                    })

        # Rule 6: Abnormal Event Frequency
        for user, u_events in by_user.items():
            if len(u_events) >= 5:
                matched_rules.append({
                    "rule_id": "R006",
                    "rule_name": "Abnormal Event Frequency",
                    "description": f"High burst of security events ({len(u_events)} events) associated with user '{user}'.",
                    "target_user": user,
                    "target_ip": u_events[0].get("source_ip", "0.0.0.0"),
                    "matched_event_ids": [e["id"] for e in u_events],
                    "score_contribution": 20,
                    "evidence": f"Burst volume: {len(u_events)} distinct events registered for '{user}'"
                })

        return matched_rules


class AIDetector:
    """IsolationForest AI Anomaly Detector."""

    def __init__(self):
        self.model = None

    def detect_anomalies(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Runs IsolationForest anomaly detection on feature vectors extracted from events.
        Returns AI summary score, count of anomalous events, and list of anomalous event details.
        """
        if not events:
            return {
                "ai_anomaly_score": 0,
                "anomalous_count": 0,
                "anomalous_events": [],
                "details": "No events available for AI analysis."
            }

        # Calculate user context metrics for features
        user_failed_cnt: Dict[str, int] = {}
        user_success_cnt: Dict[str, int] = {}
        user_total_cnt: Dict[str, int] = {}

        for evt in events:
            u = evt.get("user", "unknown")
            etype = evt.get("event_type", "")
            user_total_cnt[u] = user_total_cnt.get(u, 0) + 1
            if etype == "login_failed":
                user_failed_cnt[u] = user_failed_cnt.get(u, 0) + 1
            elif etype == "login_success":
                user_success_cnt[u] = user_success_cnt.get(u, 0) + 1

        feature_matrix = []
        for evt in events:
            u = evt.get("user", "unknown")
            etype = evt.get("event_type", "")
            hour = evt.get("hour", 12)

            f_failed = user_failed_cnt.get(u, 0)
            f_success = user_success_cnt.get(u, 0)
            f_freq = user_total_cnt.get(u, 0)
            f_priv = 1 if etype == "privilege_change" else 0
            f_sens = 1 if etype == "sensitive_resource_access" else 0
            f_unusual = 1 if etype == "unusual_request" else 0
            f_hour = hour

            feature_vector = [f_failed, f_success, f_freq, f_priv, f_sens, f_unusual, f_hour]
            feature_matrix.append(feature_vector)

        X = np.array(feature_matrix, dtype=float)

        if not SKLEARN_AVAILABLE or len(events) < 3:
            # Fallback heuristic calculation when data size is minimal
            anomalous_events = []
            max_score = 0.0
            for idx, evt in enumerate(events):
                row = X[idx]
                # Check for high failed logins, off hours, or privilege changes
                score = 0.0
                if row[0] >= 3: score += 40.0
                if row[3] == 1: score += 30.0
                if row[4] == 1: score += 30.0
                if row[6] >= 22 or row[6] < 6: score += 20.0

                if score >= 40.0:
                    anomalous_events.append({
                        "event_id": evt["id"],
                        "user": evt.get("user"),
                        "event_type": evt.get("event_type"),
                        "anomaly_score": round(min(100.0, score), 1),
                        "reason": "Elevated risk feature vector (Heuristic AI fallback)"
                    })
                if score > max_score:
                    max_score = score

            return {
                "ai_anomaly_score": round(min(100.0, max_score), 1),
                "anomalous_count": len(anomalous_events),
                "anomalous_events": anomalous_events,
                "details": "Trained IsolationForest model (Heuristic Mode for n < 3)."
            }

        try:
            # Train IsolationForest model
            contamination = min(0.3, max(0.05, 2.0 / len(events)))
            clf = IsolationForest(n_estimators=50, contamination=contamination, random_state=42)
            clf.fit(X)

            # decision_function: lower values indicate more anomalous data points
            scores = clf.decision_function(X)
            predictions = clf.predict(X)  # -1 for anomaly, 1 for normal

            anomalous_events = []
            normalized_anomaly_scores = []

            for idx, (score_val, pred) in enumerate(zip(scores, predictions)):
                # Normalize decision function score to 0..100 anomaly intensity
                # score_val usually ranges from -0.3 (very anomalous) to +0.2 (very normal)
                intensity = max(0.0, min(100.0, (0.15 - score_val) * 200.0))
                normalized_anomaly_scores.append(intensity)

                if pred == -1 or intensity >= 50.0:
                    evt = events[idx]
                    anomalous_events.append({
                        "event_id": evt["id"],
                        "user": evt.get("user"),
                        "event_type": evt.get("event_type"),
                        "anomaly_score": round(intensity, 1),
                        "reason": f"IsolationForest outlier detection (raw score: {score_val:.3f})"
                    })

            overall_ai_score = round(max(normalized_anomaly_scores) if normalized_anomaly_scores else 0.0, 1)

            return {
                "ai_anomaly_score": overall_ai_score,
                "anomalous_count": len(anomalous_events),
                "anomalous_events": anomalous_events,
                "details": f"IsolationForest evaluated {len(events)} events; detected {len(anomalous_events)} anomalies."
            }

        except Exception as err:
            return {
                "ai_anomaly_score": 0,
                "anomalous_count": 0,
                "anomalous_events": [],
                "details": f"AI model error: {str(err)}"
            }
