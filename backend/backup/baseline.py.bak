import statistics
from typing import List, Dict, Any, Tuple

class EntityBaselineTracker:
    """Tracks per-entity statistical baselines for anomaly detection."""

    def __init__(self):
        # We will build baselines from the provided events. 
        # In a real system, these would be loaded from a database.
        self.user_hours: Dict[str, List[int]] = {}
        self.user_ips: Dict[str, set] = {}
        self.user_failure_counts: Dict[str, int] = {}
        self.user_success_counts: Dict[str, int] = {}
        
        self.global_hours: List[int] = []
        self.global_failure_rate: float = 0.0

    def fit(self, events: List[Dict[str, Any]]):
        """Builds baselines from historical events."""
        global_fails = 0
        global_successes = 0

        for evt in events:
            user = evt.get("user", "unknown")
            hour = evt.get("hour", 12)
            ip = evt.get("source_ip", "0.0.0.0")
            etype = evt.get("event_type", "")

            # Track user hours
            self.user_hours.setdefault(user, []).append(hour)
            self.global_hours.append(hour)

            # Track user IPs
            self.user_ips.setdefault(user, set()).add(ip)

            # Track failures/successes
            if etype == "login_failed":
                self.user_failure_counts[user] = self.user_failure_counts.get(user, 0) + 1
                global_fails += 1
            elif etype == "login_success":
                self.user_success_counts[user] = self.user_success_counts.get(user, 0) + 1
                global_successes += 1

        # Global failure rate
        total_logins = global_fails + global_successes
        if total_logins > 0:
            self.global_failure_rate = global_fails / total_logins

    def get_user_failure_rate(self, user: str) -> Tuple[float, int]:
        """Returns failure rate and total login attempts for a user."""
        f = self.user_failure_counts.get(user, 0)
        s = self.user_success_counts.get(user, 0)
        t = f + s
        if t == 0:
            return 0.0, 0
        return f / t, t

    def analyze_event(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes a single event against the baseline."""
        user = evt.get("user", "unknown")
        hour = evt.get("hour", 12)
        ip = evt.get("source_ip", "0.0.0.0")
        etype = evt.get("event_type", "")

        deviations = []
        baseline_score = 0
        confidence = "HIGH"

        user_history_count = len(self.user_hours.get(user, []))

        # Cold-start handling
        if user_history_count < 5:
            confidence = "LOW"
            # Fallback to global baselines
            if self.global_hours:
                # Global hour check (rough: mostly daytime 8-18)
                median_global_hour = statistics.median(self.global_hours)
                if abs(hour - median_global_hour) > 6:
                    deviations.append(f"Unusual global login hour ({hour}:00, median {median_global_hour}:00)")
                    baseline_score += 10
            
            if etype == "login_failed" and self.global_failure_rate < 0.3:
                deviations.append(f"Failed login on cold-start profile (Global rate: {self.global_failure_rate:.1%})")
                baseline_score += 5
        else:
            # User specific baselines
            median_hour = statistics.median(self.user_hours[user])
            
            # 1. Hour deviation
            hour_diff = min(abs(hour - median_hour), 24 - abs(hour - median_hour))
            if hour_diff > 4:
                deviations.append(f"Unusual login hour for user ({hour}:00 vs median {median_hour}:00)")
                baseline_score += 15

            # 2. IP deviation
            known_ips = self.user_ips.get(user, set())
            if ip not in known_ips and len(known_ips) > 0:
                deviations.append(f"Unknown source IP for user ({ip})")
                baseline_score += 20

            # 3. Failure rate deviation
            if etype == "login_failed":
                u_fail_rate, total_attempts = self.get_user_failure_rate(user)
                if u_fail_rate > 0.5 and total_attempts >= 3:
                    deviations.append(f"Elevated failure rate for user ({u_fail_rate:.1%})")
                    baseline_score += 20

        return {
            "event_id": evt["id"],
            "user": user,
            "baseline_score": baseline_score,
            "deviations": deviations,
            "confidence": confidence,
            "history_count": user_history_count
        }

    def evaluate_baselines(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluates all events sequentially, updating the baseline after each."""
        # For evaluation, we will rebuild the baseline sequentially to simulate real-time
        self.__init__() # Reset
        
        results = []
        for evt in events:
            # Analyze BEFORE adding to baseline so we don't consider the current event as "normal"
            res = self.analyze_event(evt)
            if res["baseline_score"] > 0:
                results.append(res)
            
            # Now fit this event
            self.fit([evt])
            
        return results
