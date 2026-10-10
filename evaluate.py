import sys
import uuid
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Setup paths to import backend
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from backend.detector import RuleEngine, AIDetector
from backend.risk_engine import RiskEngine

def generate_labeled_dataset():
    """Generates a reproducible dataset with ground truth labels."""
    dataset = []
    base_time = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 1. Generate Benign Events (Simulating 1 Day of normal activity)
    # 50 normal logins spread across the day
    for i in range(50):
        dataset.append({
            "id": f"evt-benign-{i}",
            "timestamp": (base_time + timedelta(hours=8 + (i % 10), minutes=i)).isoformat(),
            "hour": 8 + (i % 10),
            "user": f"user_{(i % 5) + 1}",
            "source_ip": f"192.168.1.{10 + (i % 5)}",
            "event_type": "login_success",
            "resource": "/auth/login",
            "details": "Standard user login",
            "label_attack": False
        })
        
    # 50 file accesses
    for i in range(50):
        dataset.append({
            "id": f"evt-benign-file-{i}",
            "timestamp": (base_time + timedelta(hours=9 + (i % 8), minutes=i)).isoformat(),
            "hour": 9 + (i % 8),
            "user": f"user_{(i % 5) + 1}",
            "source_ip": f"192.168.1.{10 + (i % 5)}",
            "event_type": "file_access",
            "resource": f"/docs/file_{i%10}.pdf",
            "details": "Opened document",
            "label_attack": False
        })
        
    # 2. Generate Attack 1: Brute Force & Account Takeover (4 events)
    at_ip = "203.0.113.88"
    at_user = "admin"
    for i in range(3):
        dataset.append({
            "id": f"evt-attack-bf-{i}",
            "timestamp": (base_time + timedelta(hours=2, minutes=i)).isoformat(),
            "hour": 2,
            "user": at_user,
            "source_ip": at_ip,
            "event_type": "login_failed",
            "resource": "/portal/login",
            "details": "Failed password check",
            "label_attack": True
        })
    dataset.append({
        "id": "evt-attack-bf-success",
        "timestamp": (base_time + timedelta(hours=2, minutes=3)).isoformat(),
        "hour": 2,
        "user": at_user,
        "source_ip": at_ip,
        "event_type": "login_success",
        "resource": "/portal/login",
        "details": "Brute force success",
        "label_attack": True
    })
    
    # 3. Generate Attack 2: Privilege Escalation & Sensitive Access (4 events)
    pe_ip = "10.0.4.12"
    pe_user = "dev_user"
    dataset.extend([
        {
            "id": "evt-attack-pe-1",
            "timestamp": (base_time + timedelta(hours=14, minutes=0)).isoformat(),
            "hour": 14,
            "user": pe_user,
            "source_ip": pe_ip,
            "event_type": "login_success",
            "resource": "/dev/login",
            "details": "Dev login",
            "label_attack": True
        },
        {
            "id": "evt-attack-pe-2",
            "timestamp": (base_time + timedelta(hours=14, minutes=5)).isoformat(),
            "hour": 14,
            "user": pe_user,
            "source_ip": pe_ip,
            "event_type": "unusual_request",
            "resource": "/api/internal/sudo_check",
            "details": "Probe",
            "label_attack": True
        },
        {
            "id": "evt-attack-pe-3",
            "timestamp": (base_time + timedelta(hours=15, minutes=0)).isoformat(),
            "hour": 15,
            "user": pe_user,
            "source_ip": pe_ip,
            "event_type": "privilege_change",
            "resource": "/system/group/wheel",
            "details": "Elevated to wheel",
            "label_attack": True
        },
        {
            "id": "evt-attack-pe-4",
            "timestamp": (base_time + timedelta(hours=15, minutes=5)).isoformat(),
            "hour": 15,
            "user": pe_user,
            "source_ip": pe_ip,
            "event_type": "sensitive_resource_access",
            "resource": "/etc/shadow",
            "details": "Read shadow",
            "label_attack": True
        }
    ])
    
    return dataset

def evaluate_harness():
    events = generate_labeled_dataset()
    
    total_events = len(events)
    attack_events = [e for e in events if e["label_attack"]]
    benign_events = [e for e in events if not e["label_attack"]]
    
    total_attacks = len(attack_events)
    total_benign = len(benign_events)
    
    print(f"--- LogShield Evaluation Harness (Synthetic Replay Benchmark) ---")
    print(f"Total Events: {total_events}")
    print(f"Benign Events (1 Day): {total_benign}")
    print(f"Attack Events: {total_attacks}")
    print(f"Note: These metrics do not represent production accuracy.")
    print("-" * 65)
    
    detector = AIDetector()
    rule_engine = RuleEngine()
    risk_engine = RiskEngine()
    
    from backend.baseline import EntityBaselineTracker
    baseline_tracker = EntityBaselineTracker()
    
    # Evaluate Rules Base
    matched_rules = rule_engine.evaluate_rules(events)
    rule_alert_ids = set()
    for r in matched_rules:
        for eid in r.get("matched_event_ids", []):
            rule_alert_ids.add(eid)
            
    # Evaluate AI Base
    ai_res = detector.detect_anomalies(events)
    ai_alert_ids = set([e["event_id"] for e in ai_res.get("anomalous_events", [])])
    
    # Evaluate Entity Baseline
    baseline_anomalies = baseline_tracker.evaluate_baselines(events)
    baseline_alert_ids = set([b["event_id"] for b in baseline_anomalies if b["baseline_score"] > 0])
    
    # Evaluate RiskEngine (Combined)
    incidents = risk_engine.correlate_incidents(events, matched_rules, baseline_anomalies)
    # Consider events in HIGH or CRITICAL incidents as combined alerts
    combined_alert_ids = set()
    for inc in incidents:
        if inc["severity"] in ("HIGH", "CRITICAL"):
            for e in inc.get("correlated_events", []):
                combined_alert_ids.add(e["id"])
                
    # Calculate Metrics
    def calc_metrics(alert_ids, name):
        # Recall: True Positives / Total Attacks
        tp = sum(1 for e in attack_events if e["id"] in alert_ids)
        # False Positives: Alerts on Benign Events
        fp = sum(1 for e in benign_events if e["id"] in alert_ids)
        
        recall = (tp / total_attacks) * 100 if total_attacks > 0 else 0
        
        print(f"[{name}]")
        print(f"  Attack Recall: {tp}/{total_attacks} ({recall:.1f}%)")
        print(f"  Benign Alerts/Day (FP): {fp}")
        print()
        
    calc_metrics(rule_alert_ids, "Fixed-Rule Baseline")
    calc_metrics(ai_alert_ids, "IsolationForest Baseline")
    calc_metrics(baseline_alert_ids, "Entity Baseline Tracker")
    calc_metrics(combined_alert_ids, "LogShield Risk Engine (Combined)")

if __name__ == "__main__":
    evaluate_harness()
