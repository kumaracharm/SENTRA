import os
import json
import hmac
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Body, Request, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse

from backend.parser import parse_json_logs, parse_csv_logs, parse_logs, normalize_log_event, parse_timestamp
from backend.detector import RuleEngine, AIDetector
from backend.baseline import EntityBaselineTracker
from backend.risk_engine import RiskEngine, SourceHealthTracker

# New L1-L3 modules
from backend.telemetry_validator import EventValidator, get_default_validator, TrustLevel
from backend.adaptive_baseline import AdaptiveBaselineTracker, get_default_tracker
from backend.attack_graph import TemporalAttackGraph

from fastapi.middleware.cors import CORSMiddleware

# Setup paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_FILE = DATA_DIR / "logs.json"
FRONTEND_DIR = BASE_DIR / "frontend"

# Environmental security configuration
LOGSHIELD_INGEST_TOKEN = os.getenv("LOGSHIELD_INGEST_TOKEN", "logshield-secret-token")
LOGSHIELD_HMAC_SECRET = os.getenv("LOGSHIELD_HMAC_SECRET", "logshield-hmac-secret-key")
LOGSHIELD_REQUIRE_HMAC = os.getenv("LOGSHIELD_REQUIRE_HMAC", "false").lower() == "true"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)
if not LOGS_FILE.exists():
    with open(LOGS_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

app = FastAPI(
    title="LOGSHIELD API",
    description="AI-Assisted Log-Based Intrusion Detection System (V1.0 — Security Intelligence Upgrade)",
    version="1.0"
)

# Enable CORS for cross-origin login website and separate frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate engines and trackers
rule_engine = RuleEngine()
ai_detector = AIDetector()
risk_engine = RiskEngine()
source_health_tracker = SourceHealthTracker(silence_threshold_seconds=30)

# L1-L3 singletons
event_validator = get_default_validator()
adaptive_baseline = get_default_tracker()
attack_graph_engine = TemporalAttackGraph(session_window_minutes=60)

# Deduplication and sequence tracking state (kept for backward compat)
seen_event_ids: set[str] = set()
seen_sequences: dict[str, int] = {}  # source_ip -> highest sequence number


def sync_source_health_from_events(events: List[Dict[str, Any]]):
    """Sync source activity timestamps and sequence tracking from log events."""
    for evt in events:
        src = evt.get("source_ip", "127.0.0.1")
        ts = evt.get("timestamp")
        source_health_tracker.update_source(src, ts)
        if evt.get("id"):
            seen_event_ids.add(str(evt["id"]))
        if evt.get("sequence") is not None:
            try:
                seq_val = int(evt["sequence"])
                seen_sequences[src] = max(seen_sequences.get(src, -1), seq_val)
            except (ValueError, TypeError):
                pass


def read_logs_file() -> List[Dict[str, Any]]:
    """Helper to read and parse logs from logs.json."""
    if not LOGS_FILE.exists():
        return []
    try:
        with open(LOGS_FILE, "r", encoding="utf-8") as f:
            content = f.read()
            events = parse_logs(content, filename="logs.json")
            sync_source_health_from_events(events)
            return events
    except Exception:
        return []


def write_logs_file(events: List[Dict[str, Any]]):
    """Helper to write events to logs.json."""
    with open(LOGS_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)


@app.get("/api/health")
def get_health():
    """Health check endpoint with system telemetry status."""
    sources = source_health_tracker.get_source_health()
    active_gaps = [s for s in sources if s.get("is_evidence_gap")]
    return {
        "status": "ok",
        "app": "LOGSHIELD",
        "version": "1.0",
        "logs_path": str(LOGS_FILE),
        "ingest_endpoint": "/api/ingest",
        "tracked_sources_count": len(sources),
        "evidence_gaps_count": len(active_gaps),
        "ingest_security": {
            "token_required": True,
            "hmac_supported": True,
            "hmac_required": LOGSHIELD_REQUIRE_HMAC
        }
    }


@app.get("/api/logs")
def get_logs():
    """Returns the current raw log events."""
    events = read_logs_file()
    return {
        "count": len(events),
        "logs": events
    }


@app.get("/api/analyze")
def analyze_logs():
    """Analyzes logs via Parser, Rules, IsolationForest AI, Correlation, and Risk Engine."""
    events = read_logs_file()
    source_health_list = source_health_tracker.get_source_health()
    active_gaps = [s for s in source_health_list if s.get("is_evidence_gap")]

    if not events:
        risk_summary = risk_engine.evaluate_overall_risk(
            [], [], {"ai_anomaly_score": 0, "anomalous_count": 0}, [], [], source_health_list
        )
        return {
            "total_events": 0,
            "critical_alerts": 0,
            "high_risk_events": 0,
            "average_risk": 0,
            "anomalous_events_count": 0,
            "risk_summary": risk_summary,
            "matched_rules": [],
            "baseline_anomalies": [],
            "ai_analysis": {
                "ai_anomaly_score": 0,
                "anomalous_count": 0,
                "anomalous_events": []
            },
            "incidents": [],
            "events": [],
            "sources_health": source_health_list,
            "evidence_gaps": active_gaps,
            "detection_breakdown": {
                "rule_score": 0,
                "ai_score": 0,
                "baseline_score": 0,
                "correlation_bonus": 0
            }
        }

    # 1. Rule Engine Evaluation
    rules = rule_engine.evaluate_rules(events)

    # 2. AI Anomaly Detection
    ai_res = ai_detector.detect_anomalies(events)

    # 3. Entity Baseline Evaluation
    baseline_tracker = EntityBaselineTracker()
    baseline_anomalies = baseline_tracker.evaluate_baselines(events)

    # 4. Event Correlation into Incidents & Case Files
    incidents = risk_engine.correlate_incidents(events, rules, baseline_anomalies, source_health_list)

    # 5. Overall Risk & Separate Evidence Confidence Assessment
    risk_summary = risk_engine.evaluate_overall_risk(events, rules, ai_res, baseline_anomalies, incidents, source_health_list)

    # Stats calculations
    critical_alerts = sum(1 for inc in incidents if inc.get("severity") == "CRITICAL") + \
                      sum(1 for r in rules if r.get("score_contribution", 0) >= 30)
    
    high_risk_events = sum(1 for e in ai_res.get("anomalous_events", []) if e.get("anomaly_score", 0) >= 60)

    return {
        "total_events": len(events),
        "critical_alerts": critical_alerts,
        "high_risk_events": high_risk_events,
        "average_risk": risk_summary["risk_score"],
        "anomalous_events_count": ai_res.get("anomalous_count", 0),
        "risk_summary": risk_summary,
        "matched_rules": rules,
        "baseline_anomalies": baseline_anomalies,
        "ai_analysis": ai_res,
        "incidents": incidents,
        "events": events,
        "sources_health": source_health_list,
        "evidence_gaps": active_gaps,
        "detection_breakdown": risk_summary["breakdown"]
    }


@app.get("/api/analyze/v2")
def analyze_logs_v2():
    """
    Upgraded analysis endpoint using all four architectural layers (L1-L4).
    Returns richer incident data with:
    - Separate threat_risk_score and evidence_confidence_score
    - Temporal attack graph chains and matched patterns
    - Behavioral drift and baseline adaptation status
    - Counterfactual assessment for top incident
    - Risk-ranked response recommendations
    """
    events = read_logs_file()
    source_health_list = source_health_tracker.get_source_health()
    active_gaps = [s for s in source_health_list if s.get("is_evidence_gap")]

    # L1: Source identity and telemetry classification summary
    source_identity = event_validator.source_registry.all_sources()

    if not events:
        return {
            "version": "1.0",
            "total_events": 0,
            "threat_risk_score": 0,
            "evidence_confidence_score": 100,
            "incidents_v2": [],
            "attack_graph_chains": [],
            "baseline_status": [],
            "drift_alarms": [],
            "source_identity": source_identity,
            "evidence_gaps": active_gaps,
            "response_recommendations": [],
            "counterfactual_demo": None,
        }

    # Standard analysis pipeline (L1+L2+Rules+AI)
    rules = rule_engine.evaluate_rules(events)
    ai_res = ai_detector.detect_anomalies(events)
    baseline_tracker = EntityBaselineTracker()
    baseline_anomalies = baseline_tracker.evaluate_baselines(events)
    incidents = risk_engine.correlate_incidents(events, rules, baseline_anomalies, source_health_list)
    risk_summary = risk_engine.evaluate_overall_risk(
        events, rules, ai_res, baseline_anomalies, incidents, source_health_list
    )

    # L2: Adaptive baseline evaluation
    adaptive_results = adaptive_baseline.evaluate_events(events)
    baseline_status = adaptive_baseline.get_entity_status()
    drift_alarms = [r for r in adaptive_results if r.get("drift_alarm")]
    suspected_poisoning = [r for r in adaptive_results if r.get("suspected_poisoning")]

    # L3: Temporal attack graph
    attack_graph_results = attack_graph_engine.analyze(events)
    graph_chains = [r.to_dict() for r in attack_graph_results]

    # Enhance incidents with graph data
    incidents_v2 = []
    for inc in incidents:
        inc_copy = dict(inc)
        # Find matching graph chain
        for chain in attack_graph_results:
            if chain.entity == inc.get("user") and chain.source_ip == inc.get("source_ip"):
                inc_copy["graph_score"] = chain.graph_score
                inc_copy["matched_patterns"] = chain.matched_patterns
                inc_copy["observed_stages"] = chain.observed_stages
                inc_copy["inferred_stages"] = chain.inferred_stages
                inc_copy["contradictory_evidence"] = chain.contradictory_evidence
                inc_copy["missing_observations"] = chain.missing_observations
                inc_copy["graph_incident_id"] = chain.incident_id
                break
        # L4: Risk-ranked response recommendations
        inc_copy["response_recommendations"] = _build_response_recommendations(inc_copy)
        incidents_v2.append(inc_copy)

    # Counterfactual demo for the top incident
    counterfactual_demo = None
    if incidents_v2:
        top_inc = incidents_v2[0]
        supporting_ids = top_inc.get("supporting_event_ids", [])
        if supporting_ids:
            # Counterfactual: what if the first event in the chain is excluded?
            cf_event_id = supporting_ids[0]
            counterfactual_demo = attack_graph_engine.counterfactual_analysis(
                events, cf_event_id
            )
            counterfactual_demo["demo_context"] = (
                f"Counterfactual: what happens to incident "
                f"'{top_inc.get('incident_id')}' if event '{cf_event_id}' is excluded?"
            )

    # Global response recommendations from the risk summary
    global_recommendations = _build_global_recommendations(risk_summary, incidents_v2, drift_alarms)

    return {
        "version": "1.0",
        "total_events": len(events),
        "threat_risk_score": risk_summary.get("threat_risk_score", risk_summary["risk_score"]),
        "evidence_confidence_score": risk_summary.get("evidence_confidence", 60),
        "severity": risk_summary["severity"],
        "risk_summary": risk_summary,
        "incidents_v2": incidents_v2,
        "attack_graph_chains": graph_chains,
        "baseline_status": baseline_status,
        "drift_alarms": [r for r in adaptive_results if r.get("drift_alarm")],
        "suspected_poisoning_alerts": suspected_poisoning,
        "baseline_frozen_entities": [
            s for s in baseline_status if s.get("baseline_frozen")
        ],
        "source_identity": source_identity,
        "evidence_gaps": active_gaps,
        "response_recommendations": global_recommendations,
        "counterfactual_demo": counterfactual_demo,
        "matched_rules": rules,
        "ai_analysis": ai_res,
        "sources_health": source_health_list,
    }


def _build_response_recommendations(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    L4: Build explicit, evidence-backed response recommendations for one incident.
    All recommendations are ADVISORY only. No automated action is taken.
    """
    recs = []
    user = incident.get("user", "unknown")
    source_ip = incident.get("source_ip", "unknown")
    severity = incident.get("severity", "LOW")
    verdict = incident.get("verdict", "")
    confidence = incident.get("evidence_confidence", 50)

    if "ACCOUNT TAKEOVER" in verdict or "EXFILTRATION" in verdict:
        recs.append({
            "priority": 1,
            "action": "ISOLATE_SOURCE",
            "description": f"Block source IP {source_ip} at network perimeter.",
            "supporting_evidence": incident.get("reasons", [])[:2],
            "uncertainty": f"Evidence confidence: {confidence}%. Verify no legitimate admin use before blocking.",
            "authorized": False,
            "advisory_only": True,
        })
        recs.append({
            "priority": 2,
            "action": "REVOKE_SESSION",
            "description": f"Revoke all active sessions for account '{user}' and force password reset.",
            "supporting_evidence": [incident.get("explanation", "")],
            "uncertainty": "Confirm this is not an authorized privileged operation before revoking.",
            "authorized": False,
            "advisory_only": True,
        })

    if "PRIVILEGE ESCALATION" in verdict or severity in ("HIGH", "CRITICAL"):
        recs.append({
            "priority": 3,
            "action": "AUDIT_PERMISSIONS",
            "description": f"Review recent permission changes for '{user}' and revert unauthorized escalations.",
            "supporting_evidence": incident.get("reasons", [])[:1],
            "uncertainty": "Some escalations may be legitimate IT admin operations.",
            "authorized": False,
            "advisory_only": True,
        })

    recs.append({
        "priority": 10,
        "action": "INVESTIGATE",
        "description": f"Collect additional telemetry: endpoint logs, network capture, and identity audit for '{user}' from {source_ip}.",
        "supporting_evidence": incident.get("missing_evidence", [])[:2],
        "uncertainty": "Missing telemetry noted — investigation may resolve ambiguity.",
        "authorized": False,
        "advisory_only": True,
    })

    return sorted(recs, key=lambda r: r["priority"])


def _build_global_recommendations(
    risk_summary: Dict[str, Any],
    incidents: List[Dict[str, Any]],
    drift_alarms: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Global recommendations based on overall risk posture."""
    recs = []
    severity = risk_summary.get("severity", "LOW")

    if severity in ("HIGH", "CRITICAL"):
        recs.append({
            "priority": 1,
            "action": "ESCALATE_TO_SOC",
            "description": "Escalate to Security Operations Center for manual review.",
            "reasoning": f"Overall threat risk score {risk_summary.get('threat_risk_score', 0)}/100 at {severity} severity.",
            "advisory_only": True,
        })

    if drift_alarms:
        recs.append({
            "priority": 2,
            "action": "REVIEW_BASELINE_DRIFT",
            "description": "Review Page-Hinkley drift alarms — potential baseline manipulation detected.",
            "reasoning": f"{len(drift_alarms)} drift alarm(s) fired across entities.",
            "advisory_only": True,
        })

    if risk_summary.get("evidence_gaps"):
        recs.append({
            "priority": 3,
            "action": "CHECK_TELEMETRY_SOURCES",
            "description": "Verify telemetry collection on silent sources.",
            "reasoning": "Evidence gaps detected — incomplete telemetry reduces assessment confidence.",
            "advisory_only": True,
        })

    return recs


@app.get("/api/baselines")
def get_baselines():
    """Returns current entity baseline state from the adaptive baseline tracker."""
    return {
        "entity_count": len(adaptive_baseline.entities),
        "entities": adaptive_baseline.get_entity_status(),
        "global_hour_samples": len(adaptive_baseline.global_profile.all_hours),
    }


@app.get("/api/counterfactual/{event_id}")
def get_counterfactual(event_id: str):
    """
    Counterfactual analysis: how does the incident assessment change if
    the specified event_id is excluded from consideration?
    """
    events = read_logs_file()
    result = attack_graph_engine.counterfactual_analysis(events, event_id)
    return result


@app.post("/api/scenario/run")
async def run_scenario(request: Request):
    """
    Runs a named reproducible scenario by generating synthetic events.
    Scenario names: normal, brute_force, privilege_escalation, data_exfil,
                    gradual_drift, incomplete_telemetry, conflicting_evidence
    """
    body = await request.json()
    scenario_name = str(body.get("scenario", "normal")).lower()
    
    from backend.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    result = runner.run(scenario_name)
    
    if result.get("error"):
        return JSONResponse(status_code=400, content=result)
    
    # Append generated events to logs
    events_to_add = result.get("events", [])
    if events_to_add:
        existing = read_logs_file()
        write_logs_file(existing + events_to_add)
        sync_source_health_from_events(events_to_add)
    
    analysis = analyze_logs()
    return {
        "scenario": scenario_name,
        "description": result.get("description", ""),
        "events_generated": len(events_to_add),
        "ground_truth_labels": result.get("labels", {}),
        "analysis": analysis,
    }


@app.post("/api/ingest")
async def ingest_event(
    request: Request,
    x_logshield_token: Optional[str] = Header(None, alias="X-LogShield-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_logshield_signature: Optional[str] = Header(None, alias="X-LogShield-Signature"),
    x_signature_256: Optional[str] = Header(None, alias="X-Signature-256")
):
    """
    Real-time secure event ingestion API endpoint for external web applications.
    Validates token, HMAC signature, timestamp drift, and duplicate/replayed event sequences.
    """
    # 1. Integration Token Validation
    token = x_logshield_token
    if not token and authorization:
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        else:
            token = authorization.strip()
            
    if not token:
        token = request.query_params.get("token")

    if not token or token != LOGSHIELD_INGEST_TOKEN:
        return JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "detail": "Invalid or missing integration token",
                "code": "INVALID_TOKEN"
            }
        )

    # 2. HMAC-SHA256 Signature Verification
    body_bytes = await request.body()
    sig_header = x_logshield_signature or x_signature_256
    hmac_verified = False

    if LOGSHIELD_REQUIRE_HMAC and not sig_header:
        return JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "detail": "HMAC signature header (X-LogShield-Signature) required but missing",
                "code": "MISSING_SIGNATURE"
            }
        )

    if sig_header and LOGSHIELD_HMAC_SECRET:
        clean_sig = sig_header.replace("sha256=", "").strip()
        expected_sig = hmac.new(
            LOGSHIELD_HMAC_SECRET.encode("utf-8"),
            body_bytes,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(clean_sig.lower(), expected_sig.lower()):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Invalid HMAC signature verification",
                    "code": "INVALID_SIGNATURE"
                }
            )
        hmac_verified = True

    # 3. Payload Parsing & Malformed Event Validation
    if not body_bytes or not body_bytes.strip():
        return JSONResponse(
            status_code=400,
            content={
                "error": "Bad Request",
                "detail": "Empty or missing event payload",
                "code": "MALFORMED_EVENT"
            }
        )

    try:
        raw_payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Bad Request",
                "detail": "Malformed JSON event payload",
                "code": "MALFORMED_EVENT"
            }
        )

    if isinstance(raw_payload, dict):
        raw_events = [raw_payload]
    elif isinstance(raw_payload, list):
        raw_events = raw_payload
    else:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Bad Request",
                "detail": "JSON payload must be an event object or list of event objects",
                "code": "MALFORMED_EVENT"
            }
        )

    if not raw_events:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Bad Request",
                "detail": "No event objects found in payload",
                "code": "MALFORMED_EVENT"
            }
        )

    # 4. Event Validation via L1 EventValidator
    now_utc = datetime.now(timezone.utc)
    accepted_events = []

    for idx, raw_evt in enumerate(raw_events):
        if not isinstance(raw_evt, dict):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Bad Request",
                    "detail": f"Event at index {idx} is not a valid JSON object",
                    "code": "MALFORMED_EVENT"
                }
            )

        # Use L1 validator for richer classification
        val_result = event_validator.validate_event(
            raw_evt,
            hmac_verified=hmac_verified,
            ingest_method="api",
            now_utc=now_utc,
        )

        if not val_result.accepted:
            # Map rejection codes to HTTP responses
            code = val_result.rejection_code or "VALIDATION_ERROR"
            if code in ("DUPLICATE_EVENT", "DUPLICATE_SEQUENCE"):
                return JSONResponse(
                    status_code=409,
                    content={
                        "error": "Conflict",
                        "detail": val_result.rejection_detail,
                        "code": code,
                    }
                )
            elif code in ("TIMESTAMP_DRIFT", "INVALID_TIMESTAMP"):
                return JSONResponse(
                    status_code=422,
                    content={
                        "error": "Unprocessable Entity",
                        "detail": val_result.rejection_detail,
                        "code": code,
                    }
                )
            else:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Bad Request",
                        "detail": val_result.rejection_detail,
                        "code": code,
                    }
                )

        normalized = normalize_log_event(raw_evt, idx)
        # Add provenance from L1 validator
        normalized.update(val_result.provenance)
        seq_num = raw_evt.get("sequence")
        if seq_num is not None:
            normalized["sequence"] = seq_num

        # Also maintain legacy in-memory sets for backward compatibility
        evt_id = normalized.get("id")
        if evt_id:
            seen_event_ids.add(str(evt_id))
        src_ip = normalized.get("source_ip", "127.0.0.1")
        if seq_num is not None:
            try:
                seen_sequences[src_ip] = max(seen_sequences.get(src_ip, -1), int(seq_num))
            except (ValueError, TypeError):
                pass

        accepted_events.append(normalized)

    # 5. Ingestion & Storage Update
    existing = read_logs_file()
    updated_logs = existing + accepted_events
    write_logs_file(updated_logs)

    sync_source_health_from_events(accepted_events)

    # Run instant analysis
    analysis_result = analyze_logs()

    return {
        "status": "success",
        "message": f"Successfully ingested {len(accepted_events)} live security event(s).",
        "ingested_count": len(accepted_events),
        "analysis": analysis_result
    }


@app.post("/api/upload")
async def upload_logs(
    request: Request,
    file: Optional[UploadFile] = File(None),
    mode: Optional[str] = "overwrite"
):
    """Upload and ingest log files (JSON, CSV, Syslog/TXT) or direct JSON payload."""
    parsed_events = []
    filename = ""

    if file and file.filename:
        filename = file.filename
        content = await file.read()
        parsed_events = parse_logs(content, filename=filename)
    else:
        try:
            body_bytes = await request.body()
            if body_bytes:
                content_str = body_bytes.decode("utf-8", errors="ignore")
                parsed_events = parse_logs(content_str, filename="payload.json")
        except Exception:
            pass

    if not parsed_events:
        raise HTTPException(status_code=400, detail="Could not parse any valid log events.")

    if mode == "append":
        existing = read_logs_file()
        parsed_events = existing + parsed_events

    write_logs_file(parsed_events)
    sync_source_health_from_events(parsed_events)

    return analyze_logs()


@app.post("/api/reset")
def reset_logs():
    """Clears all logs and tracking state in data/logs.json."""
    seen_event_ids.clear()
    seen_sequences.clear()
    source_health_tracker.sources.clear()
    event_validator.reset()
    write_logs_file([])
    return {
        "status": "success",
        "message": "Logs reset successfully.",
        "analysis": analyze_logs()
    }


# Mount static files for dashboard frontend
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            with open(index_path, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>LOGSHIELD API Running. Frontend index.html not found.</h1>"
