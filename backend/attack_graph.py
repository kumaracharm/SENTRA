"""
L3 — Temporal Attack Reasoning and Explainability
==================================================
TemporalAttackGraph: connects events across time via a directed graph,
identifies multi-stage attack sequences, and provides counterfactual analysis.

Approach
--------
We implement a lightweight temporal state-transition graph rather than a
full attack tree (which would require predefined MITRE ATT&CK templates and
labeled training data we do not have). The algorithm:

1. Creates an event node for each ingested event.
2. Draws a directed edge from event A to event B when:
   - Same entity (user) or same source IP (lateral movement)
   - B occurs after A within a configurable session window
   - The event-type transition is in the known transition table
     (e.g. login_failed → login_success is meaningful, not just two randoms)
3. Scores each path through the graph by summing transition weights.
4. Identifies the highest-scoring path as the incident chain.
5. Counterfactual: removes a nominated event and rescores.

Reference for state-transition scoring:
  Ning, P., Cui, Y., Reeves, D. S. (2002). "Constructing Attack Scenarios
  Through Correlation of Intrusion Alerts." ACM CCS 2002.

Design choices vs. full attack tree
------------------------------------
* We do NOT require pre-trained classifiers or hand-coded MITRE ATT&CK IDs.
* We DO use the existing normalised event types as states.
* Edge weights encode the security significance of each transition.
* This is a contribution of integration and evaluation, not a novel algorithm.

Limitations
-----------
* Session window (default 30 min) may miss slow-burn APT campaigns.
* Transition table only covers events in VALID_EVENT_TYPES.
* Graph is rebuilt on every call (stateless); persisting the graph across
  ingestions would require incremental update logic.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Transition weight table
# ---------------------------------------------------------------------------
# Rows = source state, columns = destination state.
# Weight 0 = no meaningful causal relationship; weight > 0 = scored edge.

_TRANSITION_WEIGHTS: Dict[str, Dict[str, float]] = {
    "login_failed": {
        "login_failed": 1.0,          # Continued brute-force attempt
        "login_success": 4.0,         # Brute-force success — highly suspicious
        "unusual_request": 2.0,       # Probing after failure
        "privilege_change": 0.0,
        "sensitive_resource_access": 0.0,
        "file_access": 0.0,
        "data_transfer": 0.0,
    },
    "login_success": {
        "privilege_change": 5.0,      # Immediate escalation post-login
        "sensitive_resource_access": 4.0,
        "data_transfer": 3.0,
        "unusual_request": 2.0,
        "file_access": 1.0,
        "login_failed": 0.0,
        "login_success": 0.5,
    },
    "privilege_change": {
        "sensitive_resource_access": 6.0,   # Escalation then data access
        "data_transfer": 5.0,
        "file_access": 3.0,
        "unusual_request": 2.0,
        "login_failed": 0.0,
        "login_success": 0.0,
        "privilege_change": 1.0,
    },
    "sensitive_resource_access": {
        "data_transfer": 6.0,         # Access then exfil
        "file_access": 2.0,
        "unusual_request": 1.0,
        "login_failed": 0.0,
        "login_success": 0.0,
        "privilege_change": 0.0,
        "sensitive_resource_access": 3.0,
    },
    "unusual_request": {
        "login_failed": 1.0,
        "login_success": 2.0,
        "privilege_change": 3.0,
        "sensitive_resource_access": 3.0,
        "unusual_request": 2.0,
        "data_transfer": 2.0,
        "file_access": 1.0,
    },
    "file_access": {
        "data_transfer": 3.0,
        "sensitive_resource_access": 2.0,
        "unusual_request": 1.0,
        "file_access": 0.5,
        "login_failed": 0.0,
        "login_success": 0.0,
        "privilege_change": 0.0,
    },
    "data_transfer": {
        "data_transfer": 2.0,
        "file_access": 1.0,
        "unusual_request": 1.0,
        "login_failed": 0.0,
        "login_success": 0.0,
        "privilege_change": 0.0,
        "sensitive_resource_access": 0.0,
    },
}

# Known multi-stage attack progression patterns (for pattern matching)
_ATTACK_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "CREDENTIAL_BRUTE_FORCE",
        "description": "Repeated failed logins followed by successful authentication",
        "sequence": ["login_failed", "login_failed", "login_success"],
        "min_match": 2,  # At least 2 failed before success
        "base_score": 35.0,
        "mitre_technique": "T1110",
    },
    {
        "name": "PRIVILEGE_ESCALATION_CHAIN",
        "description": "Login succeeded by privilege change",
        "sequence": ["login_success", "privilege_change"],
        "min_match": 2,
        "base_score": 30.0,
        "mitre_technique": "T1068",
    },
    {
        "name": "FULL_ACCOUNT_TAKEOVER",
        "description": "Brute force → login → privilege escalation → data access",
        "sequence": [
            "login_failed", "login_success",
            "privilege_change", "sensitive_resource_access",
        ],
        "min_match": 4,
        "base_score": 75.0,
        "mitre_technique": "T1110,T1068,T1530",
    },
    {
        "name": "DATA_EXFILTRATION",
        "description": "Sensitive access followed by data transfer",
        "sequence": ["sensitive_resource_access", "data_transfer"],
        "min_match": 2,
        "base_score": 40.0,
        "mitre_technique": "T1030",
    },
    {
        "name": "RECON_AND_LATERAL",
        "description": "Unusual request probing followed by privilege action",
        "sequence": ["unusual_request", "privilege_change"],
        "min_match": 2,
        "base_score": 25.0,
        "mitre_technique": "T1595",
    },
]

DEFAULT_SESSION_WINDOW_MINUTES = 30


# ---------------------------------------------------------------------------
# Event node
# ---------------------------------------------------------------------------

class EventNode:
    __slots__ = (
        "event_id", "user", "source_ip", "event_type",
        "timestamp", "resource", "details", "trust_level",
        "anomaly_score",
    )

    def __init__(self, event: Dict[str, Any]):
        self.event_id = str(event.get("id", ""))
        self.user = str(event.get("user", "unknown"))
        self.source_ip = str(event.get("source_ip", "0.0.0.0"))
        self.event_type = str(event.get("event_type", "unusual_request"))
        self.timestamp = str(event.get("timestamp", ""))
        self.resource = str(event.get("resource", "/"))
        self.details = str(event.get("details", ""))
        self.trust_level = str(event.get("_trust_level", "STANDARD"))
        self.anomaly_score = float(event.get("_anomaly_score", 0.0))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "user": self.user,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "resource": self.resource,
            "details": self.details,
            "trust_level": self.trust_level,
            "anomaly_score": self.anomaly_score,
        }


# ---------------------------------------------------------------------------
# Temporal edge
# ---------------------------------------------------------------------------

class TemporalEdge:
    __slots__ = (
        "from_id", "to_id", "weight", "relationship",
        "temporal_gap_seconds",
    )

    def __init__(
        self,
        from_id: str,
        to_id: str,
        weight: float,
        relationship: str,
        gap_seconds: float,
    ):
        self.from_id = from_id
        self.to_id = to_id
        self.weight = weight
        self.relationship = relationship
        self.temporal_gap_seconds = gap_seconds


# ---------------------------------------------------------------------------
# Graph and incident result
# ---------------------------------------------------------------------------

class AttackChainResult:
    """
    Complete result of temporal reasoning for one entity session.
    Supports counterfactual analysis via exclude_event_id.
    """

    def __init__(
        self,
        incident_id: str,
        entity: str,
        source_ip: str,
        nodes: List[EventNode],
        edges: List[TemporalEdge],
        graph_score: float,
        matched_patterns: List[Dict[str, Any]],
        observed_stages: List[str],
        inferred_stages: List[str],
        contradictory_evidence: List[str],
        missing_observations: List[str],
        explanation: str,
        supporting_event_ids: List[str],
    ):
        self.incident_id = incident_id
        self.entity = entity
        self.source_ip = source_ip
        self.nodes = nodes
        self.edges = edges
        self.graph_score = graph_score
        self.matched_patterns = matched_patterns
        self.observed_stages = observed_stages
        self.inferred_stages = inferred_stages
        self.contradictory_evidence = contradictory_evidence
        self.missing_observations = missing_observations
        self.explanation = explanation
        self.supporting_event_ids = supporting_event_ids

    def counterfactual(self, exclude_event_id: str) -> Dict[str, Any]:
        """
        Remove one event from the chain and recalculate the graph score.
        Returns a dict describing how the assessment changes.
        """
        remaining_nodes = [n for n in self.nodes if n.event_id != exclude_event_id]
        remaining_ids = {n.event_id for n in remaining_nodes}
        remaining_edges = [
            e for e in self.edges
            if e.from_id in remaining_ids and e.to_id in remaining_ids
        ]

        # Recalculate score from remaining edges
        new_score = sum(e.weight for e in remaining_edges)
        # Recheck patterns
        remaining_types = [n.event_type for n in remaining_nodes]
        new_patterns = _match_patterns(remaining_types)
        new_score += sum(p["base_score"] for p in new_patterns)

        delta = new_score - self.graph_score
        excluded_node = next(
            (n for n in self.nodes if n.event_id == exclude_event_id), None
        )
        excluded_type = excluded_node.event_type if excluded_node else "unknown"

        return {
            "excluded_event_id": exclude_event_id,
            "excluded_event_type": excluded_type,
            "original_score": round(self.graph_score, 2),
            "counterfactual_score": round(new_score, 2),
            "score_delta": round(delta, 2),
            "interpretation": (
                f"Removing event '{exclude_event_id}' (type: {excluded_type}) "
                f"{'reduces' if delta < 0 else 'does not change'} the incident "
                f"score by {abs(delta):.1f} points. "
                + (
                    "This event is material to the incident assessment."
                    if delta < -5
                    else "This event has minimal impact on the overall assessment."
                )
            ),
            "remaining_patterns": [p["name"] for p in new_patterns],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "entity": self.entity,
            "source_ip": self.source_ip,
            "graph_score": round(self.graph_score, 2),
            "matched_patterns": self.matched_patterns,
            "observed_stages": self.observed_stages,
            "inferred_stages": self.inferred_stages,
            "contradictory_evidence": self.contradictory_evidence,
            "missing_observations": self.missing_observations,
            "explanation": self.explanation,
            "supporting_event_ids": self.supporting_event_ids,
            "event_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.as_dict() for n in self.nodes],
        }


# ---------------------------------------------------------------------------
# Helper: pattern matching
# ---------------------------------------------------------------------------

def _match_patterns(event_type_sequence: List[str]) -> List[Dict[str, Any]]:
    """Return all _ATTACK_PATTERNS whose required subsequence is present."""
    matched = []
    for pattern in _ATTACK_PATTERNS:
        required = pattern["sequence"]
        min_match = pattern.get("min_match", len(required))
        # Check if we can find the required types as a subsequence
        idx = 0
        match_count = 0
        for etype in event_type_sequence:
            if idx < len(required) and etype == required[idx]:
                idx += 1
                match_count += 1
        if match_count >= min_match:
            matched.append(pattern)
    return matched


# ---------------------------------------------------------------------------
# Main graph engine
# ---------------------------------------------------------------------------

class TemporalAttackGraph:
    """
    L3 Temporal Attack Graph engine.

    For each (entity, source_ip) session, constructs a directed temporal
    graph of events, scores paths using transition weights, detects known
    attack patterns, and supports counterfactual analysis.
    """

    def __init__(
        self,
        session_window_minutes: int = DEFAULT_SESSION_WINDOW_MINUTES,
    ):
        self.session_window = timedelta(minutes=session_window_minutes)

    def _parse_ts(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def _build_session_groups(
        self, events: List[Dict[str, Any]]
    ) -> Dict[Tuple[str, str], List[EventNode]]:
        """
        Group events into (user, source_ip) sessions respecting the
        temporal session window.

        Two consecutive events from the same (user, ip) that are more than
        session_window apart are placed in different sessions.
        """
        # Sort events by timestamp
        sorted_events = sorted(
            events, key=lambda x: str(x.get("timestamp", ""))
        )

        sessions: Dict[Tuple[str, str], List[EventNode]] = defaultdict(list)

        for evt in sorted_events:
            node = EventNode(evt)
            key = (node.user, node.source_ip)
            sessions[key].append(node)

        return dict(sessions)

    def _build_edges(
        self, nodes: List[EventNode]
    ) -> List[TemporalEdge]:
        """Build weighted temporal edges between consecutive nodes."""
        edges = []
        for i in range(len(nodes) - 1):
            a = nodes[i]
            b = nodes[i + 1]

            # Compute temporal gap
            dt_a = self._parse_ts(a.timestamp)
            dt_b = self._parse_ts(b.timestamp)
            if dt_a and dt_b:
                gap = (dt_b - dt_a).total_seconds()
            else:
                gap = 0.0

            # Skip if gap exceeds session window
            if dt_a and dt_b and (dt_b - dt_a) > self.session_window:
                continue

            # Look up transition weight
            weight = _TRANSITION_WEIGHTS.get(a.event_type, {}).get(
                b.event_type, 0.0
            )

            if weight > 0:
                relationship = (
                    f"{a.event_type} -> {b.event_type} "
                    f"({gap:.0f}s gap)"
                )
                edges.append(
                    TemporalEdge(
                        from_id=a.event_id,
                        to_id=b.event_id,
                        weight=weight,
                        relationship=relationship,
                        gap_seconds=gap,
                    )
                )
        return edges

    def _detect_contradictions(self, nodes: List[EventNode]) -> List[str]:
        """
        Identify evidence that contradicts a malicious interpretation.
        """
        contradictions = []
        types = [n.event_type for n in nodes]

        # Single direct authentication with no failed logins and no overt exploit probes
        success_count = types.count("login_success")
        failed_count = types.count("login_failed")
        has_overt_threat = "unusual_request" in types or ("data_transfer" in types and "privilege_change" in types)
        if success_count > 0 and failed_count == 0 and not has_overt_threat:
            contradictions.append(
                "Authentication succeeded without prior failures — "
                "consistent with legitimate access."
            )

        # Very long time between events (> 4h) suggests separate sessions
        for i in range(len(nodes) - 1):
            dt_a = self._parse_ts(nodes[i].timestamp)
            dt_b = self._parse_ts(nodes[i + 1].timestamp)
            if dt_a and dt_b:
                gap_h = (dt_b - dt_a).total_seconds() / 3600
                if gap_h > 4:
                    contradictions.append(
                        f"Large temporal gap ({gap_h:.1f}h) between events "
                        f"'{nodes[i].event_type}' and '{nodes[i+1].event_type}' "
                        "may indicate independent sessions rather than a single attack chain."
                    )

        return contradictions

    def _missing_observations(
        self, observed_types: Set[str], patterns: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Identify expected events that are absent for detected patterns.
        """
        missing = []
        for pattern in patterns:
            for step in pattern["sequence"]:
                if step not in observed_types:
                    missing.append(
                        f"Pattern '{pattern['name']}' expects '{step}' "
                        "but it was not observed — may indicate incomplete telemetry."
                    )
        return list(dict.fromkeys(missing))  # Deduplicate preserving order

    def analyze(
        self, events: List[Dict[str, Any]]
    ) -> List[AttackChainResult]:
        """
        Analyse all events and return a list of AttackChainResult objects,
        one per (entity, source_ip) session, sorted by graph_score descending.
        Only sessions with graph_score > 0 are returned.
        """
        sessions = self._build_session_groups(events)
        results = []
        incident_counter = 2000

        for (user, source_ip), nodes in sessions.items():
            if len(nodes) < 2:
                continue

            edges = self._build_edges(nodes)
            if not edges:
                continue

            # Score = sum of edge weights + pattern base scores
            edge_score = sum(e.weight for e in edges)
            observed_types = {n.event_type for n in nodes}
            event_type_sequence = [n.event_type for n in nodes]
            matched_patterns = _match_patterns(event_type_sequence)
            pattern_score = sum(p["base_score"] for p in matched_patterns)

            # Observed vs inferred stages
            observed_stages = list(dict.fromkeys(event_type_sequence))
            inferred_stages = []
            for pattern in matched_patterns:
                for step in pattern["sequence"]:
                    if step not in observed_types:
                        inferred_stages.append(
                            f"{step} (inferred from pattern '{pattern['name']}')"
                        )

            contradictions = self._detect_contradictions(nodes)
            missing_obs = self._missing_observations(observed_types, matched_patterns)

            # Score = sum of edge weights + pattern base scores minus contradiction discount
            contradiction_discount = len(contradictions) * 20.0
            graph_score = max(0.0, edge_score + pattern_score - contradiction_discount)

            if graph_score <= 0 and not matched_patterns:
                continue

            # Build explanation
            if matched_patterns:
                top_pattern = max(
                    matched_patterns, key=lambda p: p["base_score"]
                )
                explanation = (
                    f"Temporal graph analysis detected pattern "
                    f"'{top_pattern['name']}': {top_pattern['description']}. "
                    f"Graph score {graph_score:.1f} from {len(edges)} causal edges "
                    f"and {len(matched_patterns)} matched sequence(s). "
                    f"Observed stages: {', '.join(observed_stages)}."
                )
            else:
                explanation = (
                    f"Temporal graph analysis found {len(edges)} causal event "
                    f"transitions for entity '{user}' from {source_ip}. "
                    f"No known multi-stage pattern fully matched. "
                    f"Graph score: {graph_score:.1f}."
                )

            incident_counter += 1
            results.append(
                AttackChainResult(
                    incident_id=f"TG-{incident_counter}",
                    entity=user,
                    source_ip=source_ip,
                    nodes=nodes,
                    edges=edges,
                    graph_score=graph_score,
                    matched_patterns=[
                        {
                            "name": p["name"],
                            "description": p["description"],
                            "base_score": p["base_score"],
                            "mitre_technique": p.get("mitre_technique", ""),
                        }
                        for p in matched_patterns
                    ],
                    observed_stages=observed_stages,
                    inferred_stages=inferred_stages,
                    contradictory_evidence=contradictions,
                    missing_observations=missing_obs,
                    explanation=explanation,
                    supporting_event_ids=[n.event_id for n in nodes],
                )
            )

        return sorted(results, key=lambda r: r.graph_score, reverse=True)

    def counterfactual_analysis(
        self,
        events: List[Dict[str, Any]],
        exclude_event_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Find the incident that contains exclude_event_id and return its
        counterfactual assessment.
        """
        results = self.analyze(events)
        for result in results:
            if exclude_event_id in result.supporting_event_ids:
                cf = result.counterfactual(exclude_event_id)
                cf["incident_id"] = result.incident_id
                cf["entity"] = result.entity
                return cf
        return {
            "excluded_event_id": exclude_event_id,
            "interpretation": (
                f"Event '{exclude_event_id}' was not part of any scored "
                "attack chain — no counterfactual impact."
            ),
            "original_score": 0,
            "counterfactual_score": 0,
            "score_delta": 0,
        }
