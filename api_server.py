"""
api_server.py — a minimal, real FastAPI service wrapping the existing
detection pipeline, turning it from "a script you run" into "a
service other tools can integrate with."

Design principle: reuses the exact same detection, quorum, baseline,
suppression, audit-trail, and MITRE-mapping modules already built and
tested - this is a thin HTTP layer over real logic, not a
reimplementation. State (the adaptive baseline and the quorum
coordinator's pending evidence) lives in memory for the lifetime of
the running server process, exactly mirroring how a real long-running
service would work, rather than reloading everything from disk on
every request.

Run with:
    uvicorn api_server:app --reload
"""

import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import detector
from rolling_baseline import RollingBaseline
from quorum import QuorumCoordinator
from feedback import is_suppressed
from audit_trail import build_audit_record, save_audit_record, load_audit_records, verify_chain
from confidence_scoring import compute_confidence_score, rank_alerts_by_confidence
from flood_detection import FloodDetector, apply_flood_awareness, compute_window_rarity
from mitre_mapping import annotate_summary_with_attack

app = FastAPI(title="APIS - Adaptive Protective Immune System", version="1.0")


class TrafficRow(BaseModel):
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = 0
    bytes: int
    ssh_banner: Optional[str] = ""


class IngestResponse(BaseModel):
    rows_processed: int
    raw_signals: int
    newly_confirmed: list
    suppressed: list


_state = {
    "rolling_baseline": None,
    "coordinator": None,
    "alerts_by_pair": {},
    "flood_detector": None,
    "flood_active": False,
    "flood_zscore": None,
}


def _get_state():
    if _state["rolling_baseline"] is None:
        static_baseline = detector.load_baseline() if os.path.exists(detector.BASELINE_PATH) else {}
        _state["rolling_baseline"] = RollingBaseline(initial_baseline=static_baseline)
        _state["coordinator"] = QuorumCoordinator(
            active_detector_types=detector.ACTIVE_DETECTOR_TYPES,
            type_diversity_excluded_types=detector.QUORUM_EXCLUDED_SIGNALS,
        )
        _state["flood_detector"] = FloodDetector()
    return _state


@app.post("/ingest/flow", response_model=IngestResponse)
def ingest_flow(rows: list[TrafficRow]):
    """
    Accepts a batch of network-flow rows, runs them through the real
    detection pipeline, and returns any NEWLY confirmed detections
    from this call - evidence accumulates across separate calls via
    the persistent, in-memory quorum coordinator, exactly like the
    CLI's --state-file does across separate runs.
    """
    state = _get_state()
    rolling = state["rolling_baseline"]
    coordinator = state["coordinator"]

    parsed_rows = []
    for r in rows:
        parsed_rows.append({
            "timestamp": datetime.fromisoformat(r.timestamp),
            "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "dst_port": r.dst_port, "bytes": r.bytes, "ssh_banner": r.ssh_banner or "",
        })

    baseline_snapshot = rolling.export()
    alerts = detector.detect(parsed_rows, baseline_snapshot)

    # Flood detection: each ingest call is treated as one real-time
    # window - a documented adversarial evasion pattern (MITRE T1562,
    # Impair Defenses) is deliberately flooding a system with noise to
    # bury a real signal. This must be checked BEFORE the window's own
    # count can influence the baseline (see FloodDetector's own
    # poisoning-safety guarantee).
    is_flood, flood_zscore = state["flood_detector"].observe_window(len(alerts))
    state["flood_active"] = is_flood
    state["flood_zscore"] = flood_zscore

    for alert in alerts:
        state["alerts_by_pair"].setdefault((alert["src_ip"], alert["dst_ip"]), []).append(alert)

    newly_confirmed = []
    suppressed_list = []
    pending_confirmations = []  # collected first, so rarity can be computed across the WHOLE window before any record is saved

    def on_quorum(src, dst, summary, path):
        suppressed = is_suppressed(src, dst, summary, path)
        action = "SUPPRESSED" if suppressed else ("AUTONOMOUS_ACTION_OK" if path == "type_diversity" else "ESCALATE_FOR_REVIEW")
        pending_confirmations.append({
            "src": src, "dst": dst, "summary": summary, "path": path,
            "action": action, "suppressed": suppressed,
        })

    coordinator.on_quorum_reached = on_quorum
    alerted_keys = set()
    for alert in alerts:
        ts = datetime.fromisoformat(alert["timestamp"])
        coordinator.record_batch(alert["signals"], alert["src_ip"], alert["dst_ip"], timestamp=ts)
        alerted_keys.add((alert["src_ip"], alert["dst_ip"], alert["timestamp"]))

    # Rarity is computed across every confirmation that occurred in
    # THIS SAME window, non-suppressed only - a suppressed pattern is
    # already known-safe and isn't part of the "is this an outlier
    # worth protecting" question at all.
    unsuppressed = [c for c in pending_confirmations if not c["suppressed"]]
    rarity_flags = compute_window_rarity([(c["summary"], c["path"]) for c in unsuppressed])
    rarity_by_pair = {(c["src"], c["dst"]): is_rare for c, is_rare in zip(unsuppressed, rarity_flags)}

    for c in pending_confirmations:
        flood_context = {
            "active": state["flood_active"],
            "zscore": state["flood_zscore"],
            "is_rare_in_window": rarity_by_pair.get((c["src"], c["dst"]), True),
        }
        record = build_audit_record(
            src=c["src"], dst=c["dst"], summary=c["summary"], path=c["path"], action=c["action"],
            contributing_alerts=state["alerts_by_pair"].get((c["src"], c["dst"]), []),
            baseline=baseline_snapshot, suppressed=c["suppressed"],
            mitre_techniques=annotate_summary_with_attack(c["summary"]),
            flood_context=flood_context,
        )
        save_audit_record(record)
        if c["suppressed"]:
            suppressed_list.append({"src": c["src"], "dst": c["dst"], "summary": c["summary"], "path": c["path"]})
        else:
            newly_confirmed.append({"src": c["src"], "dst": c["dst"], "summary": c["summary"],
                                     "path": c["path"], "action": c["action"]})

    for row in parsed_rows:
        key = (row["src_ip"], row["dst_ip"], row["timestamp"].isoformat())
        if key not in alerted_keys and row["src_ip"] in baseline_snapshot:
            rolling.observe_safe(row)

    return IngestResponse(
        rows_processed=len(parsed_rows),
        raw_signals=len(alerts),
        newly_confirmed=newly_confirmed,
        suppressed=suppressed_list,
    )


def _score_with_flood_awareness(record):
    score, breakdown = compute_confidence_score(record)
    flood_ctx = record.get("flood_context")
    if flood_ctx:
        score, breakdown = apply_flood_awareness(
            score, breakdown,
            is_flood_active=flood_ctx.get("active", False),
            flood_zscore=flood_ctx.get("zscore"),
            is_rare_in_window=flood_ctx.get("is_rare_in_window", True),
        )
    return score, breakdown


@app.get("/alerts")
def get_alerts(action: Optional[str] = None, limit: int = 50, sort_by_confidence: bool = True):
    """Returns confirmed detections from the real audit trail,
    optionally filtered by action, with a confidence_score attached
    to each - a real triage-queue ordering rather than treating every
    confirmed detection as equally urgent. Scores account for whether
    a flood-evasion condition (MITRE T1562) was active when each
    detection actually occurred. Set sort_by_confidence=false to see
    them in plain chronological order instead."""
    records = load_audit_records()
    if action:
        records = [r for r in records if r["action"] == action]

    scored_records = []
    for r in records:
        score, breakdown = _score_with_flood_awareness(r)
        scored_records.append({**r, "confidence_score": score, "confidence_breakdown": breakdown})

    if sort_by_confidence:
        scored_records = sorted(scored_records, key=lambda r: r["confidence_score"], reverse=True)

    return {"count": len(scored_records), "alerts": scored_records[:limit]}


@app.get("/alerts/{alert_index}")
def get_alert_detail(alert_index: int):
    """Returns the FULL structured provenance record for one specific
    alert, by its position in the audit trail, including its
    flood-aware confidence score and breakdown."""
    records = load_audit_records()
    if alert_index < 0 or alert_index >= len(records):
        raise HTTPException(status_code=404, detail="Alert not found")
    record = records[alert_index]
    score, breakdown = _score_with_flood_awareness(record)
    record["confidence_score"] = score
    record["confidence_breakdown"] = breakdown
    return record


@app.get("/health")
def health():
    return {"status": "ok", "service": "APIS - Adaptive Protective Immune System"}


class AgentEvent(BaseModel):
    time: float
    agent_id: str
    tool: str
    action: str
    session_id: Optional[str] = ""
    target: Optional[str] = ""
    input_provenance: Optional[str] = "unknown"
    result_size: Optional[int] = 0
    success: Optional[bool] = True
    external: Optional[bool] = False


@app.post("/ingest/agent", response_model=IngestResponse)
def ingest_agent(events: list[AgentEvent]):
    """
    Layer 9: accepts a batch of AI-agent tool-call events and runs them
    through the same detection, quorum, suppression, audit-trail and
    MITRE-mapping path every other domain uses.

    The pair identity is (durable agent identity -> target touched),
    mirroring (src -> dst) on the network side. Note the durable
    identity is never the session: agents are ephemeral, and binding a
    baseline to an instance is the documented reason agent baselines
    fail.
    """
    from agent_baseline import parse_agent_event, load_agent_baseline
    from agent_detector import AgentBehaviorDetector, AGENT_SIGNAL_TYPES

    state = _get_state()
    if state.get("agent_baseline") is None:
        state["agent_baseline"] = load_agent_baseline()
        state["agent_coordinator"] = QuorumCoordinator(active_detector_types=AGENT_SIGNAL_TYPES)
        state["agent_events_by_pair"] = {}

    baseline = state["agent_baseline"]
    coordinator = state["agent_coordinator"]
    detector_instance = AgentBehaviorDetector(baseline)

    parsed = [parse_agent_event(e.model_dump()) for e in events]
    parsed = [p for p in parsed if p is not None]

    newly_confirmed = []
    suppressed_list = []
    signal_count = 0

    for event in parsed:
        signals = detector_instance.process_event(event)
        if not signals:
            continue
        signal_count += len(signals)
        pair = (event["agent_id"], event["target"] or "(no-target)")
        enriched = dict(event)
        enriched["signals"] = signals
        enriched["timestamp"] = datetime.fromtimestamp(event["time"]).isoformat()
        state["agent_events_by_pair"].setdefault(pair, []).append(enriched)

    pending = []

    def on_quorum(src, dst, summary, path):
        pending.append((src, dst, summary, path))

    coordinator.on_quorum_reached = on_quorum

    # Feed the coordinator in event order so quorum reflects real timing.
    replay = AgentBehaviorDetector(baseline)
    for event in parsed:
        signals = replay.process_event(event)
        if not signals:
            continue
        coordinator.record_batch(
            signals, event["agent_id"], event["target"] or "(no-target)",
            timestamp=datetime.fromtimestamp(event["time"]),
        )

    for src, dst, summary, path in pending:
        suppressed = is_suppressed(src, dst, summary, path)
        action = "SUPPRESSED" if suppressed else (
            "AUTONOMOUS_ACTION_OK" if path == "type_diversity" else "ESCALATE_FOR_REVIEW")
        save_audit_record(build_audit_record(
            src=src, dst=dst, summary=summary, path=path, action=action,
            contributing_alerts=state["agent_events_by_pair"].get((src, dst), []),
            baseline=baseline, suppressed=suppressed,
            mitre_techniques=annotate_summary_with_attack(summary),
        ))
        entry = {"src": src, "dst": dst, "summary": summary, "path": path, "action": action}
        (suppressed_list if suppressed else newly_confirmed).append(entry)

    return IngestResponse(
        rows_processed=len(parsed),
        raw_signals=signal_count,
        newly_confirmed=newly_confirmed,
        suppressed=suppressed_list,
    )


@app.get("/audit/verify")
def verify_audit_trail():
    """
    Verifies the tamper-evident hash chain covering every recorded
    decision - the real, current regulatory requirement this responds
    to: EU AI Act Article 12 (enforceable since August 2, 2026) demands
    logs for autonomous, high-risk AI decisions be more than merely
    present. This walks the entire chain and recomputes every hash
    from scratch; any past alteration, deletion, or reordering is
    detected and precisely located.
    """
    intact, broken_at_index, total = verify_chain()
    return {
        "intact": intact,
        "total_records": total,
        "broken_at_index": broken_at_index,
        "message": (
            "Audit trail is fully intact - no record has been altered, deleted, or reordered since it was written."
            if intact else
            f"TAMPERING DETECTED at record index {broken_at_index}. Everything before this index is verified intact."
        ),
    }
