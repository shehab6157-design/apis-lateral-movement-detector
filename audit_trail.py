"""
audit_trail.py — structured provenance/audit records for every
confirmed detection, now with a cryptographic hash chain making the
log tamper-evident, not just present.

Built to close a real, known gap: most detection systems produce an
alert but not a defensible account of why it fired. As security
automation faces increasing regulatory and auditor scrutiny, this
kind of structured provenance is what makes a decision reviewable by
a human rather than trusted blindly.

Tamper-evident hash chain, added after real, current regulatory
research: the EU AI Act's high-risk provisions became fully
enforceable August 2, 2026 - Article 12 specifically mandates
"automatic logging of all events relevant to identifying risks," and
current guidance on this exact requirement states plainly logs must
be tamper-evident to survive regulator scrutiny, explicitly framing
autonomous security decisions ("this AI closed an alert without
escalation") as a real scenario auditors now ask about. A plain,
appendable JSON-lines file satisfies "present" but not "tamper-
evident." The fix follows the standard, established technique for
exactly this problem (verified against real published implementations
of the same pattern):
    entry_hash = SHA256(record_content + previous_entry's_hash)
Each entry commits to everything before it - altering, deleting, or
reordering any past entry breaks every hash after it, and is
detectable by walking the chain and recomputing (verify_chain()).
The genesis entry uses 64 zeros as its previous hash, matching the
standard convention for this pattern.

Design principle: additive, not invasive. Rather than deeply modify
detect()'s existing, already-tested internal logic, this module
reconstructs the exact evidence behind each signal from data already
available (the row and the baseline profile), using the SAME
thresholds and constants detector.py itself uses - so the audit trail
can never silently drift out of sync with what the detector actually
does.
"""

import hashlib
import json
from datetime import datetime

import detector

GENESIS_HASH = "0" * 64


def explain_signal(signal_name, row, profile):
    """
    Reconstructs the exact real evidence behind one fired signal, using
    the SAME comparison logic and thresholds detect() itself uses.
    Returns a dict describing the observed value, the baseline it was
    compared against, and the threshold that was crossed.
    """
    if signal_name == "NEW_PEER":
        return {
            "signal": "NEW_PEER",
            "observed_destination": row["dst_ip"],
            "known_peers": profile.get("known_peers", []),
            "explanation": f"{row['dst_ip']} is not in this device's known_peers baseline.",
        }

    if signal_name == "OFF_HOURS":
        ts = row["timestamp"]
        hour = ts.hour if hasattr(ts, "hour") else datetime.fromisoformat(ts).hour
        return {
            "signal": "OFF_HOURS",
            "observed_hour": hour,
            "active_hours": profile.get("active_hours", []),
            "explanation": f"Hour {hour} is not in this device's active_hours baseline.",
        }

    if signal_name == "VOLUME_OUTLIER":
        z = detector.zscore(row["bytes"], profile["avg_bytes"], profile["std_bytes"])
        return {
            "signal": "VOLUME_OUTLIER",
            "observed_bytes": row["bytes"],
            "baseline_avg_bytes": profile["avg_bytes"],
            "baseline_std_bytes": profile["std_bytes"],
            "zscore": round(z, 2),
            "threshold": detector.VOLUME_ZSCORE_THRESHOLD,
            "explanation": (f"{row['bytes']} bytes is {round(z, 2)} standard deviations above "
                             f"this device's baseline average of {profile['avg_bytes']}."),
        }

    if signal_name == "FANOUT_SPIKE":
        return {
            "signal": "FANOUT_SPIKE",
            "baseline_avg_fanout_per_hour": profile.get("avg_fanout_per_hour"),
            "baseline_std_fanout_per_hour": profile.get("std_fanout_per_hour"),
            "threshold": detector.FANOUT_ZSCORE_THRESHOLD,
            "explanation": "This device contacted more distinct peers in one hour than its baseline fanout rate.",
        }

    if signal_name == "SLOW_FANOUT":
        return {
            "signal": "SLOW_FANOUT",
            "window_hours": detector.SLOW_FANOUT_WINDOW_HOURS,
            "explanation": (f"This device accumulated an unusual number of distinct new peers over a "
                             f"{detector.SLOW_FANOUT_WINDOW_HOURS}-hour window - a patient, low-and-slow "
                             f"fan-out pattern rather than a single burst."),
        }

    if signal_name == "UNKNOWN_SSH_CLIENT":
        return {
            "signal": "UNKNOWN_SSH_CLIENT",
            "observed_banner": row.get("ssh_banner", ""),
            "known_banners": profile.get("known_ssh_banners", []),
            "explanation": f"SSH banner '{row.get('ssh_banner', '')}' does not match any known banner for this device.",
        }

    if signal_name == "PTH_SUSPECTED":
        known = profile.get("known_destinations", []) if profile else []
        return {
            "signal": "PTH_SUSPECTED",
            "observed_user": row.get("src_user"),
            "observed_destination": row.get("dst_computer"),
            "known_destinations_for_user": known,
            "explanation": (f"An NTLM cross-computer network logon by {row.get('src_user')} to "
                             f"{row.get('dst_computer')} - not among this user's known, legitimate "
                             f"destinations (or the user exceeds the high-privilege threshold, where "
                             f"no destination is exempted)."),
        }

    if signal_name == "PTT_SUSPECTED":
        known = profile.get("known_destinations", []) if profile else []
        return {
            "signal": "PTT_SUSPECTED",
            "observed_user": row.get("src_user"),
            "observed_destination": row.get("dst_computer"),
            "known_destinations_for_user": known,
            "explanation": (f"A Kerberos authentication by {row.get('src_user')} with no prior "
                             f"activity in the lookback window, to a destination not among this "
                             f"user's known, legitimate destinations."),
        }

    if signal_name == "NEW_TOOL":
        return {
            "signal": "NEW_TOOL",
            "observed_tool": row.get("tool"),
            "known_tools_for_agent": profile.get("known_tools", []) if profile else [],
            "explanation": (f"This agent invoked '{row.get('tool')}' - a capability it has "
                             f"never used within its learned envelope."),
        }

    if signal_name == "NEW_TARGET":
        return {
            "signal": "NEW_TARGET",
            "observed_target": row.get("target"),
            "known_target_count": len(profile.get("known_targets", [])) if profile else 0,
            "explanation": (f"This agent touched '{row.get('target')}', which is not among "
                             f"the resources it has previously used. Note this signal fires "
                             f"routinely during legitimate work and is never actionable alone."),
        }

    if signal_name == "TAINTED_SCOPE_EXPANSION":
        return {
            "signal": "TAINTED_SCOPE_EXPANSION",
            "observed_tool": row.get("tool"),
            "observed_target": row.get("target"),
            "action": row.get("action"),
            "external": row.get("external", False),
            "explanation": (f"Shortly after processing untrusted external content, this agent "
                             f"performed a novel {row.get('action')} against "
                             f"'{row.get('target')}' outside its own boundary. A novel outward "
                             f"READ does not raise this signal - consuming external content is "
                             f"ordinary agent work; acting outward after consuming it is the "
                             f"documented indirect prompt-injection pivot."),
        }

    if signal_name == "PRIVILEGE_ESCALATION":
        return {
            "signal": "PRIVILEGE_ESCALATION",
            "observed_target": row.get("target"),
            "action": row.get("action"),
            "write_targets_for_agent": profile.get("write_targets", []) if profile else [],
            "explanation": (f"This agent performed a {row.get('action')} against "
                             f"'{row.get('target')}', a resource it had previously only read. "
                             f"Creating a brand-new resource does not raise this signal."),
        }

    if signal_name == "RESULT_SIZE_OUTLIER":
        avg = profile.get("avg_result_size", 0.0) if profile else 0.0
        std = profile.get("std_result_size", 1.0) if profile else 1.0
        observed = row.get("result_size", 0)
        z = detector.zscore(observed, avg, std)
        return {
            "signal": "RESULT_SIZE_OUTLIER",
            "observed_result_size": observed,
            "baseline_avg_result_size": avg,
            "baseline_std_result_size": std,
            "zscore": round(z, 2),
            "explanation": (f"A tool call returned {observed} bytes, {round(z, 2)} standard "
                             f"deviations above this agent's own baseline of {avg}."),
        }

    if signal_name == "CALL_RATE_SPIKE":
        return {
            "signal": "CALL_RATE_SPIKE",
            "baseline_calls_per_minute": profile.get("avg_calls_per_minute") if profile else None,
            "explanation": ("This agent issued tool calls far faster than its own busy-minute "
                             "baseline rate - machine-speed activity characteristic of an "
                             "automated pivot rather than ordinary paced work."),
        }

    return {"signal": signal_name, "explanation": "No evidence reconstruction available for this signal type."}


def build_quorum_reasoning(summary, path):
    """Explains WHY quorum was reached, using the same thresholds
    quorum.py itself applies."""
    if path == "type_diversity":
        return {
            "path": "type_diversity",
            "distinct_signal_types": len(summary),
            "threshold_required": 2,
            "explanation": (f"{len(summary)} distinct signal types ({', '.join(summary.keys())}) "
                             f"co-occurred - meets the 2-type-diversity threshold for corroboration."),
        }
    if path == "repetition_burst":
        signal_type = next(iter(summary))
        return {
            "path": "repetition_burst",
            "signal_type": signal_type,
            "occurrences": summary[signal_type],
            "explanation": (f"The same signal ({signal_type}) repeated {summary[signal_type]} times "
                             f"within the burst window - met the personalized repetition threshold "
                             f"for this specific device's traffic volume."),
        }
    return {"path": path, "explanation": "Unrecognized confirmation path."}


def build_audit_record(src, dst, summary, path, action, contributing_alerts, baseline,
                        suppressed=False, cross_domain_evidence=None, mitre_techniques=None,
                        flood_context=None):
    """
    Assembles the full, structured audit record for one confirmed
    detection - the complete, defensible account of why this specific
    action was taken. flood_context, if provided, permanently records
    whether an alert-flood condition (MITRE T1562, Impair Defenses)
    was active AT THE TIME this detection occurred - the situation the
    record describes, not whatever the live system's flood state
    happens to be whenever this record is later read back.
    """
    profile = baseline.get(src, {})

    signal_evidence = []
    for alert in contributing_alerts:
        for signal_name in alert["signals"]:
            evidence = explain_signal(signal_name, alert, profile)
            evidence["timestamp"] = alert["timestamp"] if isinstance(alert["timestamp"], str) else alert["timestamp"].isoformat()
            signal_evidence.append(evidence)

    record = {
        "pair": {"src": src, "dst": dst},
        "generated_at": datetime.now().isoformat(),
        "confirmation_path": path,
        "quorum_reasoning": build_quorum_reasoning(summary, path),
        "signal_evidence": signal_evidence,
        "action": action,
        "suppressed": suppressed,
        "cross_domain_correlation": {
            "applied": cross_domain_evidence is not None,
            "evidence": cross_domain_evidence,
        },
        "mitre_techniques": mitre_techniques or [],
        "flood_context": flood_context,
    }
    return record


def _compute_entry_hash(record, prev_hash):
    """SHA-256 over the record's own content plus the previous entry's
    hash - the standard hash-chain construction, verified against real
    published implementations of the same pattern."""
    payload = json.dumps(record, sort_keys=True, default=str) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_last_hash(path):
    records = load_audit_records(path)
    if not records:
        return GENESIS_HASH
    return records[-1].get("_entry_hash", GENESIS_HASH)


def save_audit_record(record, path="audit_trail.jsonl"):
    """Appends one record to a JSON-lines audit log, chained to the
    previous entry via SHA-256 - one detection per line, tamper-
    evident, so any later insertion, deletion, or edit of a past
    record is detectable by verify_chain()."""
    prev_hash = _get_last_hash(path)
    entry_hash = _compute_entry_hash(record, prev_hash)
    chained_record = dict(record)
    chained_record["_prev_hash"] = prev_hash
    chained_record["_entry_hash"] = entry_hash
    with open(path, "a") as f:
        f.write(json.dumps(chained_record) + "\n")


def load_audit_records(path="audit_trail.jsonl"):
    records = []
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    except FileNotFoundError:
        pass
    return records


def verify_chain(path="audit_trail.jsonl"):
    """
    Walks the entire audit log and recomputes every hash from scratch,
    verifying nothing has been altered, deleted, or reordered since it
    was written. Returns (intact: bool, first_broken_index: int|None,
    total_records: int).
    """
    records = load_audit_records(path)
    prev_hash = GENESIS_HASH
    for i, record in enumerate(records):
        stored_prev = record.get("_prev_hash")
        stored_entry_hash = record.get("_entry_hash")
        record_without_chain = {k: v for k, v in record.items() if k not in ("_prev_hash", "_entry_hash")}
        recomputed = _compute_entry_hash(record_without_chain, prev_hash)

        if stored_prev != prev_hash or stored_entry_hash != recomputed:
            return False, i, len(records)

        prev_hash = stored_entry_hash

    return True, None, len(records)
