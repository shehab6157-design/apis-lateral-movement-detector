"""
cross_signal_correlator.py — Layer 8 extension: cross-domain
correlation between network-flow evidence and Windows credential-theft
evidence.

Biological basis: the same principle already used by
overwhelm.py (correlating multiple independent weak signals from
different conversations into one higher-confidence threat) applied
across data SOURCES rather than just across conversations - a real
hive's threat response integrates multiple independent sensory
channels (chemical, vibrational, visual) rather than trusting any one
channel alone; two independent detection domains agreeing on the same
entity within a short window is much stronger evidence than either
alone.

HONEST SCOPE: this module is generic - it works on whatever device
identifier both signal sources share (IP address or computer name).
On the real LANL dataset, flows.txt and auth.txt already share the
same computer-name identifiers, making real evaluation possible. This
project's own live Docker lab is IP-only network traffic with no
Windows authentication data source, so a live demo of this specific
capability would require adding one - stated plainly, not implied to
already work end-to-end live.
"""

from datetime import timedelta

CORRELATION_WINDOW_MINUTES = 30


def correlate(flow_confirmations, auth_confirmations, window_minutes=CORRELATION_WINDOW_MINUTES):
    """
    flow_confirmations: dict of (src, dst) -> (summary, path, timestamp)
        - from detector.py's apply_quorum()/refine_actions() output,
          extended with a timestamp of when the pair confirmed.
    auth_confirmations: dict of (src_computer, dst_computer) -> (summary, timestamp)
        - from auth_detector.py's ChemicalMimicryDetector output.

    Returns a dict of (src, dst) -> correlation info for every pair
    that appears in BOTH domains within window_minutes of each other -
    the highest-confidence tier this system can produce, since it
    represents two fully independent data sources agreeing.
    """
    correlated = {}
    window = timedelta(minutes=window_minutes)

    for pair, (flow_summary, flow_path, flow_ts) in flow_confirmations.items():
        auth_match = auth_confirmations.get(pair)
        if auth_match is None:
            continue
        auth_summary, auth_ts = auth_match
        if abs((flow_ts - auth_ts).total_seconds()) <= window.total_seconds():
            correlated[pair] = {
                "flow_summary": flow_summary,
                "flow_path": flow_path,
                "auth_summary": auth_summary,
                "time_delta_seconds": abs((flow_ts - auth_ts).total_seconds()),
                "confidence": "CROSS_DOMAIN_CORRELATED",
            }

    return correlated


def explain_correlation(pair, info):
    src, dst = pair
    return (f"[CROSS-DOMAIN CORRELATION] {src} -> {dst}: network evidence "
            f"({info['flow_summary']}, path={info['flow_path']}) AND authentication "
            f"evidence ({info['auth_summary']}) both confirmed within "
            f"{info['time_delta_seconds']:.0f}s of each other - two independent "
            f"data sources agreeing. Highest-confidence tier this system produces.")


# ---------------------------------------------------------------------------
# Three-domain correlation (network + identity + agent)
#
# Added after Layer 9 (Agent Behavior Detection) became a real third
# detection domain. Current 2026 agent-security research names this
# specifically as the open gap: "no single control layer sees the full
# sequence... the real gap is cross-surface correlation." Two domains
# agreeing was already the highest-confidence tier this system produced
# (40.0% precision on real LANL data versus ~2% for either alone);
# three independent domains agreeing is strictly stronger evidence.
#
# The agent domain's pair identity is (durable agent identity -> target),
# which is NOT an IP or computer name. So correlation across all three
# cannot assume a shared identifier the way flow and auth can, and this
# is handled explicitly below rather than silently producing empty
# results - a mismatch that would otherwise look like "no correlations
# found" instead of "these domains do not share an identifier."
# ---------------------------------------------------------------------------

def correlate_three_domains(flow_confirmations, auth_confirmations, agent_confirmations,
                            identity_resolver=None,
                            window_minutes=CORRELATION_WINDOW_MINUTES):
    """
    flow_confirmations:  (src, dst) -> (summary, path, timestamp)
    auth_confirmations:  (src, dst) -> (summary, timestamp)
    agent_confirmations: (agent_id, target) -> (summary, path, timestamp)

    identity_resolver: optional callable mapping an agent_id to the host
        identifier the flow/auth domains use. Required because an agent's
        durable identity (e.g. "claude-code:some-workspace") is not the
        same namespace as a computer name or IP. Without it, agent
        correlation is reported as UNAVAILABLE rather than silently empty
        - the honest failure mode.

    Returns a dict of pair -> correlation info, with a "domains" list
    naming exactly which sources agreed.
    """
    window = timedelta(minutes=window_minutes)

    # Start from the existing, already-evaluated two-domain result so
    # this extension never weakens what was measured on real data.
    correlated = correlate(flow_confirmations, auth_confirmations, window_minutes)
    for info in correlated.values():
        info["domains"] = ["flow", "auth"]

    if not agent_confirmations:
        return correlated

    if identity_resolver is None:
        for info in correlated.values():
            info["agent_domain"] = "UNAVAILABLE - no identity_resolver supplied"
        return correlated

    # Map each agent confirmation onto the host namespace the other two
    # domains share, then look for agreement within the same window.
    for (agent_id, target), agent_value in agent_confirmations.items():
        host = identity_resolver(agent_id)
        if host is None:
            continue
        agent_summary = agent_value[0]
        agent_ts = agent_value[-1]

        for pair, info in correlated.items():
            if pair[0] != host and pair[1] != host:
                continue
            flow_ts = flow_confirmations[pair][2]
            if abs((flow_ts - agent_ts).total_seconds()) <= window.total_seconds():
                info["agent_summary"] = agent_summary
                info["agent_target"] = target
                info["domains"] = ["flow", "auth", "agent"]
                info["confidence"] = "TRI_DOMAIN_CORRELATED"

    return correlated


def explain_tri_correlation(pair, info):
    src, dst = pair
    domains = info.get("domains", [])
    if "agent" not in domains:
        return explain_correlation(pair, info)
    return (f"[TRI-DOMAIN CORRELATION] {src} -> {dst}: network evidence "
            f"({info['flow_summary']}), authentication evidence ({info['auth_summary']}) "
            f"AND agent-behavior evidence ({info['agent_summary']} on "
            f"{info['agent_target']}) all confirmed within the same window. Three "
            f"structurally independent detection domains agreeing - the strongest "
            f"evidence tier this system produces.")
