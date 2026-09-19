"""
mitre_mapping.py — maps this project's detection signals and defensive
layers to the industry-standard MITRE ATT&CK (adversary technique) and
MITRE D3FEND (defensive countermeasure) frameworks.

Deliberately uses BOTH frameworks rather than forcing everything into
ATT&CK: ATT&CK catalogs ADVERSARY behavior (what an attacker does),
while D3FEND catalogs DEFENDER countermeasures (what a defense does).
Signals produced by detect() describe attacker behavior -> ATT&CK.
Defensive layers (hygiene, containment, quorum) describe defender
actions/strategy -> D3FEND, or in one case, no formal ID at all.
Forcing a defensive layer into an ATT&CK ID would be a category error,
even though it's a common shortcut - getting this wrong undermines
credibility with anyone who actually knows the frameworks.

Every mapping below was checked against the current MITRE ATT&CK
Enterprise matrix (attack.mitre.org) before being included. Two
mappings are explicitly marked ANALOGOUS rather than literal: ATT&CK's
existing Masquerading sub-techniques are defined for file/resource
naming, not protocol banners, so the banner-spoofing case cites the
parent technique (T1036) rather than overclaiming a specific
sub-technique that doesn't quite fit the described behavior.
"""

SIGNAL_ATTACK_MAPPING = {
    "NEW_PEER": {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "TA0008 - Lateral Movement",
        "rationale": ("A device establishing an SSH session with a peer it has never "
                      "contacted before is the base signal for SSH-based lateral "
                      "movement - the exact ATT&CK sub-technique for SSH."),
        "confidence": "verified against attack.mitre.org",
    },
    "FANOUT_SPIKE": {
        "technique_id": "T1021.004 / T1018",
        "technique_name": "Remote Services: SSH / Remote System Discovery",
        "tactic": "TA0008 - Lateral Movement / TA0007 - Discovery",
        "rationale": ("Rapidly contacting several new hosts within an hour combines "
                      "two adjacent techniques: the connections themselves are "
                      "T1021.004, but the RATE of touching many new systems is "
                      "characteristic of the discovery/reconnaissance phase (T1018) "
                      "that typically precedes or accompanies lateral movement."),
        "confidence": "verified against attack.mitre.org",
    },
    "SLOW_FANOUT": {
        "technique_id": "T1021.004 / T1018",
        "technique_name": "Remote Services: SSH / Remote System Discovery",
        "tactic": "TA0008 - Lateral Movement / TA0007 - Discovery",
        "rationale": ("Same underlying techniques as FANOUT_SPIKE, detecting the "
                      "same behavior deliberately spread over a longer window to "
                      "evade hourly-rate detection - the evasion attempt doesn't "
                      "change which techniques are in play, only the timing."),
        "confidence": "verified against attack.mitre.org",
    },
    "VOLUME_OUTLIER": {
        "technique_id": "T1570",
        "technique_name": "Lateral Tool Transfer",
        "tactic": "TA0008 - Lateral Movement",
        "rationale": ("An unusually large data transfer over an established internal "
                      "SSH session is the traffic-level signature of copying tools "
                      "or files between compromised hosts - ATT&CK catalogs this "
                      "specifically as Lateral Tool Transfer."),
        "confidence": "verified against attack.mitre.org",
    },
    "UNKNOWN_SSH_CLIENT": {
        "technique_id": "T1021.004 (execution) / T1036 (evasion, when banner is spoofed)",
        "technique_name": "Remote Services: SSH / Masquerading",
        "tactic": "TA0008 - Lateral Movement / TA0005 - Defense Evasion",
        "rationale": ("A device using a different SSH client than its own established "
                      "baseline suggests non-native tooling (e.g. a scripted attack "
                      "tool) being used for T1021.004. If that tool additionally "
                      "fakes its banner to match the expected client, that specific "
                      "evasion behavior applies the concept of Masquerading (T1036). "
                      "NOTE: ATT&CK's existing Masquerading sub-techniques (e.g. "
                      "T1036.005) are defined for file/resource naming, not protocol "
                      "banners, so this cites the parent technique as an ANALOGOUS "
                      "application, not a literal sub-technique match - verified via "
                      "a real banner-spoofing test in this project, not assumed."),
        "confidence": "T1021.004 verified; T1036 application is explicitly analogous",
    },
    "GUARD_BLOCKED_PORT": {
        "technique_id": "T1021",
        "technique_name": "Remote Services (parent technique)",
        "tactic": "TA0008 - Lateral Movement",
        "rationale": ("ATT&CK's own description of T1021 explicitly names telnet "
                      "alongside SSH and VNC as example remote-access vectors an "
                      "adversary may abuse - blocking telnet directly closes one of "
                      "the three protocols ATT&CK itself calls out. (Not T1571 "
                      "Non-Standard Port - that technique is specifically about an "
                      "UNUSUAL port for a protocol, e.g. HTTPS on 8088; telnet on "
                      "port 23 is its standard port, so T1571 would be the wrong ID.)"),
        "confidence": "verified against attack.mitre.org",
    },
    "OFF_HOURS": {
        "technique_id": None,
        "technique_name": "(not a technique - a temporal analytic feature)",
        "tactic": None,
        "rationale": ("Off-hours activity is not itself an ATT&CK technique - it is "
                      "a corroborating behavioral feature that raises or lowers "
                      "confidence in whichever technique the OTHER signals point "
                      "to. Listed here for completeness, not because it maps to an "
                      "ID - claiming otherwise would be forcing a fit that doesn't "
                      "exist."),
        "confidence": "N/A - honestly not a technique",
    },
}

# Defensive layers map to MITRE D3FEND (d3fend.mitre.org), which catalogs
# DEFENDER countermeasures, not attacker techniques - using ATT&CK IDs for
# these would be a category error, not just imprecise phrasing.
LAYER_D3FEND_MAPPING = {
    "guard_checkpoint": {
        "d3fend_category": "Harden - Platform Hardening",
        "rationale": "A fast, deterministic pre-filter blocking known-bad protocols/ports before deeper analysis runs.",
    },
    "hygienic_cleanup": {
        "d3fend_category": "Model / Isolate - Credential and Trust Revocation (conceptually)",
        "rationale": "Proactively audits and recommends revoking stale, no-longer-corroborated trust relationships in the baseline.",
    },
    "containment": {
        "d3fend_category": "Isolate - Network Isolation",
        "rationale": "Real Docker network disconnection of a confirmed or under-review host.",
    },
    "quorum_consensus": {
        "d3fend_category": "Detect - Analytic correlation strategy (not a listed D3FEND technique)",
        "rationale": "A detection-engineering strategy requiring corroboration across independent signals, rather than a countermeasure against one specific attacker behavior - included for completeness, not because a precise D3FEND ID exists for it.",
    },
}


def get_attack_mapping(signal_name):
    return SIGNAL_ATTACK_MAPPING.get(signal_name)


def get_d3fend_mapping(layer_name):
    return LAYER_D3FEND_MAPPING.get(layer_name)


def annotate_summary_with_attack(summary):
    """
    Given a confirmed detection's signal summary (e.g. {'NEW_PEER': 1,
    'FANOUT_SPIKE': 1}), returns the sorted set of distinct ATT&CK
    technique IDs implicated - for inclusion in SIEM exports and
    analyst-facing output.
    """
    technique_ids = set()
    for signal in summary:
        mapping = SIGNAL_ATTACK_MAPPING.get(signal)
        if mapping and mapping["technique_id"]:
            for tid in mapping["technique_id"].split(" / "):
                technique_ids.add(tid.split(" ")[0])  # strip any parenthetical note
    return sorted(technique_ids)


if __name__ == "__main__":
    import json
    print("=== Signal -> ATT&CK mapping ===")
    print(json.dumps(SIGNAL_ATTACK_MAPPING, indent=2))
    print("\n=== Layer -> D3FEND mapping ===")
    print(json.dumps(LAYER_D3FEND_MAPPING, indent=2))


# ---------------------------------------------------------------------------
# Layer 7 (Chemical-Mimicry Detection) signal -> ATT&CK mapping
# ---------------------------------------------------------------------------

SIGNAL_ATTACK_MAPPING["PTH_SUSPECTED"] = {
    "technique_id": "T1550.002",
    "technique_name": "Use Alternate Authentication Material: Pass the Hash",
    "tactic": "TA0008 - Lateral Movement",
    "rationale": ("A cross-computer NTLM authentication with a Network logon type "
                  "matches MITRE's own detection guidance for this technique: "
                  "'anomalous NTLM LogonType 3 authentications... especially from "
                  "lateral systems.' Built and tested against the real, verified "
                  "LANL auth.txt format."),
    "confidence": "verified against attack.mitre.org and real LANL auth.txt data",
}

SIGNAL_ATTACK_MAPPING["PTT_SUSPECTED"] = {
    "technique_id": "T1550.003",
    "technique_name": "Use Alternate Authentication Material: Pass the Ticket",
    "tactic": "TA0008 - Lateral Movement",
    "rationale": ("A Kerberos authentication with no prior authentication history "
                  "for that user is the closest honest approximation this "
                  "dataset's fields support to MITRE's official detection logic "
                  "(a TGS request with no corresponding prior TGT) - stated as an "
                  "adaptation, not a literal implementation, since LANL's auth.txt "
                  "does not carry real Windows Event IDs."),
    "confidence": "verified against attack.mitre.org; adaptation explicitly stated",
}


def get_layer7_d3fend_mapping():
    return {
        "chemical_mimicry_detection": {
            "d3fend_category": "Detect - Authentication Event Thresholding (conceptually)",
            "rationale": ("Detects anomalous use of an otherwise-valid credential - the "
                          "defender-side response to an attacker successfully mimicking "
                          "a legitimate identity, paralleling how real bee colonies still "
                          "sometimes catch near-perfect chemical mimics."),
        }
    }


# ---------------------------------------------------------------------------
# Layer 9 - Agent Behavior Detection
#
# These map to MITRE ATLAS (the adversarial threat matrix for AI systems),
# not ATT&CK Enterprise. That distinction is deliberate and is the same
# category discipline applied above between ATT&CK and D3FEND: ATT&CK
# catalogs adversary behavior against conventional IT, while ATLAS
# catalogs adversary behavior against AI/ML systems. Forcing an agent
# hijack into an ATT&CK Enterprise ID would be the same kind of category
# error as forcing a defensive layer into ATT&CK.
#
# IDs verified against MITRE ATLAS documentation before inclusion:
#   AML.T0051     - LLM Prompt Injection
#   AML.T0051.001 - Indirect (injection embedded in retrieved content)
#   AML.T0086     - Exfiltration via AI Agent Tool Invocation
#
# Where an ATT&CK Enterprise technique genuinely also applies - because
# the agent's own valid credentials are being used - it is cited
# alongside rather than instead of the ATLAS ID.
# ---------------------------------------------------------------------------

SIGNAL_ATTACK_MAPPING["TAINTED_SCOPE_EXPANSION"] = {
    "technique_id": "AML.T0051.001",
    "technique_name": "LLM Prompt Injection: Indirect",
    "tactic": "MITRE ATLAS",
    "rationale": ("The agent processes untrusted external content and then acts "
                  "outside its established envelope. Indirect prompt injection is "
                  "precisely the technique of embedding instructions in content "
                  "the agent will later retrieve and process, so the observed "
                  "sequence is its behavioral consequence rather than a separate "
                  "technique."),
    "confidence": "verified against MITRE ATLAS",
}

SIGNAL_ATTACK_MAPPING["NEW_TOOL"] = {
    "technique_id": "AML.T0051",
    "technique_name": "LLM Prompt Injection",
    "tactic": "MITRE ATLAS",
    "rationale": ("An agent invoking a capability it has never used is the "
                  "observable result of its instructions being subverted. Mapped "
                  "to the parent technique rather than a sub-technique, because "
                  "novel tool use alone does not indicate whether the injection "
                  "was direct or indirect."),
    "confidence": "verified against MITRE ATLAS",
}

SIGNAL_ATTACK_MAPPING["NEW_TARGET"] = {
    "technique_id": "AML.T0051",
    "technique_name": "LLM Prompt Injection",
    "tactic": "MITRE ATLAS",
    "rationale": ("Reaching a resource outside the agent's established envelope. "
                  "Same parent-technique reasoning as NEW_TOOL - and note this "
                  "signal fires constantly during legitimate work, which is why "
                  "it is never actionable alone."),
    "confidence": "verified against MITRE ATLAS",
}

SIGNAL_ATTACK_MAPPING["RESULT_SIZE_OUTLIER"] = {
    "technique_id": "AML.T0086",
    "technique_name": "Exfiltration via AI Agent Tool Invocation",
    "tactic": "MITRE ATLAS",
    "rationale": ("A tool call returning or transmitting an anomalous volume for "
                  "this agent is the direct signature of using the agent's own "
                  "legitimate tool access to move data out."),
    "confidence": "verified against MITRE ATLAS",
}

SIGNAL_ATTACK_MAPPING["PRIVILEGE_ESCALATION"] = {
    "technique_id": "AML.T0051 / T1078",
    "technique_name": "LLM Prompt Injection / Valid Accounts",
    "tactic": "MITRE ATLAS / TA0004 - Privilege Escalation",
    "rationale": ("The agent writes to or executes against a resource it had only "
                  "ever read. Cited under BOTH frameworks deliberately: the "
                  "subversion is an ATLAS concern, but the mechanism is the "
                  "agent's own valid credentials being used beyond their "
                  "established pattern, which is ATT&CK T1078."),
    "confidence": "verified against MITRE ATLAS and attack.mitre.org",
}

SIGNAL_ATTACK_MAPPING["CALL_RATE_SPIKE"] = {
    "technique_id": "AML.T0051",
    "technique_name": "LLM Prompt Injection",
    "tactic": "MITRE ATLAS",
    "rationale": ("Machine-speed bursts of tool calls well beyond this agent's own "
                  "baseline rate. Named in current agent-security research as a "
                  "distinguishing property of automated agent pivots versus "
                  "human-paced attacker activity."),
    "confidence": "verified against MITRE ATLAS",
}
