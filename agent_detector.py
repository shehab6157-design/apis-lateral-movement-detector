"""
agent_detector.py — Layer 9, Agent Behavior Detection.

The threat, per real, current 2026 research checked before building:
adversaries "use an AI agent's legitimate, authenticated connections to
pivot between systems by injecting malicious instructions into content
the agent processes, meaning natural language is the attack vector."
Reported as a top 2026 risk that "most organizations aren't equipped to
control."

Why this is a genuine third domain and not a rename of Layer 7:
Layer 7 (chemical mimicry) catches an attacker presenting a STOLEN
credential. Here the credential is not stolen at all - the legitimate
agent, holding its own legitimate credential, is redirected from the
inside. Every individual action is authorized. As the research puts it:
"there is no foreign process, no exploit, no dropped binary - just the
agent using the identity, network routes, and tools it was handed at
deployment to reach targets it was technically allowed to touch. That is
the entire problem."

Design consequences taken directly from that research:

  1. "What you score is the sequence, not the event... A pattern that
     breaks the agent's normal envelope is the alert; an individual
     authorized action is not." -> every signal below is emitted against
     a per-agent envelope, and NONE is ever individually actionable:
     they feed the same shared QuorumCoordinator every other layer uses.

  2. Baselines must bind to a durable identity because agents are
     ephemeral ("pods recycle before models" finish learning).
     -> agent_baseline.py keys on agent_id, never session_id.

  3. TAINTED_SCOPE_EXPANSION is the signal specific to this threat and
     the reason this layer exists: the agent processes untrusted input,
     then within a short window reaches a tool or target it has never
     reached before. That ordering - taint, then novel scope - is the
     prompt-injection pivot signature. Neither half alone is
     suspicious: agents read untrusted content constantly, and agents
     legitimately reach new targets. The sequence is the signal.

HONEST SCOPE, stated here as everywhere else in this project: several
commercial products (ARMO, Elisity and others) now sell per-agent
behavioral baselining, so this is not an unsolved problem in the sense
of nobody having attempted it. What the research does describe as the
open gap is the cross-surface, sequence-level, drift-resistant version -
and there is no open, independently-evaluated implementation of it.
That gap is what this layer targets, and its results will be reported
with the same ablation discipline used on the other two domains.
"""

from collections import deque

from agent_baseline import WRITE_ACTIONS

# How long after reading untrusted content a scope expansion is still
# treated as plausibly caused by it. Deliberately short: a pivot driven
# by injected instructions follows the injection closely, while ordinary
# new-target work spreads out over a session.
TAINT_WINDOW_SECONDS = 120
# How many calls after the taint remain in scope, so a burst of rapid
# calls cannot outrun the window on time alone.
TAINT_WINDOW_CALLS = 10

# Matches the project's existing convention (VOLUME_OUTLIER uses 3.0).
RESULT_SIZE_ZSCORE_THRESHOLD = 3.0
# "Machine-speed lateral movement" is named in the research as a
# distinguishing property of agent pivots versus human attackers.
RATE_MULTIPLIER_THRESHOLD = 5.0

AGENT_SIGNAL_TYPES = {
    "NEW_TOOL",
    "NEW_TARGET",
    "TAINTED_SCOPE_EXPANSION",
    "PRIVILEGE_ESCALATION",
    "RESULT_SIZE_OUTLIER",
    "CALL_RATE_SPIKE",
}


def zscore(value, mean, std):
    if std <= 0:
        return 0.0
    return (value - mean) / std


def _location_of(target):
    """
    The 'place' a target lives in: the directory for a path, the scheme
    and host for a URL. Returns None when a target has no meaningful
    location (a bare executable name, an empty target), so that missing
    information can never be mistaken for a location match.
    """
    if not target:
        return None
    normalized = str(target).replace("\\", "/")
    lowered = normalized.lower()

    if lowered.startswith(("http://", "https://")):
        without_scheme = normalized.split("://", 1)[1]
        host = without_scheme.split("/", 1)[0]
        return f"url:{host.lower()}"

    if "/" not in normalized:
        return None

    directory = normalized.rsplit("/", 1)[0]
    return f"path:{directory.lower()}"


class AgentBehaviorDetector:
    """
    Emits raw signals for one stream of agent tool-call events. Emits
    only - confirmation is the shared quorum layer's job, so a single
    novel tool call can never trigger an action on its own.
    """

    def __init__(self, baseline=None):
        self.baseline = baseline or {}
        # Per durable agent identity: recent untrusted-input reads, and
        # a rolling call-time window for rate estimation.
        self._taint = {}
        self._taint_location = {}
        self._recent_calls = {}
        self._calls_since_taint = {}

    def _profile(self, agent_id):
        return self.baseline.get(agent_id)

    def _note_rate(self, agent_id, now):
        window = self._recent_calls.setdefault(agent_id, deque())
        window.append(now)
        while window and now - window[0] > 60.0:
            window.popleft()
        return len(window)

    def _taint_active(self, agent_id, now):
        """True if this agent recently processed untrusted input, by
        both the time window and the call-count window."""
        taint_time = self._taint.get(agent_id)
        if taint_time is None:
            return False
        if now - taint_time > TAINT_WINDOW_SECONDS:
            return False
        if self._calls_since_taint.get(agent_id, 0) > TAINT_WINDOW_CALLS:
            return False
        return True

    def process_event(self, event):
        """Returns the list of raw signal names fired by this event."""
        signals = []
        agent_id = event["agent_id"]
        now = event["time"]
        profile = self._profile(agent_id)

        calls_last_minute = self._note_rate(agent_id, now)

        if agent_id in self._calls_since_taint:
            self._calls_since_taint[agent_id] += 1

        # An agent with no learned envelope cannot be scored against
        # one. Conservative on purpose, matching the identity side's
        # handling of unknown users: record the taint state, emit
        # nothing.
        if profile is None:
            if event["input_provenance"] == "untrusted":
                self._taint[agent_id] = now
                self._taint_location[agent_id] = _location_of(event["target"])
                self._calls_since_taint[agent_id] = 0
            return signals

        known_tools = set(profile.get("known_tools", []))
        known_targets = set(profile.get("known_targets", []))
        write_targets = set(profile.get("write_targets", []))

        is_new_tool = event["tool"] not in known_tools
        is_new_target = bool(event["target"]) and event["target"] not in known_targets

        if is_new_tool:
            signals.append("NEW_TOOL")
        if is_new_target:
            signals.append("NEW_TARGET")

        # The signal this layer exists for, in its refined form.
        #
        # The original rule - any novel scope while tainted - was
        # measured on real Claude Code traces and FAILED: it fired on 5
        # of 6 false positives. The reason was structural, not a
        # threshold problem. "Read external content, then touch
        # something new" is the job description of a research or
        # summarization agent, so benign work and the attack produced
        # the identical sequence.
        #
        # The refinement under test: benign agents consume outward and
        # act inward (read a doc, write a summary into their own
        # workspace). The pivot acts OUTWARD after consuming external
        # content - that is what exfiltration and remote execution are.
        # So a novel READ no longer qualifies, however external; only a
        # novel WRITE or EXECUTE beyond the agent's own boundary does.
        #
        # Honest cost of this narrowing: detection moves later in the
        # chain. The attacker's first outward read is no longer caught;
        # the outward action is. Whether that trade is worth it is an
        # empirical question, measured in agent_evaluation.py.
        acted_outward = (
            event["action"] in WRITE_ACTIONS
            and event.get("external", False)
        )
        # THIRD REFINEMENT, and the risk of that is stated plainly below.
        #
        # The act-outward rule assumed agents read outward and write
        # inward. Measured on 510 real tool calls that assumption held
        # for coding agents and BROKE for research agents: given 22
        # untrusted reads instead of 5, it produced 4 false positives,
        # every one of them the same benign shape - read a source file,
        # write a summary next to it.
        #
        # The distinction that separates those from the attack is where
        # the write LANDS relative to what was just read. Writing into
        # the same place you read from is in-place summarization.
        # Writing somewhere unrelated to the read source is what
        # exfiltration looks like.
        #
        # Honest risk: this is the third pass at one signal, and it was
        # shaped by four specific false positives. Fitting a rule to the
        # cases that broke it is how a detector ends up describing its
        # own test set. It is therefore evaluated on a SEPARATE corpus
        # of research-agent traces generated after the change, not on
        # the 510 calls that motivated it - and if it does not hold
        # there, the honest outcome is to report that the taint approach
        # does not generalize across agent workloads.
        same_place_as_taint = False
        if acted_outward:
            write_location = _location_of(event["target"])
            taint_location = self._taint_location.get(agent_id)
            # Both must be known. An unknown location is not a match:
            # missing information must never suppress a signal.
            same_place_as_taint = (
                write_location is not None
                and taint_location is not None
                and write_location == taint_location
            )

        if ((is_new_tool or is_new_target)
                and acted_outward
                and not same_place_as_taint
                and self._taint_active(agent_id, now)):
            signals.append("TAINTED_SCOPE_EXPANSION")

        # A write/execute against a target this agent has previously
        # only READ is the "cross-system side effect" the research calls
        # out as worth logging on its own.
        #
        # Narrowed after a real evaluation: an earlier version fired on
        # ANY write to a target not in write_targets, which included
        # brand-new files. Creating a file is not privilege escalation,
        # it is what a development agent does all day - and novelty is
        # already covered by NEW_TARGET. Genuine escalation is acting on
        # something it previously only observed.
        if (event["action"] in WRITE_ACTIONS
                and event["target"]
                and event["target"] in known_targets
                and event["target"] not in write_targets):
            signals.append("PRIVILEGE_ESCALATION")

        z = zscore(event["result_size"],
                   profile.get("avg_result_size", 0.0),
                   profile.get("std_result_size", 1.0))
        if z >= RESULT_SIZE_ZSCORE_THRESHOLD:
            signals.append("RESULT_SIZE_OUTLIER")

        baseline_rate = profile.get("avg_calls_per_minute", 0.0)
        if baseline_rate > 0 and calls_last_minute >= baseline_rate * RATE_MULTIPLIER_THRESHOLD:
            signals.append("CALL_RATE_SPIKE")

        # Taint is recorded AFTER scoring this event, so reading
        # untrusted content never implicates the very call that read it.
        if event["input_provenance"] == "untrusted":
            self._taint[agent_id] = now
            self._taint_location[agent_id] = _location_of(event["target"])
            self._calls_since_taint[agent_id] = 0

        return signals
