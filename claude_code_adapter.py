"""
claude_code_adapter.py — converts real Claude Code session transcripts
into the normalized Layer 9 agent-event format.

Written against the ACTUAL observed schema of Claude Code v2.1.276
transcripts (~/.claude/projects/<workspace>/<session-uuid>.jsonl),
inspected directly rather than assumed:

  - Each line is one JSON record with a top-level "type" and "timestamp".
  - A tool CALL is a block with type "tool_use" inside
    record["message"]["content"], on records of type "assistant".
    Block keys: caller, id, input, name, type.
  - A tool RESULT is a block with type "tool_result" inside
    record["message"]["content"], on records of type "user".
    Block keys: content, tool_use_id, type, and is_error when it failed.
  - Calls and results are paired by tool_use id, so the adapter reads the
    transcript twice: once to collect results, once to emit events.

Real tool names and input fields observed: PowerShell(command,
description), Write(content, file_path), Read(file_path), Edit(file_path,
old_string, new_string, replace_all), Glob(pattern).

=== The durable-identity decision ===
Layer 9's whole premise is that the baseline must bind to a DURABLE
identity, because ephemeral instances recycle before a profile forms.
Claude Code's sessionId is exactly such an ephemeral instance: a new one
per session. The stable analogue of a Deployment or ServiceAccount here
is the WORKSPACE the agent operates in (record["cwd"]), so agent_id is
derived from that and sessionId is carried separately, never used as the
baseline key.

=== The input_provenance decision (derived, not observed) ===
Claude Code does not label the trust level of content, so provenance is
DERIVED by this adapter. This is a real judgment call and is documented
as such rather than presented as ground truth:

  untrusted - the agent read content it did not itself produce:
              a Read of a file this agent has not written during the
              observed history, and anything fetched from the network
              (WebFetch/WebSearch). This is the realistic prompt-
              injection vector: external text entering the agent's
              context.
  trusted   - the agent's own output or its own prior writes: Write,
              Edit, and Reads of files it wrote earlier.
  unknown   - shell execution (PowerShell/Bash), whose output can
              contain anything. Deliberately NOT marked untrusted,
              because doing so would make nearly every session
              permanently tainted and render TAINTED_SCOPE_EXPANSION
              meaningless. Marking it unknown is the conservative
              choice: it neither creates taint nor suppresses it.

Anyone evaluating results from this adapter should treat provenance as a
heuristic of this adapter, not as a property of the source data.
"""

import json
import os
from datetime import datetime

# Observed and anticipated Claude Code tool names, mapped to the coarse
# action classes Layer 9 scores against.
READ_TOOLS = {"Read", "Glob", "Grep", "NotebookRead", "WebFetch", "WebSearch"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
EXEC_TOOLS = {"PowerShell", "Bash", "BashOutput", "KillShell"}
NETWORK_TOOLS = {"WebFetch", "WebSearch"}

# Read tools that return only metadata (file names, paths) rather than
# file CONTENT. Refined after inspecting the first real conversion:
# Glob matched 2 of 16 real calls and was being marked untrusted, but it
# returns a list of paths, not the bytes inside them - a far weaker
# injection vector than actual content. Treating it as untrusted inflates
# taint and would drive TAINTED_SCOPE_EXPANSION false positives on
# ordinary work. Grep is deliberately NOT in this set: it returns
# matching LINES, which is real content an attacker could have written.
METADATA_ONLY_READ_TOOLS = {"Glob"}

# Tool input fields that identify what was touched, in priority order.
TARGET_FIELDS = ("file_path", "path", "notebook_path", "pattern", "url", "query")


def _parse_timestamp(value):
    """Claude Code writes ISO-8601 timestamps (commonly with a trailing
    Z). Returns epoch seconds, or None if unparseable."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _action_for(tool_name):
    if tool_name in WRITE_TOOLS:
        return "write"
    if tool_name in EXEC_TOOLS:
        return "execute"
    return "read"


def _target_for(tool_name, tool_input):
    """The resource this call touched, normalized so the same resource
    reads the same way across calls."""
    if not isinstance(tool_input, dict):
        return ""

    for field in TARGET_FIELDS:
        value = tool_input.get(field)
        if value:
            if field in ("file_path", "path", "notebook_path"):
                return str(value).replace("\\", "/")
            return str(value)

    # Shell commands: the executable/cmdlet is the meaningful unit of
    # scope. Using the whole command string would make every distinct
    # invocation a brand-new target and drown the signal in noise.
    #
    # Real traces exposed two successive problems here. First, PowerShell
    # here-strings start with @' or @", so naive first-token extraction
    # captured the delimiter as the "executable". Stripping the delimiter
    # was NOT enough: the next token is the here-string's literal text
    # (e.g. a CSV header line), which is not an executable either. A
    # here-string has no meaningful executable at its head, so the honest
    # answer is no target rather than a manufactured one - inventing a
    # target from missing information is what produced phantom NEW_TARGET
    # signals in the first place.
    command = tool_input.get("command")
    if command:
        text = str(command).strip()
        if text.startswith(("@'", '@"')):
            return ""
        for token in text.split():
            cleaned = token.strip("'\"`(){}$|&;<>")
            if cleaned and not cleaned.startswith("-"):
                return cleaned
        return ""

    return ""


def _agent_id_for(cwd, fallback):
    """Durable workspace identity - deliberately not the session."""
    if cwd:
        normalized = str(cwd).replace("\\", "/").rstrip("/")
        name = normalized.split("/")[-1] or normalized
        return f"claude-code:{name}"
    return f"claude-code:{fallback}"


def _iter_records(path):
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


def _content_blocks(record):
    message = record.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    return content if isinstance(content, list) else []


def _collect_results(path):
    """First pass: map tool_use id -> (result_size, success)."""
    results = {}
    for record in _iter_records(path):
        for block in _content_blocks(record):
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            use_id = block.get("tool_use_id")
            if not use_id:
                continue
            content = block.get("content")
            if isinstance(content, str):
                size = len(content)
            elif isinstance(content, list):
                size = sum(
                    len(part.get("text", "")) if isinstance(part, dict) else len(str(part))
                    for part in content
                )
            elif content is None:
                size = 0
            else:
                size = len(str(content))
            results[use_id] = (size, not bool(block.get("is_error")))
    return results


def _is_external(target, workspace):
    """
    True when the target lies outside the agent's own workspace.

    Used only by the refined TAINTED_SCOPE_EXPANSION rule. A URL is
    always external. A path inside the workspace is not. A bare
    executable name (the target form used for shell calls) is not a
    location at all, so it is treated as internal rather than guessed
    at - guessing would manufacture signal from missing information.
    """
    if not target:
        return False
    normalized = target.replace("\\", "/").lower()
    if normalized.startswith(("http://", "https://")):
        return True
    if "/" not in normalized:
        return False
    if workspace and normalized.startswith(workspace):
        return False
    return True


def _read_provenance(target, agent_written, workspace):
    """
    Trust classification for a read, refined after a real evaluation
    produced 6 false positives on 18 benign events, every one of them
    involving TAINTED_SCOPE_EXPANSION.

    trusted   - the agent wrote this file itself (at any point in its
                history, not just this session), OR the file lives
                inside the agent's own workspace. A development agent
                reading its own project's source is the dominant benign
                case and must not permanently taint the session.
    untrusted - content originating outside the agent's workspace, or
                from the network. This is the documented injection
                vector: external text entering the agent's context.

    STATED LIMITATION, not hidden: a poisoned file placed INSIDE the
    workspace is classified trusted by this rule and its injection
    would not raise taint. That is a real gap. The alternative -
    treating every in-project read as untrusted - was measured on real
    traces and produced a false-positive rate that made the signal
    useless, which is the worse failure of the two. A content-level
    check (rather than a location-level one) is the honest next step
    and is not implemented here.
    """
    if target in agent_written:
        return "trusted"
    if workspace and target:
        normalized = target.replace("\\", "/").lower()
        if normalized.startswith(workspace):
            return "trusted"
    return "untrusted"


def convert_transcript(path, written=None, workspaces=None):
    """
    Second pass: emit one normalized Layer 9 event per tool call.

    written / workspaces are per-DURABLE-AGENT state deliberately passed
    in, so they persist ACROSS transcripts. Found necessary by a real
    evaluation, not assumed: an earlier version scoped these per
    transcript file, which means per session. A file the agent wrote in
    one session and read back in a later one was then classified as
    untrusted external content, and TAINTED_SCOPE_EXPANSION fired on
    ordinary work in all six false positives of the first real run.

    That is precisely the failure this layer exists to avoid - state
    resetting when an ephemeral instance recycles - reproduced inside
    the adapter itself. Keying this state on agent_id fixes it.
    """
    results = _collect_results(path)
    session_fallback = os.path.splitext(os.path.basename(path))[0]
    events = []
    if written is None:
        written = {}
    if workspaces is None:
        workspaces = {}

    for record in _iter_records(path):
        blocks = _content_blocks(record)
        if not blocks:
            continue

        timestamp = _parse_timestamp(record.get("timestamp"))
        session_id = record.get("sessionId") or record.get("session_id") or session_fallback
        cwd = record.get("cwd")
        agent_id = _agent_id_for(cwd, session_fallback)

        if cwd:
            workspaces[agent_id] = str(cwd).replace("\\", "/").rstrip("/").lower()
        agent_written = written.setdefault(agent_id, set())
        workspace = workspaces.get(agent_id)

        for block in blocks:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue

            name = block.get("name") or "(unnamed)"
            tool_input = block.get("input") if isinstance(block.get("input"), dict) else {}
            target = _target_for(name, tool_input)
            action = _action_for(name)
            size, success = results.get(block.get("id"), (0, True))

            if name in NETWORK_TOOLS:
                provenance = "untrusted"
            elif name in EXEC_TOOLS or name in METADATA_ONLY_READ_TOOLS:
                provenance = "unknown"
            elif action == "read":
                provenance = _read_provenance(target, agent_written, workspace)
            else:
                provenance = "trusted"

            if action == "write" and target:
                agent_written.add(target)

            if timestamp is None:
                continue

            events.append({
                "time": timestamp,
                "agent_id": agent_id,
                "session_id": str(session_id),
                "tool": name,
                "target": target,
                "action": action,
                "input_provenance": provenance,
                "result_size": size,
                "success": success,
                # Whether the target lies outside the agent's own
                # workspace. Computed here because only the adapter
                # knows the workspace; the detector stays generic.
                "external": _is_external(target, workspace),
            })

    return events


def find_transcripts(root=None):
    root = root or os.path.join(os.path.expanduser("~"), ".claude", "projects")
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".jsonl"):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


def convert_all(root=None):
    """Converts every transcript, sharing per-durable-agent state across
    them. Sharing is the whole point: an agent's write history and
    workspace must not reset when a new session starts."""
    events = []
    written = {}
    workspaces = {}
    # Chronological order matters: a file must be seen as written before
    # a later read of it can be classified as the agent's own output.
    for path in sorted(find_transcripts(root), key=lambda p: os.path.getmtime(p)):
        events.extend(convert_transcript(path, written=written, workspaces=workspaces))
    events.sort(key=lambda e: e["time"])
    return events


if __name__ == "__main__":
    import sys
    from collections import Counter

    out_path = sys.argv[1] if len(sys.argv) > 1 else "agent_events.txt"
    events = convert_all()

    with open(out_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"Converted {len(events)} real tool calls -> {out_path}\n")
    if not events:
        print("  (no tool calls found - run a few Claude Code sessions first)")
        raise SystemExit(0)

    print("Durable agent identities:")
    for agent, n in Counter(e["agent_id"] for e in events).most_common():
        print(f"  {agent}: {n} calls")
    print("\nSessions represented (ephemeral - NOT the baseline key):")
    print(f"  {len(set(e['session_id'] for e in events))}")
    print("\nTools:")
    for tool, n in Counter(e["tool"] for e in events).most_common():
        print(f"  {tool}: {n}")
    print("\nDerived provenance:")
    for prov, n in Counter(e["input_provenance"] for e in events).most_common():
        print(f"  {prov}: {n}")
    print("\nActions:")
    for action, n in Counter(e["action"] for e in events).most_common():
        print(f"  {action}: {n}")
