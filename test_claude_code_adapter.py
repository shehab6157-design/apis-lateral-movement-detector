"""
test_claude_code_adapter.py — tests the adapter against a fixture built
to match the ACTUAL observed Claude Code v2.1.276 transcript schema
(verified by inspecting real session files), not an invented one.
"""

import json

import pytest

from claude_code_adapter import convert_transcript


def assistant(ts, tool_name, tool_input, use_id, cwd="C:\\Users\\sheha\\claude-trace-lab",
              session="9b3f27fc-23db-4b32-811d-cf3274eb2d1f"):
    """A real Claude Code assistant record carrying a tool_use block."""
    return {
        "type": "assistant", "timestamp": ts, "cwd": cwd, "sessionId": session,
        "uuid": f"u-{use_id}", "version": "2.1.276", "userType": "external",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": use_id, "name": tool_name,
             "input": tool_input, "caller": "assistant"}
        ]},
    }


def result(ts, use_id, content, is_error=False,
           session="9b3f27fc-23db-4b32-811d-cf3274eb2d1f"):
    """A real Claude Code user record carrying a tool_result block."""
    block = {"type": "tool_result", "tool_use_id": use_id, "content": content}
    if is_error:
        block["is_error"] = True
    return {
        "type": "user", "timestamp": ts, "sessionId": session,
        "message": {"role": "user", "content": [block]},
    }


def write_transcript(tmp_path, records, name="session.jsonl"):
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return str(path)


# ------------------------------------------------------------- basics

def test_extracts_tool_calls_and_pairs_results(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Write",
                  {"file_path": "C:\\Users\\sheha\\claude-trace-lab\\a.py",
                   "content": "print(1)"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "Wrote 1 line"),
    ])
    events = convert_transcript(path)
    assert len(events) == 1
    assert events[0]["tool"] == "Write"
    assert events[0]["action"] == "write"
    assert events[0]["result_size"] == len("Wrote 1 line")
    assert events[0]["success"] is True


def test_non_tool_records_are_ignored(tmp_path):
    path = write_transcript(tmp_path, [
        {"type": "attachment", "timestamp": "2026-09-18T14:16:00.000Z"},
        {"type": "system", "timestamp": "2026-09-18T14:16:00.000Z"},
        {"type": "assistant", "timestamp": "2026-09-18T14:16:00.000Z",
         "message": {"content": [{"type": "text", "text": "thinking out loud"}]}},
        assistant("2026-09-18T14:16:02.000Z", "Read", {"file_path": "/x/y.txt"}, "t1"),
        result("2026-09-18T14:16:03.000Z", "t1", "contents"),
    ])
    events = convert_transcript(path)
    assert len(events) == 1
    assert events[0]["tool"] == "Read"


def test_failed_call_is_marked_unsuccessful(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "PowerShell",
                  {"command": "python missing.py", "description": "run"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "No such file", is_error=True),
    ])
    assert convert_transcript(path)[0]["success"] is False


def test_timestamp_parsed_to_epoch(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Glob", {"pattern": "*.py"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "a.py"),
    ])
    assert convert_transcript(path)[0]["time"] > 1_700_000_000


# --------------------------------------------- the durable-identity rule

def test_agent_id_is_the_workspace_not_the_session(tmp_path):
    """The whole premise of Layer 9: ephemeral instances must not reset
    security state. Two sessions in one workspace are ONE agent."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Read", {"file_path": "/x/a.txt"}, "t1",
                  session="session-one"),
        result("2026-09-18T14:16:01.000Z", "t1", "a", session="session-one"),
        assistant("2026-09-18T15:00:00.000Z", "Read", {"file_path": "/x/b.txt"}, "t2",
                  session="session-two"),
        result("2026-09-18T15:00:01.000Z", "t2", "b", session="session-two"),
    ])
    events = convert_transcript(path)
    assert len({e["agent_id"] for e in events}) == 1
    assert events[0]["agent_id"] == "claude-code:claude-trace-lab"
    # the ephemeral id is still carried, just never used as the key
    assert {e["session_id"] for e in events} == {"session-one", "session-two"}


# ------------------------------------------------------- target mapping

@pytest.mark.parametrize("tool,tool_input,expected", [
    ("Read", {"file_path": "C:\\dir\\file.txt"}, "C:/dir/file.txt"),
    ("Write", {"file_path": "/a/b.py", "content": "x"}, "/a/b.py"),
    ("Edit", {"file_path": "/a/b.py", "old_string": "x", "new_string": "y"}, "/a/b.py"),
    ("Glob", {"pattern": "**/*.py"}, "**/*.py"),
    ("WebFetch", {"url": "https://example.com"}, "https://example.com"),
])
def test_target_extracted_per_tool(tmp_path, tool, tool_input, expected):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", tool, tool_input, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "ok"),
    ])
    assert convert_transcript(path)[0]["target"] == expected


def test_shell_target_is_the_executable_not_the_whole_command(tmp_path):
    """Using the full command string would make every invocation a brand
    new target and drown the signal."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "PowerShell",
                  {"command": "python -m pytest test_x.py -v", "description": "run tests"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "6 passed"),
    ])
    event = convert_transcript(path)[0]
    assert event["target"] == "python"
    assert event["action"] == "execute"


# ------------------------------------------------ the provenance heuristic

def test_reading_a_file_the_agent_did_not_write_is_untrusted(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Read", {"file_path": "/data/external.csv"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "a,b,c"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "untrusted"


def test_reading_back_its_own_write_is_trusted(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Write",
                  {"file_path": "/work/mine.py", "content": "print(1)"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "Wrote 1 line"),
        assistant("2026-09-18T14:16:05.000Z", "Read", {"file_path": "/work/mine.py"}, "t2"),
        result("2026-09-18T14:16:06.000Z", "t2", "print(1)"),
    ])
    events = convert_transcript(path)
    assert events[0]["input_provenance"] == "trusted"
    assert events[1]["input_provenance"] == "trusted"


def test_network_fetch_is_always_untrusted(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "WebFetch", {"url": "https://example.com"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "<html>"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "untrusted"


def test_shell_execution_is_unknown_not_untrusted(tmp_path):
    """Marking shell output untrusted would leave nearly every session
    permanently tainted and make the pivot signal meaningless."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "PowerShell",
                  {"command": "python --version", "description": "check"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "Python 3.13.14"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "unknown"


# --------------------------------------------------- end-to-end usability

def test_converted_events_are_accepted_by_layer_9(tmp_path):
    """The real contract: adapter output must parse cleanly as Layer 9
    events and build a baseline without special-casing."""
    from agent_baseline import parse_agent_event, build_agent_baseline

    records = []
    ts = 0
    for i in range(6):
        ts += 1
        records.append(assistant(f"2026-09-18T14:{ts:02d}:00.000Z", "Write",
                                 {"file_path": f"/w/f{i}.py", "content": "x"}, f"t{i}"))
        records.append(result(f"2026-09-18T14:{ts:02d}:01.000Z", f"t{i}", "Wrote 1 line"))
    path = write_transcript(tmp_path, records)

    events = convert_transcript(path)
    parsed = [parse_agent_event(e) for e in events]
    assert all(p is not None for p in parsed)

    baseline = build_agent_baseline(parsed)
    assert "claude-code:claude-trace-lab" in baseline
    assert baseline["claude-code:claude-trace-lab"]["observed_calls"] == 6


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


def test_glob_is_metadata_only_so_not_untrusted(tmp_path):
    """Refined after a real conversion: Glob returns file NAMES, not
    file content. Treating it as untrusted inflates taint and drives
    false pivot signals on ordinary work."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Glob", {"pattern": "**/*.py"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "a.py\nb.py"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "unknown"


def test_grep_stays_untrusted_because_it_returns_content(tmp_path):
    """Grep returns matching LINES - real content an attacker could
    have written - so it is deliberately not treated as metadata."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "Grep",
                  {"pattern": "TODO", "path": "/data/notes.txt"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "line 4: TODO fix this"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "untrusted"


# ---------------------------------------------------------------------------
# Fixes driven by a real evaluation: 6 false positives on 18 benign events,
# every one involving TAINTED_SCOPE_EXPANSION.
# ---------------------------------------------------------------------------

def test_written_files_persist_across_sessions(tmp_path):
    """The bug this layer exists to prevent, found inside the adapter
    itself: write state was scoped per transcript, i.e. per session, so
    reading back your own file in a later session looked external."""
    from claude_code_adapter import convert_transcript

    s1 = write_transcript(tmp_path, [
        assistant("2026-09-18T14:00:00.000Z", "Write",
                  {"file_path": "C:\\Users\\sheha\\claude-trace-lab\\mine.py",
                   "content": "x"}, "t1", session="sess-1"),
        result("2026-09-18T14:00:01.000Z", "t1", "Wrote 1 line", session="sess-1"),
    ], name="s1.jsonl")

    s2 = write_transcript(tmp_path, [
        assistant("2026-09-18T15:00:00.000Z", "Read",
                  {"file_path": "C:\\Users\\sheha\\claude-trace-lab\\mine.py"},
                  "t2", session="sess-2"),
        result("2026-09-18T15:00:01.000Z", "t2", "x", session="sess-2"),
    ], name="s2.jsonl")

    written, workspaces = {}, {}
    convert_transcript(s1, written=written, workspaces=workspaces)
    events = convert_transcript(s2, written=written, workspaces=workspaces)

    assert events[0]["input_provenance"] == "trusted"


def test_reading_a_file_inside_the_workspace_is_trusted(tmp_path):
    """A development agent reading its own project source is the
    dominant benign case and must not taint the session."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:00:00.000Z", "Read",
                  {"file_path": "C:\\Users\\sheha\\claude-trace-lab\\someone_elses.py"},
                  "t1"),
        result("2026-09-18T14:00:01.000Z", "t1", "code"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "trusted"


def test_reading_a_file_outside_the_workspace_is_untrusted(tmp_path):
    """Content arriving from outside the agent's own scope is the
    documented injection vector."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:00:00.000Z", "Read",
                  {"file_path": "C:\\data\\vendor_feed.csv"}, "t1"),
        result("2026-09-18T14:00:01.000Z", "t1", "a,b,c"),
    ])
    assert convert_transcript(path)[0]["input_provenance"] == "untrusted"


def test_here_string_delimiter_is_not_treated_as_an_executable(tmp_path):
    """Real traces exposed this: PowerShell here-strings begin with @',
    which naive first-token extraction captured as the 'executable',
    manufacturing phantom NEW_TARGET signals."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "PowerShell",
                  {"command": "@'\nsome text\n'@ | Set-Content out.txt",
                   "description": "write a file"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "ok"),
    ])
    # My first fix stripped the delimiter but then grabbed the NEXT
    # token - the here-string's literal text - which is not an
    # executable either. A here-string has no executable at its head,
    # so the correct answer is no target at all.
    target = convert_transcript(path)[0]["target"]
    assert target == ""


def test_leading_flags_are_skipped_when_finding_the_executable(tmp_path):
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T14:16:00.000Z", "PowerShell",
                  {"command": "python -m pytest -v", "description": "tests"}, "t1"),
        result("2026-09-18T14:16:01.000Z", "t1", "6 passed"),
    ])
    assert convert_transcript(path)[0]["target"] == "python"


def test_here_string_content_is_not_mistaken_for_an_executable(tmp_path):
    """Real traces showed CSV header text being recorded as the
    'executable' of a PowerShell call."""
    path = write_transcript(tmp_path, [
        assistant("2026-09-18T15:04:41.000Z", "PowerShell",
                  {"command": "@'\ndate,product,region,quantity,unit_price\n2026-01-05,Widget,North,10,9.99\n'@ | Set-Content sales.csv",
                   "description": "write csv"}, "t1"),
        result("2026-09-18T15:04:42.000Z", "t1", "ok"),
    ])
    assert convert_transcript(path)[0]["target"] == ""
