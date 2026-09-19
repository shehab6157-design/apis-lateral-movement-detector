"""
inspect_claude_logs.py — summarizes the real structure of Claude Code
session transcripts so the Layer 9 adapter can be written against the
actual schema instead of an assumed one.

Prints structure only: record counts, field names, tool names, and the
shape of tool-call entries. Deliberately does NOT print file contents,
prompts, or command output, which would be both enormous and needlessly
revealing.

Usage:
    python inspect_claude_logs.py
"""

import json
import os
from collections import Counter

PROJECTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "projects")


def find_transcripts():
    found = []
    for root, _dirs, files in os.walk(PROJECTS_DIR):
        for name in files:
            if name.endswith(".jsonl"):
                found.append(os.path.join(root, name))
    return sorted(found)


def summarize(path):
    print(f"\n=== {os.path.basename(path)} ===")
    top_keys = Counter()
    types = Counter()
    tool_names = Counter()
    tool_input_keys = Counter()
    example_tool_use = None
    example_tool_result_keys = None
    record_count = 0
    timestamp_field = None

    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            record_count += 1
            if not isinstance(rec, dict):
                continue

            top_keys.update(rec.keys())
            types[rec.get("type", "(no type)")] += 1

            for field in ("timestamp", "time", "ts", "createdAt"):
                if field in rec:
                    timestamp_field = field

            # Tool calls live inside the assistant message content blocks
            message = rec.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type")
                        types[f"  content-block: {btype}"] += 1
                        if btype == "tool_use":
                            tool_names[block.get("name", "(unnamed)")] += 1
                            inp = block.get("input")
                            if isinstance(inp, dict):
                                tool_input_keys.update(
                                    f"{block.get('name')}.{k}" for k in inp.keys()
                                )
                            if example_tool_use is None:
                                example_tool_use = {
                                    "block_keys": sorted(block.keys()),
                                    "name": block.get("name"),
                                    "input_keys": sorted(inp.keys()) if isinstance(inp, dict) else type(inp).__name__,
                                }
                        elif btype == "tool_result":
                            if example_tool_result_keys is None:
                                example_tool_result_keys = sorted(block.keys())

    print(f"records: {record_count}")
    print(f"timestamp field detected: {timestamp_field}")
    print(f"\ntop-level fields: {sorted(top_keys)}")
    print("\nrecord types:")
    for t, n in types.most_common():
        print(f"  {t}: {n}")
    print("\ntool calls by name:")
    for t, n in tool_names.most_common():
        print(f"  {t}: {n}")
    print("\ntool input fields seen:")
    for k, n in sorted(tool_input_keys.items()):
        print(f"  {k}: {n}")
    print(f"\nexample tool_use block shape: {example_tool_use}")
    print(f"example tool_result block keys: {example_tool_result_keys}")


if __name__ == "__main__":
    transcripts = find_transcripts()
    if not transcripts:
        print(f"No transcripts found under {PROJECTS_DIR}")
    else:
        print(f"Found {len(transcripts)} transcript file(s) under {PROJECTS_DIR}")
        for path in transcripts:
            summarize(path)
