#!/usr/bin/env python3
"""PostToolUse / PostToolUseFailure recorder (register with "async": true).

PermissionRequest events carry no tool_use_id, so the human's real answer is inferred:
a request followed by an execution of the same input was approved, one with no execution
was rejected or interrupted. This hook only writes hashes and a redacted preview.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jg_common as c  # noqa: E402

_EVENTS = {"PostToolUse": "executed", "PostToolUseFailure": "executed_failed"}


def main():
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return
    if not isinstance(event, dict) or event.get("hook_event_name") not in _EVENTS:
        return
    cfg = c.Config()
    if cfg.mode == "off":
        return
    tool_input = event.get("tool_input") or {}
    c.append_jsonl(cfg.outcomes_log, {
        "v": 1,
        "kind": _EVENTS[event["hook_event_name"]],
        "ts": c.now(),
        "session_id": event.get("session_id"),
        "tool_name": event.get("tool_name"),
        "input_hash": c.input_hash(tool_input),
        "key": c.preview(c.primary_key(tool_input)),
        "duration_ms": event.get("duration_ms"),
    }, cfg.log_max_bytes)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
