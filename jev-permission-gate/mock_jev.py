#!/usr/bin/env python3
"""Local stand-in for Jev that speaks jev-permission/v1. For integration testing only.

  python3 mock_jev.py --port 18765
  JEV_GATE_URL=http://127.0.0.1:18765/v1/permission JEV_GATE_MODE=enforce claude

The policy below is an example of the request shape Jev receives, not a recommended policy.
"""

import argparse
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

POLICY_VERSION = "mock-0.1"

_ALLOW_BASH = [
    (re.compile(r"^(?:ls|cat|head|tail|wc|find|grep|rg|tree|pwd|which|file|stat|du|df)\b"), 0.97, "read-only shell"),
    (re.compile(r"^git\s+(?:status|diff|log|show|branch|fetch|blame|rev-parse|stash\s+list)\b"), 0.97, "read-only git"),
    (re.compile(r"^git\s+(?:add|commit|checkout\s+-b|switch\s+-c|stash(?:\s+push)?)\b"), 0.92, "local git write"),
    (re.compile(r"^\./gradlew(?:\s+-{1,2}\S+)*(?:\s+(?::[\w:-]+:)?(?:assemble|test|lint|compile|check|dependencies|tasks|ktlint|detekt)\w*(?:\s+-{1,2}\S+)*)+\s*$"), 0.93, "gradle build/test"),
    (re.compile(r"^adb(?:\s+-s\s+\S+)?\s+(?:devices|logcat|install(?:-multiple)?|shell\s+(?:getprop|dumpsys|pm\s+list|am\s+(?:start|force-stop|broadcast)|wm\s+size|input\s+(?:tap|swipe|text)))\b"), 0.92, "adb dev action"),
]
_SOURCE_EXT = (".kt", ".kts", ".java", ".xml", ".gradle", ".md", ".json", ".yaml", ".yml", ".py", ".ts", ".js")
_COMPOUND = re.compile(r";|&&|\|\||\||\$\(|`")


def decide(req, deny_re=None):
    tool = req.get("tool_name")
    ti = req.get("tool_input") or {}
    if (req.get("local_guard") or {}).get("guarded"):
        return "abstain", 0.0, "client guard hit"
    if tool == "Bash":
        cmd = (ti.get("command") or "").strip()
        if deny_re and deny_re.search(cmd):
            return "deny", 0.95, "matches deny pattern"
        if _COMPOUND.search(cmd):
            return "abstain", 0.5, "compound command"
        for pat, conf, why in _ALLOW_BASH:
            if pat.search(cmd):
                return "allow", conf, why
        return "abstain", 0.0, "no rule"
    if tool in ("Edit", "Write", "MultiEdit"):
        path, cwd = ti.get("file_path") or "", req.get("cwd") or ""
        if cwd and path.startswith(cwd.rstrip("/") + "/") and path.endswith(_SOURCE_EXT):
            return "allow", 0.92, "source edit inside project"
        return "abstain", 0.0, "no rule"
    return "abstain", 0.0, "no rule"


def make_server(host="127.0.0.1", port=0, deny_re=None, delay_ms=0, status=200, raw_body=None):
    """Start the mock in a background thread; returns (server, url). Used by the tests too."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
            seen.append({"body": req, "auth": self.headers.get("Authorization")})
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
            if raw_body is not None:
                body = raw_body.encode("utf-8")
            else:
                d, conf, why = decide(req, deny_re)
                body = json.dumps({"decision": d, "confidence": conf, "reason": why,
                                   "policy_version": POLICY_VERSION}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.seen = seen
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://%s:%d/v1/permission" % (host, srv.server_address[1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18765)
    ap.add_argument("--deny-regex", help="Bash commands matching this are denied")
    ap.add_argument("--delay-ms", type=int, default=0)
    args = ap.parse_args()
    srv, url = make_server(args.host, args.port, re.compile(args.deny_regex) if args.deny_regex else None, args.delay_ms)
    print("mock Jev listening on %s (pid %d)" % (url, os.getpid()), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
