#!/usr/bin/env python3
"""PermissionRequest hook: let Jev answer permission prompts that a human would approve anyway.

Contract with Claude Code (hooks reference, PermissionRequest):
  - print nothing           -> the normal permission dialog shows (non-interactive: denied)
  - decision.behavior=allow -> approved; deny/ask rules are still evaluated after the hook
  - decision.behavior=deny  -> denied, `message` goes to Claude
Every failure path prints nothing, so the worst case is the dialog you would have seen anyway.
"""

import json
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jg_common as c  # noqa: E402
import jg_guard  # noqa: E402


def build_request(event, guard_reasons):
    tool_input = event.get("tool_input") or {}
    return {
        "protocol": c.PROTOCOL,
        "request_id": str(uuid.uuid4()),
        "ts_ms": int(c.now() * 1000),
        "session_id": event.get("session_id"),
        "cwd": event.get("cwd"),
        "permission_mode": event.get("permission_mode"),
        "tool_name": event.get("tool_name"),
        "tool_input": c.sanitize(tool_input),
        "input_hash": c.input_hash(tool_input),
        "mcp_server": c.sanitize(event.get("mcp_server")),
        "permission_suggestions": c.sanitize(event.get("permission_suggestions")),
        "local_guard": {"guarded": bool(guard_reasons), "reasons": guard_reasons},
        "client": {"name": "jev-permission-gate", "version": c.VERSION},
    }


def _post(cfg, body, out):
    import http.client
    from urllib.parse import urlsplit

    u = urlsplit(cfg.url)
    timeout = cfg.timeout_ms / 1000.0
    if u.scheme == "https":
        import ssl

        ctx = ssl.create_default_context(cafile=cfg.ca_bundle)
        conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=ctx)
    elif u.scheme == "http":
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    else:
        out["error"] = "bad_url_scheme"
        return
    headers = {"Content-Type": "application/json"}
    if cfg.token:
        headers["Authorization"] = "Bearer " + cfg.token
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    try:
        conn.request("POST", path, body=json.dumps(body).encode("utf-8"), headers=headers)
        resp = conn.getresponse()
        data = resp.read(64 * 1024)
        out["status"] = resp.status
        out["body"] = data
    finally:
        conn.close()


def parse_response(status, body):
    """Strictly validate Jev's answer; anything unexpected becomes an abstain."""
    if status != 200:
        return {"error": "http_%s" % status}
    try:
        obj = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"error": "bad_json"}
    if not isinstance(obj, dict):
        return {"error": "bad_json"}
    decision = obj.get("decision")
    if decision not in ("allow", "deny", "abstain"):
        return {"error": "bad_decision"}
    conf = obj.get("confidence", 0)
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        return {"error": "bad_confidence"}
    reason = obj.get("reason") if isinstance(obj.get("reason"), str) else ""
    policy = obj.get("policy_version") if isinstance(obj.get("policy_version"), str) else ""
    return {"decision": decision, "confidence": float(conf), "reason": reason[:500], "policy_version": policy[:64]}


def call_jev(cfg, request):
    """POST to Jev under a hard wall-clock budget; never raises."""
    out = {}
    t0 = time.monotonic()

    def run():
        try:
            _post(cfg, request, out)
        except Exception as e:  # network errors, TLS, DNS: all become abstain
            out["error"] = type(e).__name__

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(cfg.timeout_ms / 1000.0)
    latency = round((time.monotonic() - t0) * 1000, 1)
    if th.is_alive():
        res = {"error": "timeout"}
    elif "error" in out:
        res = {"error": out["error"]}
    else:
        res = parse_response(out.get("status"), out.get("body") or b"")
    res["latency_ms"] = latency
    return res


def decide(cfg, guard_reasons, jev):
    """Return (behavior or None, why). None means: let the human decide."""
    if not jev:
        return None, "jev_not_configured"
    if "error" in jev:
        return None, "jev_" + jev["error"]
    d, conf = jev["decision"], jev["confidence"]
    if d == "allow":
        if guard_reasons:
            return None, "guarded"
        if conf < cfg.allow_threshold:
            return None, "low_confidence"
        return "allow", "jev_allow"
    if d == "deny":
        if not cfg.enforce_deny:
            return None, "deny_disabled"
        if conf < cfg.deny_threshold:
            return None, "low_confidence"
        return "deny", "jev_deny"
    return None, "jev_abstain"


def render(behavior, event, jev, cfg):
    key = c.preview(c.primary_key(event.get("tool_input")), 120)
    label = "%s %s" % (event.get("tool_name"), key) if key else event.get("tool_name")
    policy = jev.get("policy_version") or "-"
    decision = {"behavior": behavior}
    if behavior == "deny":
        decision["message"] = "[Jev] Permission denied by policy %s: %s" % (policy, jev.get("reason") or "no reason given")
    out = {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": decision}}
    if cfg.notify:
        verb = "已自动放行" if behavior == "allow" else "已自动拒绝"
        out["systemMessage"] = "[Jev] %s：%s（策略 %s，置信度 %.2f）" % (verb, label, policy, jev.get("confidence", 0))
    return out


def main():
    t0 = time.monotonic()
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    if not isinstance(event, dict) or event.get("hook_event_name") != "PermissionRequest":
        return 0
    cfg = c.Config()
    if cfg.mode == "off":
        return 0

    guard_reasons = jg_guard.evaluate(event)
    jev = call_jev(cfg, build_request(event, guard_reasons)) if cfg.url else None
    would, why = decide(cfg, guard_reasons, jev)
    applied = would if cfg.mode == "enforce" else None

    tool_input = event.get("tool_input") or {}
    c.append_jsonl(cfg.decisions_log, {
        "v": 1,
        "kind": "permission_request",
        "ts": c.now(),
        "session_id": event.get("session_id"),
        "cwd": event.get("cwd"),
        "permission_mode": event.get("permission_mode"),
        "tool_name": event.get("tool_name"),
        "input_hash": c.input_hash(tool_input),
        "key": c.preview(c.primary_key(tool_input)),
        "guard": guard_reasons,
        "jev": jev,
        "would_apply": would,
        "applied": applied,
        "why": why,
        "mode": cfg.mode,
        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
    }, cfg.log_max_bytes)

    if applied:
        sys.stdout.write(json.dumps(render(applied, event, jev, cfg), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception as e:  # fail open to the human dialog, never to an allow
        try:
            cfg = c.Config()
            c.append_jsonl(cfg.errors_log, {"ts": c.now(), "where": "gate", "error": repr(e)[:500]}, cfg.log_max_bytes)
        except Exception:
            pass
        code = 0
    sys.stdout.flush()
    os._exit(code)  # do not wait on a still-running Jev request thread
