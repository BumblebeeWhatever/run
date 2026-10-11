import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import mock_jev  # noqa: E402

GATE = os.path.join(HERE, "gate.py")
CWD = "/work/aweme"


def event(cmd="git status", tool="Bash", **extra):
    ev = {
        "session_id": "s1",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": CWD,
        "permission_mode": "default",
        "hook_event_name": "PermissionRequest",
        "tool_name": tool,
        "tool_input": {"command": cmd, "description": "test"} if tool == "Bash" else extra.pop("tool_input"),
    }
    ev.update(extra)
    return ev


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        self.tmp.cleanup()

    def server(self, **kw):
        srv, url = mock_jev.make_server(**kw)
        self.servers.append(srv)
        return srv, url

    def run_gate(self, ev, mode="enforce", url=None, raw_stdin=None, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith("JEV_GATE_")}
        e.update({"JEV_GATE_DIR": self.dir, "JEV_GATE_MODE": mode})
        if url:
            e["JEV_GATE_URL"] = url
        e.update(env)
        t0 = time.monotonic()
        p = subprocess.run([sys.executable, "-I", GATE], input=raw_stdin if raw_stdin is not None else json.dumps(ev),
                           capture_output=True, text=True, env=e, timeout=10)
        self.elapsed = time.monotonic() - t0
        self.assertEqual(0, p.returncode, p.stderr)
        return p.stdout

    def log(self):
        path = os.path.join(self.dir, "decisions.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    # --- decisions --------------------------------------------------------

    def test_enforce_allow_output_matches_hook_contract(self):
        _, url = self.server()
        out = json.loads(self.run_gate(event("git status"), url=url))
        self.assertEqual({"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}, out["hookSpecificOutput"])
        self.assertIn("[Jev]", out["systemMessage"])
        rec = self.log()[-1]
        self.assertEqual(("allow", "allow", "jev_allow"), (rec["would_apply"], rec["applied"], rec["why"]))

    def test_shadow_never_outputs_but_logs_would_apply(self):
        _, url = self.server()
        self.assertEqual("", self.run_gate(event("git status"), mode="shadow", url=url))
        rec = self.log()[-1]
        self.assertEqual(("allow", None, "shadow"), (rec["would_apply"], rec["applied"], rec["mode"]))

    def test_guard_overrides_jev_allow(self):
        _, url = self.server(raw_body=json.dumps({"decision": "allow", "confidence": 0.99}))
        self.assertEqual("", self.run_gate(event("rm -rf build"), url=url))
        rec = self.log()[-1]
        self.assertEqual("guarded", rec["why"])
        self.assertIn("rm_recursive_or_force", rec["guard"])

    def test_low_confidence_allow_abstains(self):
        _, url = self.server(raw_body=json.dumps({"decision": "allow", "confidence": 0.5}))
        self.assertEqual("", self.run_gate(event(), url=url))
        self.assertEqual("low_confidence", self.log()[-1]["why"])

    def test_deny_carries_message_to_claude(self):
        _, url = self.server(raw_body=json.dumps({"decision": "deny", "confidence": 0.95, "reason": "prod host", "policy_version": "p7"}))
        out = json.loads(self.run_gate(event("curl https://prod"), url=url))
        d = out["hookSpecificOutput"]["decision"]
        self.assertEqual("deny", d["behavior"])
        self.assertIn("prod host", d["message"])
        self.assertIn("p7", d["message"])

    def test_deny_can_be_disabled(self):
        _, url = self.server(raw_body=json.dumps({"decision": "deny", "confidence": 0.99}))
        self.assertEqual("", self.run_gate(event(), url=url, JEV_GATE_ENFORCE_DENY="0"))
        self.assertEqual("deny_disabled", self.log()[-1]["why"])

    def test_notify_off_omits_system_message(self):
        _, url = self.server()
        out = json.loads(self.run_gate(event("git status"), url=url, JEV_GATE_NOTIFY="0"))
        self.assertNotIn("systemMessage", out)

    # --- failure paths all fall back to the human dialog ------------------

    def assert_abstain(self, why, **kw):
        self.assertEqual("", self.run_gate(event(), **kw))
        self.assertEqual(why, self.log()[-1]["why"])

    def test_timeout_is_bounded(self):
        _, url = self.server(delay_ms=3000)
        self.assert_abstain("jev_timeout", url=url, JEV_GATE_TIMEOUT_MS="200")
        self.assertLess(self.elapsed, 1.5)

    def test_http_error(self):
        _, url = self.server(status=500)
        self.assert_abstain("jev_http_500", url=url)

    def test_garbage_body(self):
        _, url = self.server(raw_body="<html>oops</html>")
        self.assert_abstain("jev_bad_json", url=url)

    def test_unknown_decision(self):
        _, url = self.server(raw_body=json.dumps({"decision": "yes", "confidence": 1}))
        self.assert_abstain("jev_bad_decision", url=url)

    def test_bad_confidence(self):
        for conf in (1.5, "0.99", True, None):
            with self.subTest(conf=conf):
                _, url = self.server(raw_body=json.dumps({"decision": "allow", "confidence": conf}))
                self.assert_abstain("jev_bad_confidence", url=url)

    def test_connection_refused(self):
        srv, url = self.server()
        srv.shutdown()
        srv.server_close()
        self.servers.remove(srv)
        self.assertEqual("", self.run_gate(event(), url=url))
        self.assertTrue(self.log()[-1]["why"].startswith("jev_"))

    def test_bad_scheme(self):
        self.assert_abstain("jev_bad_url_scheme", url="ftp://x/y")

    def test_no_url_logs_but_abstains(self):
        self.assert_abstain("jev_not_configured")
        self.assertIsNone(self.log()[-1]["jev"])

    def test_mode_off_does_nothing(self):
        self.assertEqual("", self.run_gate(event(), mode="off"))
        self.assertEqual([], self.log())

    def test_kill_switch(self):
        _, url = self.server()
        open(os.path.join(self.dir, "DISABLED"), "w").close()
        self.assertEqual("", self.run_gate(event("git status"), url=url))
        self.assertEqual([], self.log())

    def test_bad_stdin_and_other_events(self):
        self.assertEqual("", self.run_gate(None, raw_stdin="not json"))
        self.assertEqual("", self.run_gate(dict(event(), hook_event_name="PreToolUse")))
        self.assertEqual([], self.log())

    # --- what leaves the machine -----------------------------------------

    def test_secrets_redacted_and_token_sent(self):
        srv, url = self.server()
        cmd = "curl -H 'Authorization: Bearer abc123secret' https://x?token=zzz --password=hunter2"
        self.run_gate(event(cmd), url=url, JEV_GATE_TOKEN="t0k")
        sent = srv.seen[-1]
        self.assertEqual("Bearer t0k", sent["auth"])
        blob = json.dumps(sent["body"]) + json.dumps(self.log())
        for secret in ("abc123secret", "zzz", "hunter2"):
            self.assertNotIn(secret, blob)
        self.assertEqual("jev-permission/v1", sent["body"]["protocol"])

    def test_file_content_never_sent(self):
        srv, url = self.server()
        ti = {"file_path": CWD + "/app/src/Feed.kt", "content": "class Feed { val apiKey = \"SECRET\" }"}
        self.run_gate(event(tool="Write", tool_input=ti), url=url)
        body = srv.seen[-1]["body"]
        self.assertTrue(body["tool_input"]["content"]["omitted"])
        self.assertNotIn("SECRET", json.dumps(body))
        self.assertEqual(CWD + "/app/src/Feed.kt", body["tool_input"]["file_path"])

    def test_guard_result_is_sent_to_jev(self):
        srv, url = self.server()
        self.run_gate(event("git push"), url=url)
        lg = srv.seen[-1]["body"]["local_guard"]
        self.assertTrue(lg["guarded"])
        self.assertIn("git_history_or_remote", lg["reasons"])

    def test_latency_budget(self):
        _, url = self.server()
        self.run_gate(event("git status"), url=url)
        self.assertLess(self.elapsed, 1.0)


if __name__ == "__main__":
    unittest.main()
