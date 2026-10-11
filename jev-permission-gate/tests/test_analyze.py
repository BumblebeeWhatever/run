import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import analyze  # noqa: E402
import jg_common as c  # noqa: E402
import mock_jev  # noqa: E402

T0 = 1_700_000_000.0


def req(i, would, ts, mode="shadow", jev_error=None, tool="Bash", key=None):
    ti = {"command": key or "cmd-%d" % i}
    jev = {"error": jev_error, "latency_ms": 5} if jev_error else {"decision": would or "abstain", "confidence": 0.95, "latency_ms": 5, "policy_version": "p1"}
    return {"kind": "permission_request", "ts": ts, "session_id": "s", "tool_name": tool, "input_hash": c.input_hash(ti),
            "key": ti["command"], "guard": [], "jev": jev, "would_apply": would, "applied": would if mode == "enforce" else None,
            "mode": mode}


def out(i, ts, kind="executed", duration_ms=2000, key=None):
    ti = {"command": key or "cmd-%d" % i}
    return {"kind": kind, "ts": ts, "session_id": "s", "tool_name": "Bash", "input_hash": c.input_hash(ti),
            "key": ti["command"], "duration_ms": duration_ms}


class AnalyzeTest(unittest.TestCase):
    def evaluate(self, requests, outcomes):
        return analyze.metrics(analyze.join(requests, outcomes, 1800))

    def test_confusion_cells_and_wait(self):
        reqs = [req(1, "allow", T0), req(2, "allow", T0 + 1), req(3, "deny", T0 + 2), req(4, None, T0 + 3),
                req(5, "allow", T0 + 4, jev_error="timeout")]
        outs = [out(1, T0 + 12), out(3, T0 + 20), out(4, T0 + 30)]
        m = self.evaluate(reqs, outs)
        s = m["shadow"]
        self.assertEqual((4, 1, 1, 0, 1, 1), (s["evaluated"], s["correct_allow"], s["false_allow"], s["correct_deny"], s["false_deny"], s["abstain"]))
        self.assertEqual("cmd-2", s["false_allow_samples"][0]["key"])
        self.assertAlmostEqual(10 / 60, s["projected_saved_min"], places=1)  # 12s gap minus 2s run
        self.assertEqual({"timeout": 1}, m["jev"]["errors"])
        self.assertIn("样本不足", m["verdict"])

    def test_execution_outside_window_is_not_matched(self):
        m = self.evaluate([req(1, "allow", T0)], [out(1, T0 + 3600)])
        self.assertEqual(1, m["shadow"]["false_allow"])

    def test_execution_before_request_is_not_matched(self):
        m = self.evaluate([req(1, "allow", T0)], [out(1, T0 - 5)])
        self.assertEqual(1, m["shadow"]["false_allow"])

    def test_one_execution_answers_one_request(self):
        m = self.evaluate([req(1, "allow", T0), req(1, "allow", T0 + 1)], [out(1, T0 + 5)])
        self.assertEqual((1, 1), (m["shadow"]["correct_allow"], m["shadow"]["false_allow"]))

    def test_fallback_join_on_key(self):
        r = req(1, "allow", T0)
        r["input_hash"] = "different"
        m = self.evaluate([r], [out(1, T0 + 5)])
        self.assertEqual(1, m["shadow"]["correct_allow"])

    def test_verdicts(self):
        reqs = [req(i, "allow", T0 + i) for i in range(analyze.MIN_SAMPLES)]
        outs = [out(i, T0 + i + 3) for i in range(analyze.MIN_SAMPLES)]
        self.assertIn("可灰度", self.evaluate(reqs, outs)["verdict"])
        reqs.append(req(999, "allow", T0 + 5000))
        self.assertIn("禁止开启 enforce", self.evaluate(reqs, outs)["verdict"])

    def test_enforce_rows_are_not_shadow_evaluated(self):
        m = self.evaluate([req(1, "allow", T0, mode="enforce")], [])
        self.assertEqual(0, m["shadow"]["evaluated"])
        self.assertEqual(1, m["enforce"]["auto_allow"])

    def test_command_head(self):
        self.assertEqual("./gradlew testDebugUnitTest", analyze.command_head("FOO=1 ./gradlew -q :biz:feed:testDebugUnitTest"))
        self.assertEqual("git status", analyze.command_head("git status -s"))
        self.assertEqual("ls", analyze.command_head("ls -la"))


class EndToEnd(unittest.TestCase):
    """gate.py (shadow) -> record.py -> analyze.py through real subprocesses and files."""

    def test_pipeline(self):
        srv, url = mock_jev.make_server()
        try:
            with tempfile.TemporaryDirectory() as d:
                env = {k: v for k, v in os.environ.items() if not k.startswith("JEV_GATE_")}
                env.update({"JEV_GATE_DIR": d, "JEV_GATE_MODE": "shadow", "JEV_GATE_URL": url})
                ti = {"command": "git status", "description": "status"}
                base = {"session_id": "s9", "cwd": "/w", "permission_mode": "default", "tool_name": "Bash", "tool_input": ti}

                def run(script, ev):
                    p = subprocess.run([sys.executable, "-I", os.path.join(HERE, script)], input=json.dumps(ev),
                                       capture_output=True, text=True, env=env, timeout=10)
                    self.assertEqual(0, p.returncode, p.stderr)
                    return p.stdout

                self.assertEqual("", run("gate.py", dict(base, hook_event_name="PermissionRequest")))
                run("record.py", dict(base, hook_event_name="PostToolUse", tool_use_id="toolu_1", duration_ms=40, tool_response={}))
                run("record.py", dict(base, hook_event_name="Notification"))  # ignored
                with open(os.path.join(d, "outcomes.jsonl")) as f:
                    self.assertEqual(1, len(f.readlines()))
                p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "analyze.py"), "--json"],
                                   capture_output=True, text=True, env=env, timeout=10)
                self.assertEqual(0, p.returncode, p.stderr)
                m = json.loads(p.stdout)
                self.assertEqual(1, m["shadow"]["correct_allow"])
                self.assertEqual(0, m["shadow"]["false_allow"])
                txt = subprocess.run([sys.executable, "-I", os.path.join(HERE, "analyze.py")],
                                     capture_output=True, text=True, env=env, timeout=10).stdout
                self.assertIn("影子评估", txt)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
