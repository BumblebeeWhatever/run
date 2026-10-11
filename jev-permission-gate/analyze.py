#!/usr/bin/env python3
"""Shadow-mode report: how many prompts Jev could answer, and whether it would have been right.

  python3 analyze.py                 # last 14 days, text report
  python3 analyze.py --days 30 --json

Ground truth is inferred: a request followed by an execution of the same input within the
window was approved by the human; otherwise it was rejected or interrupted.
"""

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jg_common as c  # noqa: E402

MIN_SAMPLES = 200


def load(path, since):
    rows = []
    for p in (path + ".1", path):
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("ts", 0) >= since:
                    rows.append(r)
    rows.sort(key=lambda r: r["ts"])
    return rows


def join(requests, outcomes, window_s):
    by_hash = collections.defaultdict(list)
    by_key = collections.defaultdict(list)
    for o in outcomes:
        by_hash[(o.get("session_id"), o.get("tool_name"), o.get("input_hash"))].append(o)
        if o.get("key"):
            by_key[(o.get("session_id"), o.get("tool_name"), o.get("key"))].append(o)
    used = set()

    def first_after(cands, ts):
        for o in cands:
            if id(o) not in used and ts <= o["ts"] <= ts + window_s:
                used.add(id(o))
                return o
        return None

    for r in requests:
        o = first_after(by_hash[(r.get("session_id"), r.get("tool_name"), r.get("input_hash"))], r["ts"])
        if o is None and r.get("key"):
            o = first_after(by_key[(r.get("session_id"), r.get("tool_name"), r.get("key"))], r["ts"])
        if o is None:
            r["outcome"], r["wait_s"] = "not_executed", None
        else:
            r["outcome"] = o["kind"]
            run_s = (o.get("duration_ms") or 0) / 1000.0
            r["wait_s"] = max(0.0, o["ts"] - r["ts"] - run_s)
    return requests


def pct(values, p):
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return round(v[lo] + (v[hi] - v[lo]) * (k - lo), 2)


_MULTI = {"git", "adb", "gh", "npm", "yarn", "pnpm", "./gradlew", "gradle", "gradlew", "kubectl", "docker", "repo", "python", "python3"}


def command_head(key):
    """`FOO=1 ./gradlew -q :biz:feed:testDebugUnitTest` -> `./gradlew testDebugUnitTest`."""
    toks = (key or "").split()
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        toks.pop(0)
    if not toks:
        return "(empty)"
    rest = [t for t in toks[1:] if not t.startswith("-")]
    if toks[0] in _MULTI and rest:
        return toks[0] + " " + rest[0].rsplit(":", 1)[-1]
    return toks[0]


def metrics(requests):
    m = {"requests": len(requests), "sessions": len({r.get("session_id") for r in requests})}
    m["by_mode"] = dict(collections.Counter(r.get("mode") for r in requests))
    m["by_tool"] = collections.Counter(r.get("tool_name") for r in requests).most_common(10)
    m["bash_heads"] = collections.Counter(command_head(r.get("key")) for r in requests if r.get("tool_name") == "Bash").most_common(15)

    human = [r for r in requests if r.get("applied") is None]
    waits = [r["wait_s"] for r in human if r.get("wait_s") is not None]
    m["human_wait"] = {"n": len(waits), "p50_s": pct(waits, 50), "p90_s": pct(waits, 90), "total_min": round(sum(waits) / 60, 1)}

    guarded = [r for r in requests if r.get("guard")]
    m["guard"] = {"share": round(len(guarded) / len(requests), 3) if requests else 0,
                  "reasons": collections.Counter(x for r in guarded for x in r["guard"]).most_common(10)}

    called = [r for r in requests if r.get("jev")]
    errs = collections.Counter(r["jev"]["error"] for r in called if "error" in r["jev"])
    lat = [r["jev"]["latency_ms"] for r in called if "latency_ms" in r["jev"]]
    m["jev"] = {"called": len(called), "errors": dict(errs),
                "error_rate": round(sum(errs.values()) / len(called), 3) if called else None,
                "latency_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99)},
                "decisions": dict(collections.Counter(r["jev"].get("decision") for r in called if "error" not in r["jev"]))}

    # Shadow evaluation: only prompts the human actually answered.
    ev = [r for r in requests if r.get("mode") == "shadow" and r.get("jev") and "error" not in r["jev"]]
    cell = collections.defaultdict(list)
    for r in ev:
        executed = r["outcome"] != "not_executed"
        cell[(r.get("would_apply") or "abstain", executed)].append(r)
    correct_allow = cell[("allow", True)]
    false_allow = cell[("allow", False)]
    false_deny = cell[("deny", True)]
    saved = [r["wait_s"] for r in correct_allow if r.get("wait_s") is not None]
    m["shadow"] = {
        "evaluated": len(ev),
        "correct_allow": len(correct_allow),
        "false_allow": len(false_allow),
        "correct_deny": len(cell[("deny", False)]),
        "false_deny": len(false_deny),
        "abstain": len(cell[("abstain", True)]) + len(cell[("abstain", False)]),
        "coverage": round(len(correct_allow) / len(ev), 3) if ev else None,
        "projected_saved_min": round(sum(saved) / 60, 1),
        "false_allow_samples": [{"ts": r["ts"], "tool": r.get("tool_name"), "key": r.get("key"),
                                 "confidence": r["jev"].get("confidence"), "policy": r["jev"].get("policy_version")}
                                for r in false_allow[:20]],
        "false_deny_samples": [{"ts": r["ts"], "tool": r.get("tool_name"), "key": r.get("key")} for r in false_deny[:20]],
    }

    enf = [r for r in requests if r.get("mode") == "enforce"]
    est = m["human_wait"]["p50_s"] or 0
    auto = [r for r in enf if r.get("applied")]
    m["enforce"] = {"requests": len(enf), "auto_allow": sum(1 for r in auto if r["applied"] == "allow"),
                    "auto_deny": sum(1 for r in auto if r["applied"] == "deny"),
                    "est_saved_min": round(len(auto) * est / 60, 1)}

    s = m["shadow"]
    if s["evaluated"] < MIN_SAMPLES:
        verdict = "样本不足：影子评估 %d 条（< %d），继续影子期" % (s["evaluated"], MIN_SAMPLES)
    elif s["false_allow"] > 0:
        verdict = "禁止开启 enforce：存在 %d 条误放行，逐条复核后修正 Jev 策略或补本地守卫规则" % s["false_allow"]
    else:
        verdict = "可灰度 enforce：零误放行，覆盖率 %.1f%%，预计节省人工等待 %.1f 分钟" % ((s["coverage"] or 0) * 100, s["projected_saved_min"])
    m["verdict"] = verdict
    return m


def fmt_s(v):
    return "-" if v is None else "%.1fs" % v


def text_report(m, days):
    L = []
    L.append("Jev 权限审批 · 影子期报告（最近 %d 天）" % days)
    L.append("=" * 48)
    L.append("权限请求 %d 条，会话 %d 个，模式分布 %s" % (m["requests"], m["sessions"], m["by_mode"]))
    L.append("")
    L.append("[工具分布]")
    L += ["  %-28s %d" % (k, v) for k, v in m["by_tool"]]
    if m["bash_heads"]:
        L.append("[Bash 命令 Top]")
        L += ["  %-28s %d" % (k, v) for k, v in m["bash_heads"]]
    w = m["human_wait"]
    L.append("")
    L.append("[人工等待]（弹窗后由你处理并执行的请求）")
    L.append("  n=%d  p50=%s  p90=%s  合计 %.1f 分钟" % (w["n"], fmt_s(w["p50_s"]), fmt_s(w["p90_s"]), w["total_min"]))
    g = m["guard"]
    L.append("[本地守卫] 命中占比 %.1f%%  %s" % (g["share"] * 100, g["reasons"]))
    j = m["jev"]
    L.append("[Jev 调用] %d 次  错误率 %s  延迟 p50/p95/p99 = %s/%s/%s ms  决策 %s  错误 %s" % (
        j["called"], j["error_rate"], j["latency_ms"]["p50"], j["latency_ms"]["p95"], j["latency_ms"]["p99"], j["decisions"], j["errors"]))
    s = m["shadow"]
    L.append("")
    L.append("[影子评估]（Jev 判断 vs 你的实际处理）")
    L.append("  评估 %d 条：正确放行 %d · 误放行 %d · 正确拒绝 %d · 误拒绝 %d · 交还人工 %d" % (
        s["evaluated"], s["correct_allow"], s["false_allow"], s["correct_deny"], s["false_deny"], s["abstain"]))
    L.append("  覆盖率 %s  预计节省人工等待 %.1f 分钟" % ("-" if s["coverage"] is None else "%.1f%%" % (s["coverage"] * 100), s["projected_saved_min"]))
    for r in s["false_allow_samples"]:
        L.append("  ⚠ 误放行  %s  %s  conf=%s policy=%s" % (r["tool"], r["key"], r["confidence"], r["policy"]))
    for r in s["false_deny_samples"]:
        L.append("  · 误拒绝  %s  %s" % (r["tool"], r["key"]))
    e = m["enforce"]
    if e["requests"]:
        L.append("[Enforce] 请求 %d · 自动放行 %d · 自动拒绝 %d · 估算节省 %.1f 分钟（按人工等待 p50）" % (
            e["requests"], e["auto_allow"], e["auto_deny"], e["est_saved_min"]))
    L.append("")
    L.append("结论：" + m["verdict"])
    L.append("注：「未执行」包含你拒绝、按 Esc 中断和会话结束三种情况，误放行需逐条复核确认。")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--window-min", type=int, default=30, help="max gap between request and execution")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    cfg = c.Config()
    since = c.now() - args.days * 86400
    reqs = [r for r in load(cfg.decisions_log, since) if r.get("kind") == "permission_request"]
    outs = load(cfg.outcomes_log, since)
    m = metrics(join(reqs, outs, args.window_min * 60))
    print(json.dumps(m, ensure_ascii=False, indent=2) if args.json else text_report(m, args.days))


if __name__ == "__main__":
    main()
