# jev-permission/v1 协议

给 Jev 服务端的接口契约。客户端是 `gate.py`（Claude Code 的 `PermissionRequest` hook）。参考实现见 `mock_jev.py`。

## 调用方式

- `POST <JEV_GATE_URL>`，`Content-Type: application/json`
- 配置了 `JEV_GATE_TOKEN` 时附带 `Authorization: Bearer <token>`
- 客户端总超时 `JEV_GATE_TIMEOUT_MS`（默认 300ms，墙钟硬上限）。超时即视为弃权
- 客户端不走系统代理（`HTTP(S)_PROXY`），直连 Jev
- 只在 Claude Code **即将弹出权限确认框**时调用。静态 allow 规则已放行的调用不会到达 Jev

**延迟目标**：服务端 p99 < 150ms。整个 hook 进程自身开销约 40ms，二者之和要远低于 300ms 的预算。

## 请求

```json
{
  "protocol": "jev-permission/v1",
  "request_id": "6f1c…",
  "ts_ms": 1791712029242,
  "session_id": "bc8664be-…",
  "cwd": "/Users/me/aweme",
  "permission_mode": "default",
  "tool_name": "Bash",
  "tool_input": {"command": "git add hello.txt", "description": "Stage hello.txt"},
  "input_hash": "af341a758e6096d2",
  "mcp_server": null,
  "permission_suggestions": [{"type": "addRules", "rules": [{"toolName": "Bash", "ruleContent": "git add hello.txt"}], "behavior": "allow", "destination": "localSettings"}],
  "local_guard": {"guarded": false, "reasons": []},
  "client": {"name": "jev-permission-gate", "version": "0.1.0"}
}
```

| 字段 | 说明 |
|---|---|
| `tool_name` | Claude Code 工具名：`Bash`、`Edit`、`Write`、`Read`、`WebFetch`、`mcp__<server>__<tool>` 等 |
| `tool_input` | **已脱敏**。token、密码、URL 凭据等替换为 `<redacted>`。文件正文类字段（`content`、`new_string`、`old_string` 等）和超过 8000 字符的字符串只给 `{"omitted": true, "len": N, "sha256": "…"}` |
| `input_hash` | 原始 `tool_input` 的规范化 sha256 前 16 位，可用作缓存键 |
| `permission_mode` | `default` / `acceptEdits` / `auto` / `plan` 等 |
| `permission_suggestions` | Claude Code 自己建议的规则，可作为「这类请求的规范模式」参考 |
| `local_guard` | 本地守卫结果。`guarded: true` 时，**客户端会忽略 Jev 的 allow**，Jev 无需再判 allow |
| `request_id` | 每次请求唯一，用于幂等和日志关联 |

## 响应

```json
{"decision": "allow", "confidence": 0.95, "reason": "read-only git", "policy_version": "p3"}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `decision` | 是 | `allow` / `deny` / `abstain` |
| `confidence` | 是 | `[0, 1]` 之间的数字。allow 或 deny 需 ≥ 阈值（默认 0.9）才生效 |
| `reason` | 否 | ≤ 500 字符。**deny 时会原样转给 Claude**，写清楚为什么拒绝、应该怎么做 |
| `policy_version` | 否 | ≤ 64 字符。写入日志和用户提示，用于按策略版本统计误放行 |

### 语义

- **`allow`**：替用户点「同意」。Claude Code 之后仍会再评估 deny/ask 规则，所以 Jev 放行不能越过用户配置的 deny 规则。
- **`deny`**：替用户点「拒绝」，`reason` 进入 Claude 的上下文。用于明确有害、或者用户必然会拒的请求。
- **`abstain`**：不确定。客户端什么都不输出，用户看到正常的确认框。**拿不准一律 abstain**，这是安全方向。

### 客户端一律视为弃权的情况

- HTTP 状态码非 200
- 响应体不是 JSON 对象
- `decision` 不在三个合法取值内
- `confidence` 不是 `[0, 1]` 之间的数字（字符串、布尔值、越界都算）
- 超时、连接失败、TLS 错误
- `confidence` 低于阈值
- allow 但 `local_guard.guarded` 为 true

客户端**忽略**响应中的其他字段。v1 不支持改写入参（`updatedInput`）、不支持写入持久规则（`updatedPermissions`）、不支持中断（`interrupt`）。

## 隐私

- 请求里不含文件正文，只有路径和摘要
- 常见密钥格式在发出前脱敏（Bearer/Basic、`token=`、`--password=`、URL 凭据、AWS key、`sk-…`、`ghp_…`、`xox?-…`、JWT）
- 脱敏是正则兜底，不是保证。Jev 侧日志仍应按敏感数据处理

## 版本演进

破坏性变更时升级 `protocol` 字段（`jev-permission/v2`），服务端按此字段分流。新增可选字段不升级版本。
