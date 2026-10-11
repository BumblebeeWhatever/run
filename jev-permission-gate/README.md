# jev-permission-gate

让 Jev 替你回答 Claude Code 的权限确认弹窗。目标是减少「Claude 停下来等你点同意」的人工等待，不追求替代你的判断。

基于 Claude Code 的 `PermissionRequest` hook 实现，纯 Python 标准库，无需安装依赖。

## 工作原理

```text
Claude Code 即将弹出权限确认
        │
        ▼
   gate.py ──① 本地守卫：rm -rf / git push / adb uninstall / 写项目外文件 / 改 .claude 配置 …
        │       命中 → Jev 说 allow 也无效
        │
        ├──② POST Jev（墙钟硬上限 300ms，协议见 PROTOCOL.md）
        │
        ▼
   ③ 决策（仅 enforce 模式生效）
        ├─ Jev allow，置信度 ≥ 0.9，未命中守卫 → 自动放行，终端提示「[Jev] 已自动放行…」
        ├─ Jev deny，置信度 ≥ 0.9               → 自动拒绝，理由转给 Claude
        └─ 其他任何情况                         → 不输出，正常弹窗等你处理
```

另外有一个异步的 `record.py`（PostToolUse），记录哪些请求最终被执行了。`analyze.py` 用它推断你对每次弹窗的实际处理，评估 Jev 的判断准不准。

## 安全设计

所有不确定的情况都退回到「你本来就会看到的弹窗」，最坏结果等于没装：

1. **失败即弃权**：Jev 超时、连接失败、非 200、返回格式不对、置信度不够、hook 自身崩溃，一律不输出，回到人工弹窗。settings 里**不要**设 `onFailure: "block"`：在 PermissionRequest 上它会把失败变成拒绝，Jev 一挂所有操作都会被拒。
2. **本地守卫优先于 Jev**：破坏性操作（删除、改写或推送 git 历史、设备数据清除）、对外发布（push、PR、发包、部署、HTTP 写请求、ssh）、敏感文件（密钥、`.env`、`gradle.properties`）、写项目外文件、修改 Claude Code 自身配置，这些永远交给你。规则见 `jg_guard.py`，宁可多拦，不可漏拦。
3. **Claude Code 自己的 deny/ask 规则仍然生效**：官方文档明确说明，hook 返回 allow 后，deny 和 ask 规则还会再评估一遍。
4. **人工检查点不自动**：plan 模式下的任何请求、`ExitPlanMode`（批准计划）、`AskUserQuestion`。
5. **能力最小化**：v1 不改写命令（`updatedInput`），不写入持久规则（`updatedPermissions`），不中断 Claude。
6. **数据最小化**：发给 Jev 和写入日志前先脱敏常见密钥格式；文件正文只发长度和摘要；日志文件权限为 0600。

## 安装

**第 0 步（不需要 Jev）**：先在 Claude Code 里运行 `/fewer-permission-prompts`，把高频安全的只读命令加进静态 allowlist。这类请求根本不会弹窗，也就不会走到 Jev，延迟最低。Jev 只处理静态规则写不全的长尾。

**第 1 步**：放到固定目录，例如：

```bash
git clone <this-repo> /tmp/jg && cp -r /tmp/jg/jev-permission-gate ~/.claude/jev-permission-gate
```

**第 2 步**：把 `settings.example.json` 合并进 `~/.claude/settings.json`（对所有项目生效），把 `/ABSOLUTE/PATH/TO/` 换成真实的绝对路径。`args` 是 exec 形式，不经过 shell，所以 `~` 和 `$HOME` **不会展开**。

**第 3 步**：开一个新的 Claude Code 会话。日志在 `~/.claude/jev-gate/`。

## 上线路线

| 阶段 | 配置 | 产出 | 进入下一阶段的条件 |
|---|---|---|---|
| **0 · 基线** | `JEV_GATE_MODE=shadow`，不设 URL | 弹窗量、命令分布、人工等待时长 | 跑满 1 周 |
| **1 · 影子评估** | `shadow` + `JEV_GATE_URL` | Jev 的判断 vs 你的实际处理 | `analyze.py` 结论为「可灰度」：≥200 条评估样本，**0 误放行** |
| **2 · 灰度生效** | `JEV_GATE_MODE=enforce` | 真正省掉人工等待 | 持续观察 |

看报告：

```bash
python3 ~/.claude/jev-permission-gate/analyze.py            # 最近 14 天
python3 ~/.claude/jev-permission-gate/analyze.py --days 30 --json
```

报告里每一条「⚠ 误放行」都要逐条复核。「未执行」包含你点了拒绝、按 Esc 中断、会话结束三种情况，其中有些并不是真正的误判。

**回滚**（任选其一，即时生效，不用改 settings）：

```bash
touch ~/.claude/jev-gate/DISABLED          # 一键关闭；删掉这个文件即恢复
```

或者设置 `JEV_GATE_MODE=off`。

## 配置

都是环境变量，可以写进 settings.json 的 `env` 块（已实测会传到 hook 进程）。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `JEV_GATE_MODE` | `shadow` | `off` / `shadow`（只记录不决策）/ `enforce` |
| `JEV_GATE_URL` | 空 | Jev 接口，`http://` 或 `https://`。为空时只记录基线 |
| `JEV_GATE_TOKEN` | 空 | 以 `Authorization: Bearer` 发送 |
| `JEV_GATE_TIMEOUT_MS` | `300` | 调用 Jev 的墙钟上限（最小 50） |
| `JEV_GATE_ALLOW_THRESHOLD` | `0.9` | allow 生效所需的最低置信度 |
| `JEV_GATE_DENY_THRESHOLD` | `0.9` | deny 生效所需的最低置信度 |
| `JEV_GATE_ENFORCE_DENY` | `1` | 设为 `0` 时只采纳 allow，deny 一律交还给你 |
| `JEV_GATE_NOTIFY` | `1` | 自动决策时在终端提示一行 |
| `JEV_GATE_CA_BUNDLE` | 空 | 内网 CA 证书路径 |
| `JEV_GATE_DIR` | `~/.claude/jev-gate` | 日志和开关文件所在目录 |
| `JEV_GATE_LOG_MAX_BYTES` | `20971520` | 单个日志超过这个大小后滚动为 `.1` |

## 本地联调

Jev 还没接好时，可以用 `mock_jev.py` 跑通 enforce 全链路。它也是协议的参考实现：

```bash
python3 mock_jev.py --port 18765 --deny-regex '^touch denied'
JEV_GATE_MODE=enforce JEV_GATE_URL=http://127.0.0.1:18765/v1/permission claude
```

mock 的放行策略只是示例，不代表推荐策略。

## 已验证

**单元测试**：`python3 -m unittest discover -s tests`，共 39 个，覆盖守卫规则、gate 所有失败路径、协议格式、脱敏、影子评估统计。另外对「守卫优先于 Jev」和「heredoc 绕过」两处关键逻辑做了变异检查，故意改坏后测试会失败。

**端到端**：在真实的 Claude Code 2.1.296（`claude -p`）上验证：

| 场景 | 结果 |
|---|---|
| enforce + `git add`，Jev allow 0.92 | 自动放行并执行，Jev 往返约 22ms |
| enforce + `rm -rf junkdir` | 命中守卫，不做决策，目录保留 |
| enforce + `touch denied.txt`，Jev deny | 拒绝，Claude 收到拒绝理由，文件未创建 |
| shadow + `git add`，Jev 会 allow | 不做决策，只记录 |
| 配置写在 settings `env` 块里 | 能传到 hook 进程 |
| PermissionRequest 与 PostToolUse 的 `tool_input` 哈希 | 一致，影子评估能正确关联 |

hook 进程自身开销约 35–42ms（Python 启动 + 守卫 + 写日志），不含 Jev 往返。

## 已知限制

- **守卫是正则，不是沙箱**。能挡住常见写法，挡不住刻意构造的绕过（比如写个脚本再执行它）。真正的硬边界仍然是 Claude Code 的 deny 规则和 sandbox。
- **非交互模式**（`claude -p`、后台子 agent）下，hook 不给结论等于拒绝，这是 Claude Code 的官方行为。
- **你的实际处理是推断出来的**（有没有执行），不是直接读到的。所以影子评估只看 shadow 模式的数据。
- **auto 模式**下，模型分类器和这个 hook 谁先生效，没有验证过。建议在 `default` 模式下使用。
- sandbox 内的网络请求不会触发 PermissionRequest，这是官方行为。
- **信任边界**：项目级 `.claude/settings.json` 的 `env` 能覆盖这些配置（包括把 `JEV_GATE_URL` 指向别处）。这和项目级 settings 本来就能写 allow 规则、注册自己的 hook 属于同一信任边界，所以只在你信任的仓库里打开 Claude Code。

## 文件

| 文件 | 作用 |
|---|---|
| `gate.py` | PermissionRequest hook 主入口 |
| `jg_guard.py` | 本地守卫规则 |
| `jg_common.py` | 配置、脱敏、哈希、日志 |
| `record.py` | PostToolUse / PostToolUseFailure 执行记录（异步） |
| `analyze.py` | 影子期报告和上线判定 |
| `mock_jev.py` | Jev 联调桩和协议参考实现 |
| `PROTOCOL.md` | 与 Jev 服务端的接口契约 |
| `settings.example.json` | hook 注册示例 |
