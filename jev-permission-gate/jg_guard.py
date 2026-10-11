"""Local guard: requests that must always reach a human, whatever Jev says.

A guard hit never denies by itself. It only stops Jev's "allow" from applying, so the
normal permission dialog shows. Patterns over-match on purpose: a false hit costs one
manual approval, a miss could auto-approve something destructive or outward-facing.
"""

import os
import re

# Tools whose permission prompt *is* the human checkpoint (plan approval, questions).
NEVER_AUTO_TOOLS = {"ExitPlanMode", "AskUserQuestion"}

FILE_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
FILE_READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}

_SEG = r"[^;&|\n]*"  # stays within one shell segment

_BASH_RULES = [
    (r"\brm\s+(?:-\S*\s+)*(?:-\S*[rRf]|--recursive|--force)", "rm_recursive_or_force"),
    (r"\b(?:sudo|doas)\b|(?:^|[;&|]\s*)su\b", "privilege_escalation"),
    (rf"\bgit\b{_SEG}\s(?:push|rebase|filter-branch|filter-repo|update-ref)\b", "git_history_or_remote"),
    (rf"\bgit\b{_SEG}\sreset\b{_SEG}--hard", "git_discard"),
    (rf"\bgit\b{_SEG}\sclean\b{_SEG}\s-\S*f", "git_discard"),
    (rf"\bgit\b{_SEG}\s(?:checkout|restore|switch)\b{_SEG}(?:\s--(?:\s|$)|\s\.(?:\s|$)|\s-f\b|--force|--discard-changes)", "git_discard"),
    (rf"\bgit\b{_SEG}\sbranch\b{_SEG}\s(?:-D\b|--force\b)", "git_discard"),
    (rf"\bgit\b{_SEG}\scommit\b{_SEG}--amend", "git_history_or_remote"),
    (rf"\bgit\b{_SEG}\sstash\s+(?:drop|clear)\b", "git_discard"),
    (rf"\bgit\b{_SEG}\sconfig\b{_SEG}(?:--global|--system|core\.hooksPath)", "git_config_global"),
    (rf"\b(?:gh|glab)\b{_SEG}\s(?:create|edit|close|reopen|merge|comment|review|delete|upload|run|enable|disable|set|fork|transfer|archive|rename|lock|ready|sync|approve)\b", "outbound_vcs_write"),
    (rf"\b(?:gh|glab)\s+api\b{_SEG}(?:(?:-X|--method)[=\s]*(?:POST|PUT|PATCH|DELETE)\b|\s(?:-f|-F|--field|--raw-field|--input)\b)", "outbound_vcs_write"),
    (r"\brepo\s+(?:upload|forall)\b", "outbound_vcs_write"),
    (r"\b(?:ssh|scp|sftp)\b|\brsync\b[^;&|\n]*\s\S+:\S*", "remote_exec"),
    (r"\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b", "pipe_to_shell"),
    (r"\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)\b(?!\s+-m\s+json\.tool)", "pipe_to_interpreter"),
    (r"\beval\b|\bbase64\s+(?:-d|-D|--decode)\b", "indirect_exec"),
    (rf"\b(?:curl|wget|https?|httpie)\b{_SEG}\s(?:-d\b|--data|-F\b|--form|-T\b|--upload-file|--post-data|--post-file|-X\s*(?:POST|PUT|PATCH|DELETE)\b|--request[=\s]+(?:POST|PUT|PATCH|DELETE)\b|--method=(?:POST|PUT|PATCH|DELETE)\b)", "outbound_http_write"),
    (rf"\bchmod\b{_SEG}\b(?:777|666|a\+w|o\+w)\b|\bchown\b", "permission_change"),
    (rf"\bdd\b{_SEG}\bof=|\bmkfs\b|\bfdisk\b|\bdiskutil\s+(?:erase|partition)|>\s*/dev/(?:sd|disk|nvme)", "disk_write"),
    (r"\bkill\s+-(?:9|KILL)\b|\bkillall\b|\bpkill\b", "process_kill"),
    (r"\bcrontab\b|\blaunchctl\b|\bsystemctl\b|\bservice\s+\S+\s+(?:start|stop|restart)\b", "system_service"),
    # Android device: data loss or device state. Plain `adb install` stays with Jev: it is the
    # most frequent dev action and only replaces a debug build.
    (rf"\badb\b{_SEG}\s(?:uninstall|push|reboot|root|unroot|remount|disable-verity|sideload|restore|backup)\b", "adb_device_write"),
    (rf"\badb\b{_SEG}\sshell\b{_SEG}(?:\brm\b|\bpm\s+(?:clear|uninstall|disable|hide|reset-permissions)\b|\bwipe\b|\breboot\b|\bsetprop\b|\bsettings\s+put\b|\bcmd\s+package\s+(?:uninstall|clear)\b)", "adb_device_write"),
    (r"\b(?:npm|yarn|pnpm)\s+(?:publish|unpublish|deprecate)\b|\btwine\s+upload\b|\bgem\s+push\b|\bcargo\s+publish\b|\bfastlane\b|\bmvn\b[^;&|\n]*\bdeploy\b", "publish_release"),
    (rf"\bgradlew?\b{_SEG}\b(?:publish\w*|upload\w*|bintrayUpload|release)\b", "publish_release"),
    (rf"\b(?:kubectl|oc)\b{_SEG}\s(?:apply|create|delete|edit|patch|replace|scale|rollout|drain|cordon|exec|cp)\b|\bhelm\s+(?:install|upgrade|uninstall|delete|rollback)\b|\bterraform\s+(?:apply|destroy|import)\b|\bdeploy\b", "infra_change"),
    (r"(?i)\b(?:drop\s+(?:table|database|schema|index|view)|truncate\s+table|delete\s+from|update\s+\S+\s+set|insert\s+(?:into|overwrite)|alter\s+table|grant\s|revoke\s)", "db_write"),
    (r"(?:~|\$HOME|/root|/Users/[^/\s]+|/home/[^/\s]+)/\.(?:ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|config/gcloud)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.(?:jks|keystore|p12|pem|pfx)\b|(?:^|[\s/'\"=])\.env(?:rc)?(?:\.[\w.-]+)?(?:\s|$|['\"])", "sensitive_path"),
    (r"(?:^|[;&|]\s*)(?:printenv|env)\s*(?:$|[;&|>])|/proc/\S*/environ|\bsecurity\s+(?:find|dump|export)-", "secret_dump"),
    (r"\.claude/(?:settings|hooks|agents|commands|skills)|jev-permission-gate|\.claude/jev-gate", "self_modification"),
]
_BASH_RULES = [(re.compile(p), r) for p, r in _BASH_RULES]

# Commit / PR message arguments are data, not code, but routinely contain words such as
# "push" or "release". Strip only forms the shell cannot expand.
_MSG_FLAG = r"(?:-m|--message|--body|--title)[=\s]+"
_MSG_SQ = re.compile(_MSG_FLAG + r"'[^']*'")
_MSG_DQ = re.compile(_MSG_FLAG + r'"(?:[^"\\$`]|\\[^$`])*"')
_MSG_HEREDOC = re.compile(
    _MSG_FLAG + r'"\$\(\s*cat\s+<<-?\s*([\'"])(\w+)\1[ \t]*\n(.*?)\n[ \t]*\2[ \t]*\n?\s*\)\s*"',
    re.S,
)


def _strip_heredoc_msg(m):
    delim, body = m.group(2), m.group(3)
    # The shell ends a heredoc at the first delimiter line, so anything after an earlier one
    # runs as a command. Only strip when the body has no such line.
    if any(line.strip() == delim for line in body.split("\n")):
        return m.group(0)
    return "-m MSG"


def strip_messages(command):
    command = _MSG_HEREDOC.sub(_strip_heredoc_msg, command)
    command = _MSG_SQ.sub("-m MSG", command)
    return _MSG_DQ.sub("-m MSG", command)


_REDIRECT = re.compile(r"(?:^|[^<>&0-9])>{1,2}\s*([^\s;&|<>]+)")
_TEE = re.compile(r"\btee\s+(?:-a\s+)?([^\s;&|]+)")
_SAFE_WRITE_PREFIXES = ("/dev/null", "/dev/stdout", "/dev/stderr", "/tmp/", "/private/tmp/")

_SENSITIVE_PATH_RULES = [
    (r"/\.(?:ssh|aws|gnupg|kube|docker)/", "sensitive_path"),
    (r"(?:^|/)\.env(?:rc)?(?:\.[\w.-]+)?$", "sensitive_path"),
    (r"\.(?:jks|keystore|p12|pem|pfx|key)$", "sensitive_path"),
    (r"(?:^|/)id_(?:rsa|ed25519|ecdsa)", "sensitive_path"),
    (r"(?:^|/)(?:gradle\.properties|\.npmrc|\.netrc|\.pypirc|credentials(?:\.json)?)$", "credentials_file"),
]
_WRITE_ONLY_PATH_RULES = [
    (r"/\.git/", "git_internals"),
    (r"/\.claude/(?:settings(?:\.local)?\.json$|hooks/|agents/|commands/|skills/)|/jev-permission-gate/|/\.claude/jev-gate/", "self_modification"),
    (r"/\.github/workflows/|(?:^|/)\.gitlab-ci\.yml$|(?:^|/)CODEOWNERS$|(?:^|/)Jenkinsfile$", "ci_config"),
]
_SENSITIVE_PATH_RULES = [(re.compile(p), r) for p, r in _SENSITIVE_PATH_RULES]
_WRITE_ONLY_PATH_RULES = [(re.compile(p), r) for p, r in _WRITE_ONLY_PATH_RULES]

_MCP_READ_VERBS = {"get", "list", "search", "read", "fetch", "query", "describe", "show",
                   "view", "find", "lookup", "count", "check", "inspect", "explain", "status"}
_MCP_WRITE_VERBS = {"send", "post", "publish", "reply", "forward", "delete", "remove", "trash",
                    "destroy", "drop", "merge", "push", "deploy", "transfer", "pay", "share",
                    "invite", "create", "update", "write", "edit", "move", "rename", "apply",
                    "execute", "run", "upload", "restore", "reset", "archive", "pause", "label",
                    "mark", "spawn", "stop", "enable", "disable", "subscribe", "trigger", "fire",
                    "set", "add", "comment", "review", "approve", "close", "lock"}

_MAX_COMMAND = 8000


def _under(path, root):
    try:
        path, root = os.path.realpath(path), os.path.realpath(root)
    except (OSError, ValueError):
        return False
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _write_target_outside(target, cwd):
    t = os.path.expanduser(target.strip("'\""))
    if t.startswith("$HOME"):
        t = os.path.expanduser("~") + t[len("$HOME"):]
    if t.startswith("&") or t.startswith("$"):
        return False  # fd duplication or unexpandable variable; other rules cover risky forms
    if any(t == p.rstrip("/") or t.startswith(p) for p in _SAFE_WRITE_PREFIXES):
        return False
    if not os.path.isabs(t):
        t = os.path.join(cwd or ".", t)
    return not _under(t, cwd or ".")


def _bash_reasons(command, cwd):
    if len(command) > _MAX_COMMAND:
        return ["oversized_input"]
    command = strip_messages(command)
    reasons = [r for pat, r in _BASH_RULES if pat.search(command)]
    for m in list(_REDIRECT.finditer(command)) + list(_TEE.finditer(command)):
        if _write_target_outside(m.group(1), cwd):
            reasons.append("write_outside_project")
            break
    return reasons


def _path_reasons(path, rules):
    norm = os.path.realpath(path)
    return [r for pat, r in rules if pat.search(norm) or pat.search(path)]


def _file_write_reasons(tool_input, cwd):
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if not path:
        return ["missing_path"]
    reasons = [] if _under(path, cwd or ".") else ["write_outside_project"]
    return reasons + _path_reasons(path, _SENSITIVE_PATH_RULES + _WRITE_ONLY_PATH_RULES)


def _file_read_reasons(tool_input):
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path") or ""
    return _path_reasons(path, _SENSITIVE_PATH_RULES) if path else []


def _mcp_reasons(tool_name):
    parts = tool_name.split("__")
    action = parts[-1] if len(parts) >= 3 else tool_name
    tokens = set(re.split(r"[_\-.]+", action.lower()))
    if tokens & _MCP_WRITE_VERBS or not tokens & _MCP_READ_VERBS:
        return ["mcp_write_or_unknown"]
    return []


def evaluate(event):
    """Return guard reasons for a PermissionRequest event; empty list means not guarded."""
    tool = event.get("tool_name") or ""
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    cwd = event.get("cwd") or ""
    reasons = []
    if event.get("permission_mode") == "plan":
        reasons.append("plan_mode")
    if tool in NEVER_AUTO_TOOLS:
        reasons.append("human_checkpoint_tool")
    if tool == "Bash":
        reasons += _bash_reasons(tool_input.get("command") or "", cwd)
    elif tool in FILE_WRITE_TOOLS:
        reasons += _file_write_reasons(tool_input, cwd)
    elif tool in FILE_READ_TOOLS:
        reasons += _file_read_reasons(tool_input)
    elif tool.startswith("mcp__"):
        reasons += _mcp_reasons(tool)
    return list(dict.fromkeys(reasons))
