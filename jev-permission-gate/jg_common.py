"""Shared helpers for the Jev permission gate: config, redaction, hashing, logging.

Stdlib only, so the hook starts fast and needs no install step.
"""

import hashlib
import json
import os
import re
import time

VERSION = "0.1.0"
PROTOCOL = "jev-permission/v1"

MODES = ("off", "shadow", "enforce")


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


def _env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self):
        self.dir = os.path.expanduser(os.environ.get("JEV_GATE_DIR", "~/.claude/jev-gate"))
        mode = os.environ.get("JEV_GATE_MODE", "shadow").strip().lower()
        self.mode = mode if mode in MODES else "shadow"
        # Kill switch: `touch ~/.claude/jev-gate/DISABLED` turns the gate off without editing settings.
        if os.path.exists(os.path.join(self.dir, "DISABLED")):
            self.mode = "off"
        self.url = os.environ.get("JEV_GATE_URL", "").strip()
        self.token = os.environ.get("JEV_GATE_TOKEN", "").strip()
        self.ca_bundle = os.environ.get("JEV_GATE_CA_BUNDLE", "").strip() or None
        self.timeout_ms = max(50.0, _env_float("JEV_GATE_TIMEOUT_MS", 300))
        self.allow_threshold = _env_float("JEV_GATE_ALLOW_THRESHOLD", 0.9)
        self.deny_threshold = _env_float("JEV_GATE_DENY_THRESHOLD", 0.9)
        self.enforce_deny = _env_bool("JEV_GATE_ENFORCE_DENY", True)
        self.notify = _env_bool("JEV_GATE_NOTIFY", True)
        self.log_max_bytes = int(_env_float("JEV_GATE_LOG_MAX_BYTES", 20 * 1024 * 1024))

    @property
    def decisions_log(self):
        return os.path.join(self.dir, "decisions.jsonl")

    @property
    def outcomes_log(self):
        return os.path.join(self.dir, "outcomes.jsonl")

    @property
    def errors_log(self):
        return os.path.join(self.dir, "errors.jsonl")


# --- hashing / keys -------------------------------------------------------

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def input_hash(tool_input):
    """Hash of the *original* tool_input; gate and recorder must agree on it to join."""
    return hashlib.sha256(canonical(tool_input or {}).encode("utf-8")).hexdigest()[:16]


_PRIMARY_FIELDS = ("command", "file_path", "notebook_path", "url", "path", "pattern", "query")


def primary_key(tool_input):
    """The field a human would recognise the request by; also a fallback join key."""
    if not isinstance(tool_input, dict):
        return ""
    for f in _PRIMARY_FIELDS:
        v = tool_input.get(f)
        if isinstance(v, str) and v:
            return v
    return ""


# --- redaction ------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[^\s'\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)\b((?:api[_-]?key|access[_-]?key|secret|token|passw(?:or)?d|pwd|credential)s?\s*[:=]\s*)['\"]?[^\s'\"&]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(--(?:password|token|secret|api-key)[=\s]+)[^\s'\"]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^@\s/]+@"), r"\1<redacted>@"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted-aws-key>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "<redacted-key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "<redacted-gh-token>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "<redacted-slack-token>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "<redacted-jwt>"),
]


def redact_str(s):
    for pat, repl in _SECRET_PATTERNS:
        s = pat.sub(repl, s)
    return s


# Fields carrying file bodies or edit payloads: never leave the machine, only their digest does.
_BULKY_KEYS = {"content", "new_string", "old_string", "new_source", "file_text", "text", "body"}
_MAX_STR = 8000


def _digest(s):
    return {"omitted": True, "len": len(s), "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]}


def sanitize(obj, key=None):
    """Redact secrets and drop bulky payloads before anything is sent to Jev or logged."""
    if isinstance(obj, dict):
        return {k: sanitize(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v, key) for v in obj]
    if isinstance(obj, str):
        if key in _BULKY_KEYS or len(obj) > _MAX_STR:
            return _digest(obj)
        return redact_str(obj)
    return obj


def preview(s, limit=300):
    s = redact_str(s or "")
    return s if len(s) <= limit else s[: limit - 1] + "…"


# --- logging --------------------------------------------------------------

def append_jsonl(path, record, max_bytes):
    """Best-effort append; logging must never break the hook."""
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        try:
            if os.path.getsize(path) > max_bytes:
                os.replace(path, path + ".1")
        except OSError:
            pass
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    except Exception:
        pass


def now():
    return time.time()
