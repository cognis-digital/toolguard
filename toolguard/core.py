"""Core policy engine for TOOLGUARD.

A Guard evaluates each tool-call against an ordered set of rules and
returns a Decision: allow, deny, or redact (allow with arguments scrubbed).

Rule semantics (evaluated in order, first match wins per stage):
  1. Tool must appear on the allowlist (if an allowlist is defined).
  2. Tool must NOT appear on the denylist.
  3. Per-tool argument constraints (deny_args regex patterns) are checked.
  4. Rate limits (max calls per tool within a sliding window) are enforced.
  5. Sensitive argument values matching redact_patterns are masked.

The engine is deterministic and side-effect free except for the in-memory
call-history used for rate limiting.
"""

from __future__ import annotations

import json
import re
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Deque, Dict, List, Optional, Tuple


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


@dataclass
class RateLimit:
    max_calls: int
    window_seconds: float

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RateLimit":
        try:
            mc = int(d["max_calls"])
            ws = float(d["window_seconds"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"invalid rate_limit: {d!r} ({exc})") from exc
        if mc <= 0 or ws <= 0:
            raise PolicyError(f"rate_limit values must be positive: {d!r}")
        return cls(max_calls=mc, window_seconds=ws)


@dataclass
class ToolRule:
    """Per-tool constraints applied after allow/deny list checks."""

    deny_args: Dict[str, str] = field(default_factory=dict)  # arg -> regex
    rate_limit: Optional[RateLimit] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ToolRule":
        deny_args = d.get("deny_args", {}) or {}
        if not isinstance(deny_args, dict):
            raise PolicyError("deny_args must be an object of arg->pattern")
        # Validate each regex compiles up front.
        for arg, pat in deny_args.items():
            try:
                re.compile(pat)
            except re.error as exc:
                raise PolicyError(f"bad regex for arg {arg!r}: {exc}") from exc
        rl = d.get("rate_limit")
        return cls(
            deny_args={str(k): str(v) for k, v in deny_args.items()},
            rate_limit=RateLimit.from_dict(rl) if rl else None,
        )


@dataclass
class Policy:
    allow: Optional[List[str]] = None  # None => any tool allowed
    deny: List[str] = field(default_factory=list)
    tools: Dict[str, ToolRule] = field(default_factory=dict)
    redact_patterns: List[str] = field(default_factory=list)
    default_action: str = "allow"  # allow | deny (for tools not on allowlist)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Policy":
        if not isinstance(d, dict):
            raise PolicyError("policy must be a JSON object")
        default_action = d.get("default_action", "allow")
        if default_action not in ("allow", "deny"):
            raise PolicyError("default_action must be 'allow' or 'deny'")
        allow = d.get("allow")
        if allow is not None and not isinstance(allow, list):
            raise PolicyError("allow must be a list or omitted")
        deny = d.get("deny", []) or []
        if not isinstance(deny, list):
            raise PolicyError("deny must be a list")
        tools_raw = d.get("tools", {}) or {}
        if not isinstance(tools_raw, dict):
            raise PolicyError("tools must be an object")
        redact = d.get("redact_patterns", []) or []
        if not isinstance(redact, list):
            raise PolicyError("redact_patterns must be a list")
        for pat in redact:
            try:
                re.compile(pat)
            except re.error as exc:
                raise PolicyError(f"bad redact pattern {pat!r}: {exc}") from exc
        tools = {str(name): ToolRule.from_dict(rule) for name, rule in tools_raw.items()}
        return cls(
            allow=[str(a) for a in allow] if allow is not None else None,
            deny=[str(x) for x in deny],
            tools=tools,
            redact_patterns=[str(p) for p in redact],
            default_action=default_action,
        )


@dataclass
class Decision:
    tool: str
    action: str  # allow | deny | redact
    allowed: bool
    reason: str
    redactions: List[str] = field(default_factory=list)
    arguments: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


DEFAULT_POLICY: Dict[str, Any] = {
    "default_action": "deny",
    "allow": ["read_file", "list_dir", "web_search", "http_get"],
    "deny": ["shell_exec", "delete_file"],
    "tools": {
        "http_get": {
            "deny_args": {"url": r"(?i)(localhost|127\.0\.0\.1|169\.254|metadata)"},
            "rate_limit": {"max_calls": 10, "window_seconds": 60},
        },
        "read_file": {
            "deny_args": {"path": r"(?i)(/etc/shadow|\.ssh/|\.env$|id_rsa)"}
        },
    },
    "redact_patterns": [
        r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*\S+",
        r"sk-[A-Za-z0-9]{16,}",
    ],
}


def load_policy(source: Any) -> Policy:
    """Load a Policy from a dict, JSON string, or file path."""
    if isinstance(source, Policy):
        return source
    if isinstance(source, dict):
        return Policy.from_dict(source)
    if isinstance(source, str):
        text = source
        # Treat as a path if it looks like one and exists.
        try:
            with open(source, "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, ValueError):
            pass
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy is not valid JSON: {exc}") from exc
        return Policy.from_dict(data)
    raise PolicyError(f"unsupported policy source type: {type(source).__name__}")


class Guard:
    """Stateful guard that evaluates tool-calls against a Policy."""

    def __init__(self, policy: Policy, *, clock=time.monotonic):
        self.policy = policy
        self._clock = clock
        self._history: Dict[str, Deque[float]] = {}

    # -- public API ---------------------------------------------------

    def check(self, tool: str, arguments: Optional[Dict[str, Any]] = None) -> Decision:
        args = dict(arguments or {})
        p = self.policy

        # Stage 1: explicit denylist always wins.
        if tool in p.deny:
            return Decision(tool, "deny", False, f"tool '{tool}' is on the denylist", arguments=args)

        # Stage 2: allowlist membership.
        if p.allow is not None and tool not in p.allow:
            if p.default_action == "deny":
                return Decision(tool, "deny", False, f"tool '{tool}' is not on the allowlist", arguments=args)

        # Stage 3: per-argument denial patterns.
        rule = p.tools.get(tool)
        if rule:
            for arg, pattern in rule.deny_args.items():
                if arg in args and re.search(pattern, str(args[arg])):
                    return Decision(
                        tool, "deny", False,
                        f"argument '{arg}' matched denied pattern",
                        arguments=args,
                    )

        # Stage 4: rate limiting.
        if rule and rule.rate_limit:
            if not self._within_rate_limit(tool, rule.rate_limit):
                return Decision(
                    tool, "deny", False,
                    f"rate limit exceeded ({rule.rate_limit.max_calls}/{rule.rate_limit.window_seconds}s)",
                    arguments=args,
                )

        # Stage 5: redaction of sensitive argument values.
        redacted_args, hits = self._redact(args)
        if hits:
            return Decision(
                tool, "redact", True,
                f"allowed with {len(hits)} redaction(s)",
                redactions=hits, arguments=redacted_args,
            )

        return Decision(tool, "allow", True, "allowed by policy", arguments=args)

    def reset(self) -> None:
        """Clear rate-limit history."""
        self._history.clear()

    # -- internals ----------------------------------------------------

    def _within_rate_limit(self, tool: str, rl: RateLimit) -> bool:
        now = self._clock()
        hist = self._history.setdefault(tool, deque())
        cutoff = now - rl.window_seconds
        while hist and hist[0] < cutoff:
            hist.popleft()
        if len(hist) >= rl.max_calls:
            return False
        hist.append(now)
        return True

    def _redact(self, args: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        patterns = self.policy.redact_patterns
        if not patterns:
            return args, []
        hits: List[str] = []
        out: Dict[str, Any] = {}
        for key, value in args.items():
            if isinstance(value, str):
                new_val = value
                for pat in patterns:
                    new_val, n = re.subn(pat, "[REDACTED]", new_val)
                    if n:
                        hits.append(key)
                out[key] = new_val
            else:
                out[key] = value
        return out, sorted(set(hits))
