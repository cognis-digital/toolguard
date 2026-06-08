"""Command-line interface for TOOLGUARD.

Subcommands:
  check    Evaluate one tool-call (from flags or stdin JSON) against a policy.
  audit    Evaluate a batch of tool-calls (JSON array) and summarize.
  policy   Print the active/default policy as JSON.

Exit status is non-zero when any evaluated call is denied (so it can gate
an agent run in CI / runtime), or on usage/policy errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import DEFAULT_POLICY, Decision, Guard, PolicyError, load_policy


def _load_policy_arg(path: Optional[str]):
    if not path:
        return load_policy(DEFAULT_POLICY)
    return load_policy(path)


def _read_stdin_json() -> Any:
    data = sys.stdin.read().strip()
    if not data:
        return None
    return json.loads(data)


def _parse_kv_args(items: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"argument must be key=value, got {item!r}")
        key, val = item.split("=", 1)
        out[key] = val
    return out


def _print(payload: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    # table format
    if isinstance(payload, dict) and "results" in payload:
        rows = payload["results"]
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = [payload]
    print(f"{'TOOL':<20} {'ACTION':<8} {'ALLOWED':<8} REASON")
    print("-" * 72)
    for r in rows:
        print(f"{str(r.get('tool','')):<20} {str(r.get('action','')):<8} "
              f"{str(r.get('allowed','')):<8} {r.get('reason','')}")


def _decisions_to_payload(decisions: List[Decision]) -> Dict[str, Any]:
    results = [d.to_dict() for d in decisions]
    denied = sum(1 for d in decisions if not d.allowed)
    redacted = sum(1 for d in decisions if d.action == "redact")
    return {
        "results": results,
        "summary": {
            "total": len(decisions),
            "denied": denied,
            "redacted": redacted,
            "allowed": len(decisions) - denied,
        },
    }


def _cmd_check(args: argparse.Namespace) -> int:
    guard = Guard(_load_policy_arg(args.policy))
    if args.tool:
        call_args = _parse_kv_args(args.arg or [])
        decisions = [guard.check(args.tool, call_args)]
    else:
        payload = _read_stdin_json()
        if payload is None:
            raise ValueError("no --tool given and stdin is empty")
        if isinstance(payload, list):
            decisions = [guard.check(c.get("tool", ""), c.get("arguments")) for c in payload]
        else:
            decisions = [guard.check(payload.get("tool", ""), payload.get("arguments"))]
    out = _decisions_to_payload(decisions)
    _print(out if args.format == "json" else out, args.format)
    return 0 if out["summary"]["denied"] == 0 else 2


def _cmd_audit(args: argparse.Namespace) -> int:
    guard = Guard(_load_policy_arg(args.policy))
    if args.input:
        with open(args.input, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        payload = _read_stdin_json()
    if not isinstance(payload, list):
        raise ValueError("audit expects a JSON array of {tool, arguments} calls")
    decisions = [guard.check(c.get("tool", ""), c.get("arguments")) for c in payload]
    out = _decisions_to_payload(decisions)
    _print(out, args.format)
    return 0 if out["summary"]["denied"] == 0 else 2


def _cmd_policy(args: argparse.Namespace) -> int:
    policy = _load_policy_arg(args.policy)
    # Round-trip through the loader to validate, then dump.
    from dataclasses import asdict
    _print(asdict(policy), "json")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Runtime allowlist and policy for agent tool-calls.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")
    sub = parser.add_subparsers(dest="command")

    pc = sub.add_parser("check", help="evaluate a single tool-call (flags or stdin JSON)")
    pc.add_argument("--policy", help="path to a JSON policy file (default: built-in)")
    pc.add_argument("--tool", help="tool name to check")
    pc.add_argument("--arg", action="append", help="tool argument as key=value (repeatable)")
    pc.set_defaults(func=_cmd_check)

    pa = sub.add_parser("audit", help="evaluate a batch of tool-calls from a JSON array")
    pa.add_argument("--policy", help="path to a JSON policy file (default: built-in)")
    pa.add_argument("--input", help="path to JSON array file (default: stdin)")
    pa.set_defaults(func=_cmd_audit)

    pp = sub.add_parser("policy", help="print the active (or default) policy as JSON")
    pp.add_argument("--policy", help="path to a JSON policy file (default: built-in)")
    pp.set_defaults(func=_cmd_policy)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except (PolicyError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(json.dumps({"error": f"file not found: {exc.filename}"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
