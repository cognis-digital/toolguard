"""Smoke tests for TOOLGUARD. Standard library unittest, no network."""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from toolguard import TOOL_NAME, TOOL_VERSION, Guard, Policy, load_policy, DEFAULT_POLICY
from toolguard.core import PolicyError, RateLimit
from toolguard import cli


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class TestMetadata(unittest.TestCase):
    def test_name_version(self):
        self.assertEqual(TOOL_NAME, "toolguard")
        self.assertTrue(TOOL_VERSION)


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.guard = Guard(load_policy(DEFAULT_POLICY))

    def test_denylist_blocks(self):
        d = self.guard.check("shell_exec", {"cmd": "rm -rf /"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.action, "deny")
        self.assertIn("denylist", d.reason)

    def test_allowlist_allows(self):
        d = self.guard.check("read_file", {"path": "README.md"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.action, "allow")

    def test_not_on_allowlist_denied_by_default(self):
        d = self.guard.check("unknown_tool", {})
        self.assertFalse(d.allowed)
        self.assertIn("allowlist", d.reason)

    def test_arg_pattern_blocks_ssrf(self):
        d = self.guard.check("http_get", {"url": "http://169.254.169.254/meta"})
        self.assertFalse(d.allowed)
        self.assertIn("pattern", d.reason)

    def test_sensitive_path_blocked(self):
        d = self.guard.check("read_file", {"path": "/home/x/.ssh/id_rsa"})
        self.assertFalse(d.allowed)

    def test_redaction(self):
        d = self.guard.check("web_search", {"query": "x api_key=sk-abcdef0123456789ABCD"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.action, "redact")
        self.assertIn("[REDACTED]", d.arguments["query"])
        self.assertIn("query", d.redactions)

    def test_rate_limit(self):
        clock = FakeClock()
        guard = Guard(load_policy(DEFAULT_POLICY), clock=clock)
        for _ in range(10):
            self.assertTrue(guard.check("http_get", {"url": "https://ok.example"}).allowed)
        blocked = guard.check("http_get", {"url": "https://ok.example"})
        self.assertFalse(blocked.allowed)
        self.assertIn("rate limit", blocked.reason)
        clock.advance(61)
        self.assertTrue(guard.check("http_get", {"url": "https://ok.example"}).allowed)


class TestPolicyValidation(unittest.TestCase):
    def test_bad_default_action(self):
        with self.assertRaises(PolicyError):
            load_policy({"default_action": "maybe"})

    def test_bad_regex(self):
        with self.assertRaises(PolicyError):
            load_policy({"redact_patterns": ["("]})

    def test_bad_rate_limit(self):
        with self.assertRaises(PolicyError):
            RateLimit.from_dict({"max_calls": 0, "window_seconds": 10})

    def test_load_from_json_string(self):
        p = load_policy(json.dumps({"deny": ["x"]}))
        self.assertIsInstance(p, Policy)
        self.assertEqual(p.deny, ["x"])


class TestCli(unittest.TestCase):
    def _run(self, argv, stdin=None):
        old_in, old_out = sys.stdin, sys.stdout
        sys.stdout = io.StringIO()
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            code = cli.main(argv)
            return code, sys.stdout.getvalue()
        finally:
            sys.stdin, sys.stdout = old_in, old_out

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_check_allow(self):
        code, out = self._run(["--format", "json", "check", "--tool", "read_file", "--arg", "path=README.md"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["summary"]["denied"], 0)

    def test_check_deny_nonzero_exit(self):
        code, out = self._run(["--format", "json", "check", "--tool", "shell_exec", "--arg", "cmd=ls"])
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual(data["summary"]["denied"], 1)

    def test_audit_stdin(self):
        calls = json.dumps([
            {"tool": "read_file", "arguments": {"path": "a.txt"}},
            {"tool": "delete_file", "arguments": {"path": "a.txt"}},
        ])
        code, out = self._run(["--format", "json", "audit"], stdin=calls)
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual(data["summary"]["total"], 2)
        self.assertEqual(data["summary"]["denied"], 1)

    def test_policy_command(self):
        code, out = self._run(["policy"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("deny", data)

    def test_no_command_returns_1(self):
        code, _ = self._run([])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
