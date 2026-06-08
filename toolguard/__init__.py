"""TOOLGUARD - Runtime allowlist and policy engine for agent tool-calls.

Guards an AI agent's tool invocations against a declarative policy:
allow/deny lists, per-argument constraints, rate limits, and sensitive
data redaction. Standard library only, zero install.
"""

from .core import (
    Policy,
    PolicyError,
    Decision,
    Guard,
    load_policy,
    DEFAULT_POLICY,
)

TOOL_NAME = "toolguard"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Policy",
    "PolicyError",
    "Decision",
    "Guard",
    "load_policy",
    "DEFAULT_POLICY",
    "TOOL_NAME",
    "TOOL_VERSION",
]
