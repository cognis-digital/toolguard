"""TOOLGUARD MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from toolguard.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-toolguard[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-toolguard[mcp]'")
        return 1
    app = FastMCP("toolguard")

    @app.tool()
    def toolguard_scan(target: str) -> str:
        """Runtime allowlist and policy for agent tool-calls. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
