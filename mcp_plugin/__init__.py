"""ShieldKit MCP Plugin — Exposes ShieldKit as an MCP server for SOCPilot integration"""

from .mcp_server import ShieldKitMCPServer, SHIELDKIT_TOOLS

__all__ = ["ShieldKitMCPServer", "SHIELDKIT_TOOLS"]
