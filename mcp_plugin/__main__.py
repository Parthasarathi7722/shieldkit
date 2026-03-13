"""Entry point for: python -m shieldkit.mcp_plugin"""
import asyncio
from .mcp_server import main

asyncio.run(main())
