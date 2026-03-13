"""
Base scanner class and tool-check utility.
All scanners inherit from BaseScanner for consistent async execution.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from ..models import ScanResult, ScanType, ToolStatus


async def check_tool(name: str, binary: str) -> ToolStatus:
    """Check if a CLI tool is installed and return version info."""
    path = shutil.which(binary)
    if not path:
        return ToolStatus(name=name, installed=False, error=f"{binary} not found in PATH")
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        version = (stdout or stderr).decode().strip().split("\n")[0]
        return ToolStatus(name=name, installed=True, version=version, path=path)
    except Exception as e:
        return ToolStatus(name=name, installed=True, path=path, error=str(e))


class BaseScanner(ABC):
    """Base class for all ShieldKit scanners."""

    scan_type: ScanType
    tool_name: str
    binary: str

    def __init__(self, binary_override: str = ""):
        if binary_override:
            self.binary = binary_override

    async def check(self) -> ToolStatus:
        return await check_tool(self.tool_name, self.binary)

    async def run(self, target: str, **options) -> ScanResult:
        """Execute scan and return structured result."""
        result = ScanResult(
            scan_type=self.scan_type,
            target=target,
            tool=self.tool_name,
            started_at=datetime.utcnow(),
        )
        try:
            result = await self._execute(target, result, **options)
            result.status = "completed"
            result.completed_at = datetime.utcnow()
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.completed_at = datetime.utcnow()
        return result

    @abstractmethod
    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        """Override in subclass to implement actual scan logic."""
        ...

    async def _run_cmd(self, cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
        """Run a CLI command and return (stdout, stderr, returncode)."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(), stderr.decode(), proc.returncode or 0

    def _parse_json(self, raw: str) -> Any:
        """Safely parse JSON output from a CLI tool."""
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
