"""
ShieldKit MCP Server — JSON-RPC over stdio.
Exposes ShieldKit's scanning, cloud, and log capabilities as MCP tools.
SOCPilot spawns this as a subprocess and communicates via JSON-RPC 2.0.

Usage:
  python -m shieldkit.mcp_plugin.mcp_server

SOCPilot mcp_config.json entry:
  "shieldkit": {
    "command": "python",
    "args": ["-m", "shieldkit.mcp_plugin.mcp_server"],
    "env": { "SHIELDKIT_MODE": "${SHIELDKIT_MODE}" }
  }
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any


# ── Tool Definitions (Anthropic tool_use spec) ──────────────────

SHIELDKIT_TOOLS = [
    {
        "name": "shieldkit_sbom",
        "description": "Generate a Software Bill of Materials (SBOM) for a container image, directory, or archive. Returns component inventory with names, versions, licenses, and PURLs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Image name (e.g. nginx:latest), directory path, or archive path"},
                "format": {"type": "string", "enum": ["cyclonedx-json", "spdx-json"], "default": "cyclonedx-json"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_sca",
        "description": "Run Software Composition Analysis — scan a target for known vulnerabilities in dependencies. Returns CVEs with severity, CVSS scores, and fix versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Image, directory, or SBOM file to scan"},
                "severity": {"type": "string", "description": "Filter by severity: critical,high,medium,low", "default": ""},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_container_scan",
        "description": "Scan a container image for OS and application vulnerabilities using Trivy. Returns vulnerabilities with severity, packages, and fix versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Container image (e.g. nginx:latest, myregistry.io/app:v1)"},
                "mode": {"type": "string", "enum": ["image", "fs", "config", "repo"], "default": "image"},
                "severity": {"type": "string", "description": "Filter: CRITICAL,HIGH,MEDIUM,LOW", "default": ""},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_url_scan",
        "description": "Scan URLs and web endpoints for vulnerabilities using Nuclei community templates. Detects CVEs, misconfigurations, exposed files, and security headers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to scan (e.g. https://example.com)"},
                "severity": {"type": "string", "description": "Filter: critical,high,medium,low,info", "default": ""},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_iac_scan",
        "description": "Scan Infrastructure as Code files for misconfigurations using Checkov. Supports Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, Helm, ARM, Bicep.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Path to IaC directory or file"},
                "framework": {"type": "string", "description": "Framework: terraform, cloudformation, kubernetes, dockerfile, helm", "default": ""},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_cloud_scan",
        "description": "Run cloud security posture assessment against CIS, SOC2, PCI-DSS, HIPAA. Supports AWS, Azure, GCP via Prowler or ScoutSuite.",
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["aws", "azure", "gcp"]},
                "tool": {"type": "string", "enum": ["prowler", "scoutsuite"], "default": "prowler"},
                "services": {"type": "array", "items": {"type": "string"}, "description": "Specific services to check (e.g. iam, s3, ec2). Empty = all."},
                "compliance": {"type": "array", "items": {"type": "string"}, "description": "Compliance frameworks (e.g. cis, soc2, pci-dss)"},
            },
            "required": ["provider"],
        },
    },
    {
        "name": "shieldkit_log_query",
        "description": "Query security logs stored in ShieldKit's DuckDB. Supports SQL queries or structured search by source, severity, actor, action, IP.",
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "Raw SQL query (e.g. SELECT * FROM logs WHERE severity='critical')"},
                "source": {"type": "string", "description": "Filter by source: cloudtrail, syslog, vpc-flow"},
                "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info"},
                "actor": {"type": "string", "description": "Search by actor/user"},
                "source_ip": {"type": "string", "description": "Filter by source IP"},
                "keyword": {"type": "string", "description": "Full-text keyword search"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "shieldkit_log_stats",
        "description": "Get aggregate statistics about ingested security logs — total count, sources, severity distribution, top actors, top actions, and time range.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "shieldkit_log_ingest",
        "description": "Ingest security logs from a source into ShieldKit's DuckDB store. Supports S3, CloudTrail, local files, and syslog.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_type": {"type": "string", "enum": ["s3", "cloudtrail", "file", "syslog"]},
                "config": {"type": "object", "description": "Source config. S3: {bucket, prefix, region}. File: {path, format}. Syslog: {host, port}."},
            },
            "required": ["source_type", "config"],
        },
    },
]


class ShieldKitMCPServer:
    """MCP server that communicates via JSON-RPC 2.0 over stdio."""

    def __init__(self):
        self.scanners = {}
        self.pipeline = None
        self.cloud = None
        self._initialized = False

    async def _ensure_init(self):
        if self._initialized:
            return
        from ..config import get_config
        from ..scanners import SBOMScanner, SCAScanner, ContainerScanner, URLScanner, IaCScanner
        from ..cloud import CloudManager
        from ..logs import LogPipeline, LogStore

        cfg = get_config()
        self.scanners = {
            "shieldkit_sbom": SBOMScanner(cfg.syft_bin),
            "shieldkit_sca": SCAScanner(cfg.grype_bin),
            "shieldkit_container_scan": ContainerScanner(cfg.trivy_bin),
            "shieldkit_url_scan": URLScanner(cfg.nuclei_bin),
            "shieldkit_iac_scan": IaCScanner(cfg.checkov_bin),
        }
        self.cloud = CloudManager(cfg.prowler_bin, cfg.scoutsuite_bin)
        store = LogStore(cfg.duckdb_path)
        self.pipeline = LogPipeline(store)
        self._initialized = True

    async def handle_request(self, request: dict) -> dict:
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return self._response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "shieldkit", "version": "1.0.0"},
            })

        elif method == "tools/list":
            return self._response(req_id, {"tools": SHIELDKIT_TOOLS})

        elif method == "tools/call":
            await self._ensure_init()
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            result = await self._call_tool(tool_name, arguments)
            return self._response(req_id, {
                "content": [{"type": "text", "text": json.dumps(result, default=str)}]
            })

        return self._error(req_id, -32601, f"Unknown method: {method}")

    async def _call_tool(self, name: str, args: dict) -> Any:
        from ..config import get_config
        from ..models import CloudProvider, LogSourceType
        cfg = get_config()
        mock = cfg.mock_mode

        if name in self.scanners:
            target = args.pop("target", "")
            return (await self.scanners[name].run(target, mock=mock, **args)).model_dump()

        elif name == "shieldkit_cloud_scan":
            provider = CloudProvider(args.get("provider", "aws"))
            return (await self.cloud.scan(
                provider, tool=args.get("tool", "prowler"),
                services=args.get("services"), compliance=args.get("compliance"),
                mock=mock,
            )).model_dump()

        elif name == "shieldkit_log_query":
            if args.get("sql"):
                return {"results": self.pipeline.query(args["sql"], args.get("limit", 50))}
            return {"results": self.pipeline.search(**{
                k: v for k, v in args.items() if k != "sql" and v
            })}

        elif name == "shieldkit_log_stats":
            return self.pipeline.stats().model_dump()

        elif name == "shieldkit_log_ingest":
            st = LogSourceType(args["source_type"])
            return await self.pipeline.ingest(st, args.get("config", {}))

        return {"error": f"Unknown tool: {name}"}

    def _response(self, req_id, result):
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _error(self, req_id, code, message):
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    async def run_stdio(self):
        """Main loop — read JSON-RPC from stdin, write responses to stdout."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, asyncio.get_event_loop())

        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                request = json.loads(line.decode().strip())
                response = await self.handle_request(request)
                output = json.dumps(response) + "\n"
                writer.write(output.encode())
                await writer.drain()
            except Exception as e:
                error_resp = self._error(None, -32700, str(e))
                writer.write((json.dumps(error_resp) + "\n").encode())
                await writer.drain()


async def main():
    server = ShieldKitMCPServer()
    await server.run_stdio()


if __name__ == "__main__":
    asyncio.run(main())
