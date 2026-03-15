"""
ShieldKit Server — FastAPI application with REST + WebSocket + SSE.
Endpoints: scanning, cloud checks, log ingestion/query, tool status, onboarding.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
from pydantic import BaseModel

from .config import get_config
from .models import (
    CloudProvider, CloudScanRequest, LogIngestRequest, LogSourceType,
    ScanRequest, ScanType, ToolStatus,
)
from .scanners import SBOMScanner, SCAScanner, ContainerScanner, URLScanner, IaCScanner, ZAPScanner, check_tool
from .cloud import CloudManager
from .logs import LogPipeline, LogStore


# ── Globals ──────────────────────────────────────────────────────

_pipeline: LogPipeline | None = None
_cloud: CloudManager | None = None
_s3_sync = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pipeline, _cloud, _s3_sync
    cfg = get_config()

    # Resolve DB connection string (handles local / MotherDuck / S3 / Postgres)
    from .db_backends import load_db_config, get_connection_string, S3SyncManager
    db_cfg = load_db_config()
    backend = db_cfg.get("backend", "local")

    # S3 sync: pull latest DB file before connecting
    _s3_sync = None
    if backend == "s3_sync":
        _s3_sync = S3SyncManager(db_cfg)
        result = _s3_sync.download()
        print(f"[DB] S3 sync download: {result}")

    try:
        conn_str = get_connection_string(db_cfg)
    except Exception as e:
        print(f"[DB] Backend config error: {e} — falling back to local file")
        conn_str = cfg.duckdb_path

    store = LogStore(conn_str)
    _pipeline = LogPipeline(store)
    _cloud = CloudManager(cfg.prowler_bin, cfg.scoutsuite_bin)
    yield

    # S3 sync: push DB file on clean shutdown
    if _s3_sync:
        if _pipeline:
            _pipeline.close()
        result = _s3_sync.upload()
        print(f"[DB] S3 sync upload on shutdown: {result}")
    elif _pipeline:
        _pipeline.close()


app = FastAPI(
    title="ShieldKit",
    description="Security scanning, cloud posture, and log analytics suite",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Health ───────────────────────────────────────────────────────

@app.get("/health")
async def health():
    cfg = get_config()
    return {
        "status": "ok",
        "mode": "mock" if cfg.mock_mode else "live",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Tool Status ──────────────────────────────────────────────────

@app.get("/tools/status")
async def tools_status():
    """Check installation status of all security tools."""
    cfg = get_config()
    checks = await asyncio.gather(
        check_tool("syft", cfg.syft_bin),
        check_tool("grype", cfg.grype_bin),
        check_tool("trivy", cfg.trivy_bin),
        check_tool("nuclei", cfg.nuclei_bin),
        check_tool("prowler", cfg.prowler_bin),
        check_tool("checkov", cfg.checkov_bin),
        check_tool("scoutsuite", cfg.scoutsuite_bin),
        _check_zap(cfg),
    )
    return {"tools": [t.model_dump() for t in checks]}


async def _check_zap(cfg) -> ToolStatus:
    """Check if ZAP is available via Docker image or native binary."""
    # Check Docker image
    if shutil.which("docker"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "images", cfg.zap_docker_image, "--format", "{{.Tag}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            tag = stdout.decode().strip()
            if tag:
                return ToolStatus(name="zap", installed=True, version=f"Docker:{tag}", path="docker")
        except Exception:
            pass
        return ToolStatus(
            name="zap", installed=False,
            error="Docker image not pulled. Run: docker pull ghcr.io/zaproxy/zaproxy:stable",
        )
    # Check native binary
    for binary in ("zap.sh", "zap-x.sh", "zaproxy"):
        path = shutil.which(binary)
        if path:
            return ToolStatus(name="zap", installed=True, version="native", path=path)
    return ToolStatus(name="zap", installed=False, error="ZAP not found. Install via Docker or native package.")


# ── Tool Management ──────────────────────────────────────────────

_TOOL_CONFIGS_PATH = Path(__file__).resolve().parent / "data" / "tool_configs.json"


def _load_tool_configs() -> dict[str, Any]:
    """Load persisted tool configurations."""
    if _TOOL_CONFIGS_PATH.exists():
        try:
            return json.loads(_TOOL_CONFIGS_PATH.read_text())
        except Exception:
            pass
    return {}


def _save_tool_configs(configs: dict[str, Any]) -> None:
    """Persist tool configurations to disk."""
    _TOOL_CONFIGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _TOOL_CONFIGS_PATH.write_text(json.dumps(configs, indent=2))


# ── Policy Storage ────────────────────────────────────────────────

_POLICIES_FILE = Path(__file__).resolve().parent / "data" / "tool_policies.json"


def _load_tool_policies() -> dict[str, Any]:
    """Load persisted tool scan policies."""
    if _POLICIES_FILE.exists():
        try:
            return json.loads(_POLICIES_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_tool_policies(data: dict[str, Any]) -> None:
    """Persist tool scan policies to disk."""
    _POLICIES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _POLICIES_FILE.write_text(json.dumps(data, indent=2))


@app.get("/tools/config")
async def get_all_tool_configs():
    """Get saved configuration for all tools."""
    return {"configs": _load_tool_configs()}


@app.get("/tools/config/{tool_name}")
async def get_tool_config(tool_name: str):
    """Get saved configuration for a specific tool."""
    configs = _load_tool_configs()
    return {"tool": tool_name, "config": configs.get(tool_name, {})}


class ToolConfigReq(BaseModel):
    config: dict[str, Any]


@app.post("/tools/config/{tool_name}")
async def save_tool_config(tool_name: str, req: ToolConfigReq):
    """Save configuration for a tool. Applies to environment for current session."""
    cfg = get_config()
    registry = cfg.tool_registry

    if tool_name not in registry and tool_name != "zap":
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")

    configs = _load_tool_configs()
    configs[tool_name] = req.config
    _save_tool_configs(configs)

    # Apply to current environment (session-level), resolving sk:// references
    provider = get_provider()
    has_refs = any(is_secret_ref(v) for v in req.config.values() if isinstance(v, str))
    if has_refs:
        try:
            resolved = await resolve_config_dict(req.config, provider)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Secret resolution failed: {e}")
    else:
        resolved = req.config

    for key, value in resolved.items():
        if isinstance(value, str):
            os.environ[key] = value

    return {"status": "saved", "tool": tool_name, "config": req.config, "refs_resolved": has_refs}


class ToolInstallReq(BaseModel):
    method: str = "default"  # matches an id in the tool's install_methods array


def _get_install_command(tool_info: dict, method_id: str) -> str:
    """Resolve install command from the install_methods array in the registry."""
    methods: list[dict] = tool_info.get("install_methods", [])
    # Try exact match first
    for m in methods:
        if m.get("id") == method_id:
            return m.get("cmd", "")
    # Fall back to first available method
    if methods:
        return methods[0].get("cmd", "")
    return ""


@app.post("/tools/install/{tool_name}")
async def install_tool(tool_name: str, req: ToolInstallReq):
    """Run the installation command for a tool using the specified method."""
    reg_path = Path(__file__).resolve().parent / "tool_registry.json"
    if not reg_path.exists():
        raise HTTPException(status_code=500, detail="tool_registry.json not found")

    registry_raw = json.loads(reg_path.read_text())
    tool_info = {
        k: v for k, v in registry_raw.get("tools", {}).items()
        if not k.startswith("__comment")
    }.get(tool_name)

    if not tool_info:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")

    command = _get_install_command(tool_info, req.method)
    if not command:
        raise HTTPException(status_code=400, detail=f"No install method '{req.method}' for {tool_name}")

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        success = proc.returncode == 0
        return {
            "status": "success" if success else "failed",
            "tool": tool_name,
            "method": req.method,
            "command": command,
            "stdout": stdout.decode()[:3000],
            "stderr": stderr.decode()[:1000],
            "returncode": proc.returncode,
        }
    except asyncio.TimeoutError:
        return {"status": "timeout", "tool": tool_name, "command": command}
    except Exception as exc:
        return {"status": "error", "tool": tool_name, "error": str(exc), "command": command}


@app.get("/tools/registry")
async def get_tool_registry():
    """Return the full tool registry with metadata."""
    cfg = get_config()
    reg = Path(__file__).resolve().parent / "tool_registry.json"
    if reg.exists():
        return json.loads(reg.read_text())
    return {"tools": cfg.tool_registry, "tiers": {}}


# ── Secrets Manager Endpoints ────────────────────────────────────

from .secrets_manager import (
    get_provider, invalidate_provider_cache,
    load_secrets_config, save_secrets_config,
    resolve_config_dict, is_secret_ref,
    PROVIDER_METADATA, SK_REF_PREFIX,
)
from .db_backends import (
    load_db_config, save_db_config, get_connection_string,
    test_db_connection, S3SyncManager, BACKEND_METADATA,
)


@app.get("/secrets/providers")
async def list_secrets_providers():
    """Return all supported secrets provider types with their UI field definitions."""
    return {"providers": PROVIDER_METADATA}


@app.get("/secrets/config")
async def get_secrets_config():
    """Return current secrets provider config (tokens/keys masked)."""
    cfg = load_secrets_config()
    # Mask any token/key values
    safe = {k: ("***" if any(s in k.lower() for s in ("token", "key", "password", "secret")) else v)
            for k, v in cfg.items()}
    return {"config": safe}


class SecretsConfigReq(BaseModel):
    config: dict[str, Any]


@app.post("/secrets/config")
async def save_secrets_config_endpoint(req: SecretsConfigReq):
    """Save and activate secrets provider configuration."""
    save_secrets_config(req.config)
    invalidate_provider_cache()
    # Merge sensitive fields into environment (not persisted to file)
    for k, v in req.config.items():
        if v and v != "***":
            os.environ[k.upper()] = v
    return {"status": "saved", "provider": req.config.get("provider", "local_encrypted")}


@app.post("/secrets/test")
async def test_secrets_provider(req: SecretsConfigReq):
    """Test connectivity to the configured secrets provider."""
    try:
        from .secrets_manager import _build_provider
        provider = _build_provider(req.config)
        result = await provider.test()
        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}


class SecretSetReq(BaseModel):
    key: str
    value: str


@app.post("/secrets/set")
async def set_secret(req: SecretSetReq):
    """Store a secret in the active provider."""
    try:
        provider = get_provider()
        await provider.set(req.key, req.value)
        return {"status": "stored", "key": req.key, "ref": f"{SK_REF_PREFIX}{req.key}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/secrets/list")
async def list_secrets():
    """List secret key names (never values) from the active provider."""
    try:
        provider = get_provider()
        keys = await provider.list_keys()
        refs = [f"{SK_REF_PREFIX}{k}" for k in keys]
        return {"keys": keys, "refs": refs, "count": len(keys)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/secrets/{key:path}")
async def delete_secret(key: str):
    """Delete a secret from the active provider."""
    try:
        provider = get_provider()
        await provider.delete(key)
        return {"status": "deleted", "key": key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/secrets/resolve")
async def resolve_secret_ref(req: SecretSetReq):
    """Resolve a sk:// reference and return the plaintext value (for debugging/CI)."""
    if not is_secret_ref(req.key):
        raise HTTPException(status_code=400, detail="Value must start with sk://")
    try:
        from .secrets_manager import resolve_ref
        value = await resolve_ref(req.key)
        return {"resolved": True, "key": req.key[len(SK_REF_PREFIX):], "value": value}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Database Backend Endpoints ────────────────────────────────────

@app.get("/db/backends")
async def list_db_backends():
    """Return all supported database backend types with UI field definitions."""
    return {"backends": BACKEND_METADATA}


@app.get("/db/config")
async def get_db_config():
    """Return current database backend configuration."""
    cfg = load_db_config()
    safe = {k: ("***" if any(s in k.lower() for s in ("token", "password", "url")) else v)
            for k, v in cfg.items()}
    return {"config": safe}


class DBConfigReq(BaseModel):
    config: dict[str, Any]


@app.post("/db/config")
async def save_db_config_endpoint(req: DBConfigReq):
    """Save database backend configuration. Requires server restart to take effect."""
    save_db_config(req.config)
    # Store sensitive values in environment
    for k, v in req.config.items():
        if v and v != "***":
            os.environ[k.upper()] = str(v)
    return {
        "status": "saved",
        "backend": req.config.get("backend", "local"),
        "note": "Restart the server to apply the new database backend.",
    }


@app.post("/db/test")
async def test_db_backend(req: DBConfigReq):
    """Test connectivity to the configured database backend."""
    try:
        result = await test_db_connection(req.config)
        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/db/sync")
async def sync_db_to_s3():
    """Manually trigger an S3 sync upload (S3 backend only)."""
    cfg = load_db_config()
    if cfg.get("backend") != "s3_sync":
        raise HTTPException(status_code=400, detail="S3 sync is not the active backend")
    result = S3SyncManager(cfg).upload()
    return result


@app.get("/db/status")
async def db_status():
    """Return current database connection info and stats."""
    cfg = load_db_config()
    backend = cfg.get("backend", "local")
    try:
        if _pipeline and _pipeline.store and _pipeline.store.conn:
            row = _pipeline.store.conn.execute(
                "SELECT COUNT(*) FROM logs"
            ).fetchone()
            log_count = row[0] if row else 0
            scan_row = _pipeline.store.conn.execute(
                "SELECT COUNT(*) FROM scan_results"
            ).fetchone()
            scan_count = scan_row[0] if scan_row else 0
        else:
            log_count = scan_count = 0
    except Exception:
        log_count = scan_count = 0

    return {
        "backend": backend,
        "connected": _pipeline is not None,
        "log_count": log_count,
        "scan_count": scan_count,
        "motherduck": backend == "motherduck",
        "s3_sync": backend == "s3_sync",
    }


# ── Policy Endpoints ──────────────────────────────────────────────

class ToolPolicyReq(BaseModel):
    policy: dict[str, Any]  # {name, description, settings}


@app.get("/tools/policies/{tool_name}")
async def get_tool_policies(tool_name: str):
    """Get all saved scan policies for a tool."""
    all_policies = _load_tool_policies()
    return {"tool": tool_name, "policies": all_policies.get(tool_name, [])}


@app.post("/tools/policies/{tool_name}")
async def upsert_tool_policy(tool_name: str, req: ToolPolicyReq):
    """Create or update a named scan policy for a tool."""
    policy = req.policy
    if not policy.get("name"):
        raise HTTPException(status_code=400, detail="policy.name is required")
    all_policies = _load_tool_policies()
    tool_policies: list = all_policies.get(tool_name, [])
    idx = next((i for i, p in enumerate(tool_policies) if p.get("name") == policy["name"]), None)
    if idx is not None:
        tool_policies[idx] = policy
    else:
        tool_policies.append(policy)
    all_policies[tool_name] = tool_policies
    _save_tool_policies(all_policies)
    return {"status": "saved", "tool": tool_name, "policy": policy}


@app.delete("/tools/policies/{tool_name}/{policy_name}")
async def delete_tool_policy(tool_name: str, policy_name: str):
    """Delete a named scan policy for a tool."""
    all_policies = _load_tool_policies()
    tool_policies = all_policies.get(tool_name, [])
    before = len(tool_policies)
    tool_policies = [p for p in tool_policies if p.get("name") != policy_name]
    if len(tool_policies) == before:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_name}' not found for {tool_name}")
    all_policies[tool_name] = tool_policies
    _save_tool_policies(all_policies)
    return {"status": "deleted", "tool": tool_name, "policy_name": policy_name}


# ── Scanning Endpoints ───────────────────────────────────────────

class ScanReq(BaseModel):
    target: str
    options: dict[str, Any] = {}


@app.post("/scan/sbom")
async def scan_sbom(req: ScanReq):
    """Generate SBOM for a target (image, directory, archive)."""
    cfg = get_config()
    scanner = SBOMScanner(cfg.syft_bin)
    result = await scanner.run(req.target, mock=cfg.mock_mode, **req.options)

    if _pipeline:
        _store_scan_result(result.model_dump())

    return result.model_dump()


@app.post("/scan/sca")
async def scan_sca(req: ScanReq):
    """Run SCA vulnerability scan on target."""
    cfg = get_config()
    scanner = SCAScanner(cfg.grype_bin)
    result = await scanner.run(req.target, mock=cfg.mock_mode, **req.options)

    if _pipeline:
        _store_scan_result(result.model_dump())

    return result.model_dump()


@app.post("/scan/container")
async def scan_container(req: ScanReq):
    """Scan container image for vulnerabilities."""
    cfg = get_config()
    scanner = ContainerScanner(cfg.trivy_bin)
    result = await scanner.run(req.target, mock=cfg.mock_mode, **req.options)

    if _pipeline:
        _store_scan_result(result.model_dump())

    return result.model_dump()


@app.post("/scan/url")
async def scan_url(req: ScanReq):
    """Scan URL/endpoint for vulnerabilities using Nuclei templates."""
    cfg = get_config()
    scanner = URLScanner(cfg.nuclei_bin)
    result = await scanner.run(req.target, mock=cfg.mock_mode, **req.options)

    if _pipeline:
        _store_scan_result(result.model_dump())

    return result.model_dump()


@app.post("/scan/iac")
async def scan_iac(req: ScanReq):
    """Scan Infrastructure as Code for misconfigurations."""
    cfg = get_config()
    scanner = IaCScanner(cfg.checkov_bin)
    result = await scanner.run(req.target, mock=cfg.mock_mode, **req.options)

    if _pipeline:
        _store_scan_result(result.model_dump())

    return result.model_dump()


@app.post("/scan/full")
async def scan_full(req: ScanReq):
    """Run all applicable scans on target in parallel."""
    cfg = get_config()
    mock = cfg.mock_mode

    results = await asyncio.gather(
        SBOMScanner(cfg.syft_bin).run(req.target, mock=mock),
        SCAScanner(cfg.grype_bin).run(req.target, mock=mock),
        ContainerScanner(cfg.trivy_bin).run(req.target, mock=mock),
        return_exceptions=True,
    )

    output = {}
    for r in results:
        if isinstance(r, Exception):
            output[str(type(r).__name__)] = {"error": str(r)}
        else:
            output[r.scan_type.value] = r.model_dump()

    return output


class ZAPScanReq(BaseModel):
    target: str
    scan_mode: str = "baseline"           # baseline | full | api
    auth_method: str = "none"             # none | basic | form | bearer | script
    auth_config: dict[str, Any] = {}      # credentials specific to auth_method
    attack_strength: str = "medium"       # low | medium | high | insane
    alert_threshold: str = "medium"       # low | medium | high
    api_spec_url: str = ""                # OpenAPI/Swagger/GraphQL URL (api mode)
    api_spec_format: str = "openapi"      # openapi | graphql | soap
    include_patterns: list[str] = []      # URL patterns to include
    exclude_patterns: list[str] = []      # URL patterns to exclude
    use_docker: bool = True               # Use Docker image (vs. ZAP daemon API)
    zap_host: str = ""                    # Override ZAP daemon host
    zap_port: int = 0                     # Override ZAP daemon port
    zap_api_key: str = ""                 # Override ZAP API key


@app.post("/scan/zap")
async def scan_zap(req: ZAPScanReq):
    """Run OWASP ZAP DAST scan against a web application or API endpoint."""
    cfg = get_config()
    scanner = ZAPScanner()
    result = await scanner.run(
        req.target,
        mock=cfg.mock_mode,
        scan_mode=req.scan_mode,
        auth_method=req.auth_method,
        auth_config=req.auth_config,
        attack_strength=req.attack_strength,
        alert_threshold=req.alert_threshold,
        api_spec_url=req.api_spec_url,
        api_spec_format=req.api_spec_format,
        include_patterns=req.include_patterns,
        exclude_patterns=req.exclude_patterns,
        use_docker=req.use_docker,
        zap_host=req.zap_host or cfg.zap_host,
        zap_port=req.zap_port or cfg.zap_port,
        zap_api_key=req.zap_api_key or cfg.zap_api_key,
    )

    if _pipeline:
        _store_scan_result(result.model_dump())

    return result.model_dump()


# ── Cloud Endpoints ──────────────────────────────────────────────

class CloudReq(BaseModel):
    provider: str = "aws"
    tool: str = "prowler"
    services: list[str] = []
    compliance: list[str] = []
    regions: list[str] = []


@app.post("/cloud/scan")
async def cloud_scan(req: CloudReq):
    """Run cloud security posture assessment."""
    cfg = get_config()
    provider = CloudProvider(req.provider.lower())
    result = await _cloud.scan(
        provider=provider,
        tool=req.tool,
        services=req.services or None,
        compliance=req.compliance or None,
        regions=req.regions or None,
        mock=cfg.mock_mode,
    )

    if _pipeline:
        _store_cloud_findings(result.model_dump())

    return result.model_dump()


@app.post("/cloud/scan-all")
async def cloud_scan_all():
    """Scan all configured cloud providers."""
    cfg = get_config()
    results = await _cloud.scan_all_providers(mock=cfg.mock_mode)
    return [r.model_dump() for r in results]


@app.get("/cloud/providers")
async def cloud_providers():
    return _cloud.get_supported_providers()


@app.get("/cloud/compliance")
async def cloud_compliance():
    return _cloud.get_compliance_frameworks()


# ── Log Endpoints ────────────────────────────────────────────────

class LogIngestReq(BaseModel):
    source_type: str
    config: dict[str, Any] = {}


@app.post("/logs/ingest")
async def logs_ingest(req: LogIngestReq):
    """Ingest logs from a source into DuckDB."""
    source_type = LogSourceType(req.source_type)
    result = await _pipeline.ingest(source_type, req.config)
    return result


@app.post("/logs/ingest/mock")
async def logs_ingest_mock():
    """Ingest mock log data for testing."""
    result = await _pipeline.ingest_mock()
    return result


class LogQueryReq(BaseModel):
    sql: str = ""
    source: str = ""
    severity: str = ""
    actor: str = ""
    action: str = ""
    source_ip: str = ""
    keyword: str = ""
    limit: int = 100


@app.post("/logs/query")
async def logs_query(req: LogQueryReq):
    """Query logs — raw SQL or structured search."""
    if req.sql:
        results = _pipeline.query(req.sql, req.limit)
    else:
        results = _pipeline.search(
            source=req.source, severity=req.severity,
            actor=req.actor, action=req.action,
            source_ip=req.source_ip, keyword=req.keyword,
            limit=req.limit,
        )
    return {"results": results, "count": len(results)}


@app.get("/logs/stats")
async def logs_stats():
    """Get aggregate log statistics."""
    stats = _pipeline.stats()
    return stats.model_dump()


# ── Scan History ─────────────────────────────────────────────────

@app.get("/history/scans")
async def scan_history():
    """Get scan history from DuckDB."""
    if _pipeline:
        results = _pipeline.query(
            "SELECT * FROM scan_results ORDER BY started_at DESC LIMIT 50"
        )
        return {"scans": results}
    return {"scans": []}


@app.get("/history/vulnerabilities")
async def vuln_history():
    """Get vulnerability history."""
    if _pipeline:
        results = _pipeline.query(
            "SELECT * FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 100"
        )
        return {"vulnerabilities": results}
    return {"vulnerabilities": []}


# ── Investigation / Correlation ───────────────────────────────────

def _rows_to_dicts(rows, columns: list[str]) -> list[dict]:
    return [dict(zip(columns, row)) for row in rows]


@app.get("/investigate/timeline")
async def investigate_timeline(hours: int = 24):
    """
    Unified timeline — logs, scan events, and cloud findings in a single
    time-ordered stream. Useful for 'what happened right before/after this alert?'
    """
    if not _pipeline:
        return {"events": [], "hours": hours}

    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    conn = _pipeline.store.conn
    cols = ["ts", "kind", "severity", "detail", "actor", "action", "source_ip", "target", "type"]

    try:
        log_rows = conn.execute("""
            SELECT timestamp::VARCHAR, 'log', severity, source,
                   actor, action, source_ip, target_resource, event_type
            FROM logs WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 300
        """, [cutoff]).fetchall()

        scan_rows = conn.execute("""
            SELECT started_at::VARCHAR, 'scan', status, tool,
                   '', scan_type, '', target, scan_type
            FROM scan_results WHERE started_at >= ? ORDER BY started_at DESC LIMIT 100
        """, [cutoff]).fetchall()

        cloud_rows = conn.execute("""
            SELECT discovered_at::VARCHAR, 'cloud_finding', severity, check_title,
                   '', check_id, '', resource_arn, service
            FROM cloud_findings WHERE discovered_at >= ? ORDER BY discovered_at DESC LIMIT 100
        """, [cutoff]).fetchall()

        events = (
            _rows_to_dicts(log_rows, cols) +
            _rows_to_dicts(scan_rows, cols) +
            _rows_to_dicts(cloud_rows, cols)
        )
        events.sort(key=lambda x: x.get("ts") or "", reverse=True)
        return {"events": events[:500], "hours": hours, "total": len(events)}
    except Exception as exc:
        return {"events": [], "hours": hours, "error": str(exc)}


@app.get("/investigate/package/{package_name}")
async def investigate_package(package_name: str):
    """
    Cross-reference a package name across all data sources:
    - Where it appears in SBOM scans (what targets carry it)
    - Known CVEs found against it
    - Related log activity mentioning the package or its endpoints
    """
    if not _pipeline:
        return {"package": package_name}

    conn = _pipeline.store.conn
    pat = f"%{package_name}%"

    try:
        sbom_rows = conn.execute("""
            SELECT sc.name, sc.version, sc.purl, sc.target,
                   sc.discovered_at::VARCHAR, sr.scan_type, sr.started_at::VARCHAR
            FROM sbom_components sc
            JOIN scan_results sr ON sc.scan_id = sr.id
            WHERE sc.name ILIKE ? ORDER BY sc.discovered_at DESC LIMIT 50
        """, [pat]).fetchall()

        vuln_rows = conn.execute("""
            SELECT v.vuln_id, v.severity, v.package, v.installed_version,
                   v.fixed_version, v.cvss_score, v.description,
                   v.discovered_at::VARCHAR, sr.target, sr.scan_type
            FROM vulnerabilities v
            JOIN scan_results sr ON v.scan_id = sr.id
            WHERE v.package ILIKE ? ORDER BY v.discovered_at DESC LIMIT 50
        """, [pat]).fetchall()

        log_rows = conn.execute("""
            SELECT timestamp::VARCHAR, source, severity, actor,
                   action, target_resource, source_ip, event_type
            FROM logs
            WHERE action ILIKE ? OR target_resource ILIKE ? OR CAST(raw AS VARCHAR) ILIKE ?
            ORDER BY timestamp DESC LIMIT 50
        """, [pat, pat, pat]).fetchall()

        # Severity summary for this package's CVEs
        sev_dist = dict(conn.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities WHERE package ILIKE ? GROUP BY severity",
            [pat]
        ).fetchall())

        return {
            "package": package_name,
            "cve_severity_summary": sev_dist,
            "sbom_occurrences": _rows_to_dicts(sbom_rows, [
                "name", "version", "purl", "target", "discovered_at", "scan_type", "scan_time"
            ]),
            "vulnerabilities": _rows_to_dicts(vuln_rows, [
                "vuln_id", "severity", "package", "installed_version",
                "fixed_version", "cvss_score", "description", "discovered_at", "scan_target", "scan_type"
            ]),
            "related_logs": _rows_to_dicts(log_rows, [
                "ts", "source", "severity", "actor", "action", "target_resource", "source_ip", "event_type"
            ]),
        }
    except Exception as exc:
        return {"package": package_name, "error": str(exc)}


@app.get("/investigate/ip/{ip_address}")
async def investigate_ip(ip_address: str):
    """
    Full activity profile for an IP address:
    - All log events (auth attempts, API calls, network blocks)
    - First/last seen, event count, severity distribution
    - Top actions performed
    Useful for threat hunting and incident response.
    """
    if not _pipeline:
        return {"ip": ip_address}

    conn = _pipeline.store.conn

    try:
        span = conn.execute("""
            SELECT MIN(timestamp)::VARCHAR, MAX(timestamp)::VARCHAR, COUNT(*)
            FROM logs WHERE source_ip = ?
        """, [ip_address]).fetchone()

        sev_dist = dict(conn.execute(
            "SELECT severity, COUNT(*) FROM logs WHERE source_ip = ? GROUP BY severity ORDER BY COUNT(*) DESC",
            [ip_address]
        ).fetchall())

        top_actions = conn.execute("""
            SELECT action, COUNT(*) as cnt FROM logs
            WHERE source_ip = ? AND action != ''
            GROUP BY action ORDER BY cnt DESC LIMIT 10
        """, [ip_address]).fetchall()

        event_rows = conn.execute("""
            SELECT timestamp::VARCHAR, source, severity, actor,
                   action, target_resource, event_type, tags::VARCHAR
            FROM logs WHERE source_ip = ?
            ORDER BY timestamp DESC LIMIT 200
        """, [ip_address]).fetchall()

        return {
            "ip": ip_address,
            "first_seen": span[0] if span else None,
            "last_seen":  span[1] if span else None,
            "total_events": span[2] if span else 0,
            "severity_distribution": sev_dist,
            "top_actions": [{"action": r[0], "count": r[1]} for r in top_actions],
            "events": _rows_to_dicts(event_rows, [
                "ts", "source", "severity", "actor", "action", "target_resource", "event_type", "tags"
            ]),
        }
    except Exception as exc:
        return {"ip": ip_address, "error": str(exc)}


@app.get("/investigate/vuln/{vuln_id}")
async def investigate_vuln(vuln_id: str):
    """
    All scan hits for a specific CVE/check ID, plus any log activity
    that temporally correlates (±1h around the scan that found it).
    """
    if not _pipeline:
        return {"vuln_id": vuln_id}

    conn = _pipeline.store.conn
    pat = f"%{vuln_id}%"

    try:
        # Every scan that hit this CVE
        hits = conn.execute("""
            SELECT v.vuln_id, v.severity, v.package, v.installed_version,
                   v.fixed_version, v.cvss_score, v.discovered_at::VARCHAR,
                   sr.target, sr.scan_type, sr.tool, sr.started_at::VARCHAR
            FROM vulnerabilities v
            JOIN scan_results sr ON v.scan_id = sr.id
            WHERE v.vuln_id ILIKE ?
            ORDER BY v.discovered_at DESC
        """, [pat]).fetchall()

        # Cloud findings referencing the same check
        cloud_hits = conn.execute("""
            SELECT check_id, check_title, severity, service, region,
                   resource_arn, status, discovered_at::VARCHAR
            FROM cloud_findings WHERE check_id ILIKE ?
            ORDER BY discovered_at DESC LIMIT 50
        """, [pat]).fetchall()

        return {
            "vuln_id": vuln_id,
            "scan_hits": _rows_to_dicts(hits, [
                "vuln_id", "severity", "package", "installed_version",
                "fixed_version", "cvss_score", "discovered_at",
                "target", "scan_type", "tool", "scan_time"
            ]),
            "cloud_findings": _rows_to_dicts(cloud_hits, [
                "check_id", "check_title", "severity", "service",
                "region", "resource_arn", "status", "discovered_at"
            ]),
        }
    except Exception as exc:
        return {"vuln_id": vuln_id, "error": str(exc)}


# ── UI ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    ui_path = Path(__file__).parent / "ui" / "index.html"
    if ui_path.exists():
        return HTMLResponse(ui_path.read_text())
    return HTMLResponse("<h1>ShieldKit</h1><p>UI not found. Place index.html in ui/</p>")


# ── WebSocket (live scan streaming) ─────────────────────────────

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    cfg = get_config()

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action", "")

            if action == "scan":
                scan_type = data.get("scan_type", "sca")
                target = data.get("target", "")
                await websocket.send_json({"type": "status", "message": f"Starting {scan_type} scan on {target}..."})

                scanner_map = {
                    "sbom": SBOMScanner(cfg.syft_bin),
                    "sca": SCAScanner(cfg.grype_bin),
                    "container": ContainerScanner(cfg.trivy_bin),
                    "url": URLScanner(cfg.nuclei_bin),
                    "iac": IaCScanner(cfg.checkov_bin),
                    "dast": ZAPScanner(),
                }
                scanner = scanner_map.get(scan_type)
                if scanner:
                    result = await scanner.run(target, mock=cfg.mock_mode)
                    await websocket.send_json({"type": "result", "data": result.model_dump()})
                else:
                    await websocket.send_json({"type": "error", "message": f"Unknown scan type: {scan_type}"})

            elif action == "cloud":
                provider = CloudProvider(data.get("provider", "aws"))
                await websocket.send_json({"type": "status", "message": f"Scanning {provider.value}..."})
                result = await _cloud.scan(provider, mock=cfg.mock_mode)
                await websocket.send_json({"type": "result", "data": result.model_dump()})

            elif action == "logs_query":
                sql = data.get("sql", "")
                results = _pipeline.query(sql)
                await websocket.send_json({"type": "result", "data": {"results": results}})

            elif action == "logs_stats":
                stats = _pipeline.stats()
                await websocket.send_json({"type": "result", "data": stats.model_dump()})

    except WebSocketDisconnect:
        pass


# ── Helpers ──────────────────────────────────────────────────────

def _store_scan_result(data: dict) -> int | None:
    """Persist scan result to DuckDB. Returns the inserted scan_id."""
    try:
        row = _pipeline.store.conn.execute("""
            INSERT INTO scan_results (scan_type, target, tool, started_at, completed_at, status, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING id
        """, [
            data.get("scan_type", ""), data.get("target", ""),
            data.get("tool", ""), data.get("started_at"),
            data.get("completed_at"), data.get("status", ""),
            json.dumps(data.get("summary", {})),
        ]).fetchone()
        scan_id = row[0] if row else None
        if scan_id:
            _store_vulnerabilities(scan_id, data.get("vulnerabilities") or [])
            sbom = data.get("sbom") or {}
            if sbom.get("components"):
                _store_sbom_components(scan_id, data.get("target", ""), sbom["components"])
        return scan_id
    except Exception:
        return None


def _store_vulnerabilities(scan_id: int, vulns: list[dict]) -> None:
    """Persist individual vulnerabilities linked to a scan_id."""
    if not vulns:
        return
    try:
        for v in vulns:
            _pipeline.store.conn.execute("""
                INSERT INTO vulnerabilities
                    (scan_id, vuln_id, severity, package, installed_version,
                     fixed_version, description, cvss_score, data_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                scan_id, v.get("id", ""), v.get("severity", ""),
                v.get("package", ""), v.get("installed_version", ""),
                v.get("fixed_version", ""), (v.get("description") or "")[:500],
                v.get("cvss_score"), v.get("data_source", ""),
            ])
    except Exception:
        pass


def _store_sbom_components(scan_id: int, target: str, components: list[dict]) -> None:
    """Persist SBOM components linked to a scan_id."""
    if not components:
        return
    try:
        for c in components:
            _pipeline.store.conn.execute("""
                INSERT INTO sbom_components (scan_id, target, name, version, type, purl, licenses)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [
                scan_id, target,
                c.get("name", ""), c.get("version", ""),
                c.get("type", "library"), c.get("purl", ""),
                c.get("licenses") or [],
            ])
    except Exception:
        pass


def _store_cloud_findings(data: dict):
    """Persist cloud findings to DuckDB."""
    try:
        for f in data.get("findings", []):
            _pipeline.store.conn.execute("""
                INSERT INTO cloud_findings (provider, tool, service, region, resource_arn,
                    check_id, check_title, severity, status, description, remediation, compliance)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                f.get("provider", ""), data.get("tool", ""),
                f.get("service", ""), f.get("region", ""),
                f.get("resource_arn", ""), f.get("check_id", ""),
                f.get("check_title", ""), f.get("severity", ""),
                f.get("status", ""), f.get("description", ""),
                f.get("remediation", ""), f.get("compliance", []),
            ])
    except Exception:
        pass


# ── SOC Analyst Chatbot ──────────────────────────────────────────

_CHAT_TOOLS = [
    {
        "name": "shieldkit_sbom",
        "description": "Generate a Software Bill of Materials (SBOM) for a container image, directory, or archive.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Image (e.g. nginx:latest), directory path, or archive"},
                "format": {"type": "string", "enum": ["cyclonedx-json", "spdx-json"], "default": "cyclonedx-json"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_sca",
        "description": "Run Software Composition Analysis — scan for known CVEs in dependencies. Returns vulnerabilities with severity, CVSS, and fix versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Image, directory, or SBOM file"},
                "severity": {"type": "string", "description": "Filter: critical,high,medium,low", "default": ""},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_container",
        "description": "Scan a container image for OS and application vulnerabilities using Trivy.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Container image (e.g. nginx:latest)"},
                "severity": {"type": "string", "description": "Filter: CRITICAL,HIGH,MEDIUM,LOW", "default": ""},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_iac",
        "description": "Scan Infrastructure as Code files for misconfigurations (Checkov). Supports Terraform, CloudFormation, Kubernetes, Dockerfiles.",
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
        "name": "shieldkit_dast",
        "description": "Run DAST (Dynamic Application Security Testing) against a web app using OWASP ZAP.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL (e.g. https://example.com)"},
                "scan_mode": {"type": "string", "enum": ["baseline", "full", "api"], "default": "baseline"},
                "auth_method": {"type": "string", "enum": ["none", "basic", "form", "bearer"], "default": "none"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "shieldkit_cloud",
        "description": "Cloud security posture assessment against CIS, SOC2, PCI-DSS. Supports AWS, Azure, GCP.",
        "input_schema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "enum": ["aws", "azure", "gcp"]},
                "tool": {"type": "string", "enum": ["prowler", "scoutsuite"], "default": "prowler"},
                "compliance": {"type": "array", "items": {"type": "string"}, "description": "Frameworks: cis, soc2, pci-dss"},
            },
            "required": ["provider"],
        },
    },
    {
        "name": "shieldkit_log_query",
        "description": "Query security logs in ShieldKit's DuckDB store. Supports SQL or structured search.",
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "Raw SQL (e.g. SELECT * FROM logs WHERE severity='critical')"},
                "source": {"type": "string", "description": "Log source: cloudtrail, syslog, vpc-flow"},
                "severity": {"type": "string", "description": "critical, high, medium, low, info"},
                "actor": {"type": "string", "description": "Actor/user to filter by"},
                "source_ip": {"type": "string", "description": "Source IP to filter by"},
                "keyword": {"type": "string", "description": "Keyword search"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "shieldkit_log_stats",
        "description": "Get aggregate log statistics: total count, sources, severity distribution, top actors, top IPs.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "shieldkit_scan_history",
        "description": "Retrieve recent scan history with results and summaries.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 10, "description": "Number of recent scans to return"},
                "scan_type": {"type": "string", "description": "Filter by type: sbom, sca, container, iac, dast, cloud"},
            },
        },
    },
]

_CHAT_SYSTEM_PROMPT = """You are ShieldKit SOC Analyst — an expert AI security analyst embedded in the ShieldKit DevSecOps platform.

You have direct access to ShieldKit's scanning and investigation tools:
- SBOM generation (software bill of materials)
- SCA/CVE scanning (dependency vulnerabilities)
- Container image scanning
- IaC misconfiguration detection
- DAST web app scanning (OWASP ZAP)
- Cloud posture assessment (AWS/Azure/GCP)
- Security log querying and analytics

Your role:
1. Answer security questions and guide threat investigations
2. Run scans when the user asks you to check something
3. Interpret scan results and prioritize findings by risk
4. Generate incident reports and remediation guidance
5. Correlate findings across scan types for complete risk picture

Always be concise, actionable, and prioritize by severity. When running scans, explain what you found and what to do next. Format findings as clear bullet points. Use emojis sparingly for status indicators (✅ 🔴 🟠 🟡)."""


async def _execute_chat_tool(name: str, args: dict) -> str:
    """Execute a ShieldKit tool and return JSON string result."""
    cfg = get_config()
    mock = cfg.mock_mode
    try:
        if name == "shieldkit_sbom":
            target = args.pop("target")
            scanner = SBOMScanner(cfg.syft_bin)
            result = await scanner.run(target, mock=mock, **args)
            if _pipeline:
                _store_scan_result(result.model_dump())
            return json.dumps(result.model_dump(), default=str)

        elif name == "shieldkit_sca":
            target = args.pop("target")
            scanner = SCAScanner(cfg.grype_bin)
            result = await scanner.run(target, mock=mock, **args)
            if _pipeline:
                _store_scan_result(result.model_dump())
            return json.dumps(result.model_dump(), default=str)

        elif name == "shieldkit_container":
            target = args.pop("target")
            scanner = ContainerScanner(cfg.trivy_bin)
            result = await scanner.run(target, mock=mock, **args)
            if _pipeline:
                _store_scan_result(result.model_dump())
            return json.dumps(result.model_dump(), default=str)

        elif name == "shieldkit_iac":
            target = args.pop("target")
            scanner = IaCScanner(cfg.checkov_bin)
            result = await scanner.run(target, mock=mock, **args)
            if _pipeline:
                _store_scan_result(result.model_dump())
            return json.dumps(result.model_dump(), default=str)

        elif name == "shieldkit_dast":
            target = args.pop("target")
            scanner = ZAPScanner(cfg.zap_host, cfg.zap_port, cfg.zap_api_key, cfg.zap_use_docker)
            result = await scanner.run(target, mock=mock, **args)
            if _pipeline:
                _store_scan_result(result.model_dump())
            return json.dumps(result.model_dump(), default=str)

        elif name == "shieldkit_cloud":
            provider = CloudProvider(args.get("provider", "aws"))
            result = await _cloud.scan(
                provider,
                tool=args.get("tool", "prowler"),
                services=args.get("services"),
                compliance=args.get("compliance"),
                mock=mock,
            )
            if _pipeline:
                _store_cloud_findings(result.model_dump())
            return json.dumps(result.model_dump(), default=str)

        elif name == "shieldkit_log_query":
            if not _pipeline:
                return json.dumps({"error": "Log pipeline not initialized"})
            if args.get("sql"):
                results = _pipeline.query(args["sql"], args.get("limit", 50))
            else:
                results = _pipeline.search(**{k: v for k, v in args.items() if k != "sql" and v})
            return json.dumps({"results": results}, default=str)

        elif name == "shieldkit_log_stats":
            if not _pipeline:
                return json.dumps({"error": "Log pipeline not initialized"})
            return json.dumps(_pipeline.stats().model_dump(), default=str)

        elif name == "shieldkit_scan_history":
            limit = args.get("limit", 10)
            scan_type = args.get("scan_type")
            params: dict[str, Any] = {"limit": limit}
            if scan_type:
                params["scan_type"] = scan_type
            # Return from in-memory store or recent scans list
            try:
                rows = _pipeline.store.conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", [limit]
                ).fetchall()
                cols = [d[0] for d in _pipeline.store.conn.description]
                return json.dumps({"scans": [dict(zip(cols, r)) for r in rows]}, default=str)
            except Exception as e:
                return json.dumps({"scans": [], "note": str(e)})

        return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as exc:
        return json.dumps({"error": str(exc), "tool": name})


class ReportRequest(BaseModel):
    report_type: str = "vulnerability"  # vulnerability|sbom|cloud|executive|full
    format: str = "pdf"                 # pdf|csv|html
    filters: dict = {}
    title: str = ""


# ── Reports ───────────────────────────────────────────────────────

_REPORTS_DIR = Path(__file__).resolve().parent / "data" / "reports"
_REPORTS_INDEX = _REPORTS_DIR / "index.json"


def _load_reports_index() -> list[dict]:
    if _REPORTS_INDEX.exists():
        try:
            return json.loads(_REPORTS_INDEX.read_text())
        except Exception:
            pass
    return []


def _save_reports_index(entries: list[dict]) -> None:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _REPORTS_INDEX.write_text(json.dumps(entries, indent=2))


@app.post("/reports/generate")
async def generate_report(req: ReportRequest):
    """Generate a report and save it to data/reports/."""
    if not _pipeline:
        raise HTTPException(status_code=503, detail="Log store not initialised")

    valid_types = {"vulnerability", "sbom", "cloud", "executive", "full"}
    valid_fmts = {"pdf", "csv", "html"}
    if req.report_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid report_type. Choose from: {valid_types}")
    if req.format not in valid_fmts:
        raise HTTPException(status_code=400, detail=f"Invalid format. Choose from: {valid_fmts}")

    from .reports import ReportGenerator
    gen = ReportGenerator(_pipeline.store.conn)

    filename, content = gen.generate(req.report_type, req.format, req.filters, req.title)

    report_id = str(uuid.uuid4())[:8]
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _REPORTS_DIR / f"{report_id}.{req.format}"
    out_path.write_bytes(content)

    title_str = req.title or filename
    entry = {
        "id": report_id,
        "title": title_str,
        "type": req.report_type,
        "format": req.format,
        "size": len(content),
        "created_at": datetime.utcnow().isoformat(),
        "filename": filename,
    }
    entries = _load_reports_index()
    entries.insert(0, entry)
    _save_reports_index(entries)

    return {
        "id": report_id,
        "filename": filename,
        "url": f"/reports/{report_id}/download",
        "size": len(content),
    }


@app.get("/reports")
async def list_reports():
    """List all generated reports."""
    return {"reports": _load_reports_index()}


@app.get("/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download a previously generated report."""
    entries = _load_reports_index()
    entry = next((e for e in entries if e["id"] == report_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")

    fmt = entry.get("format", "pdf")
    file_path = _REPORTS_DIR / f"{report_id}.{fmt}"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")

    media_types = {"pdf": "application/pdf", "csv": "text/csv", "html": "text/html"}
    media_type = media_types.get(fmt, "application/octet-stream")
    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=entry.get("filename", file_path.name),
    )


@app.delete("/reports/{report_id}")
async def delete_report(report_id: str):
    """Delete a report file and remove it from the index."""
    entries = _load_reports_index()
    entry = next((e for e in entries if e["id"] == report_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Report not found")

    fmt = entry.get("format", "pdf")
    file_path = _REPORTS_DIR / f"{report_id}.{fmt}"
    if file_path.exists():
        file_path.unlink()

    entries = [e for e in entries if e["id"] != report_id]
    _save_reports_index(entries)
    return {"status": "deleted", "id": report_id}


class ChatMessage(BaseModel):
    role: str  # user | assistant
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    api_key: Optional[str] = None  # Override ANTHROPIC_API_KEY if provided


@app.post("/chat")
async def chat(req: ChatRequest):
    """SOC Analyst chat — single turn, returns full response with tool results."""
    import anthropic

    api_key = req.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="ANTHROPIC_API_KEY not set. Provide it in Settings or set env var.")

    try:
        client = anthropic.Anthropic(api_key=api_key)
        messages = [{"role": m.role, "content": m.content} for m in req.messages]

        # Agentic loop — keep calling until no more tool_use
        max_iterations = 8
        tool_calls_made: list[dict] = []

        for _ in range(max_iterations):
            response = client.messages.create(
                model="claude-opus-4-6",
                max_tokens=4096,
                system=_CHAT_SYSTEM_PROMPT,
                tools=_CHAT_TOOLS,
                messages=messages,
            )

            # Collect assistant message
            assistant_content = response.content
            messages.append({"role": "assistant", "content": assistant_content})

            if response.stop_reason != "tool_use":
                break

            # Execute tool calls
            tool_results = []
            for block in assistant_content:
                if block.type == "tool_use":
                    tool_calls_made.append({"name": block.name, "input": block.input})
                    result_text = await _execute_chat_tool(block.name, dict(block.input))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    })

            messages.append({"role": "user", "content": tool_results})

        # Extract final text response
        final_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                final_text += block.text

        return {
            "response": final_text,
            "tool_calls": tool_calls_made,
            "usage": {"input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens},
        }
    except anthropic.AuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"Invalid Anthropic API key. Check Settings → SOC Analyst API Key. ({e})")
    except anthropic.APIConnectionError as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach Anthropic API: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {e}")


@app.websocket("/chat/ws")
async def chat_ws(websocket: WebSocket):
    """Streaming SOC Analyst chat via WebSocket. Each message: {type, content/tool/text}."""
    import anthropic

    await websocket.accept()
    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            msg_type = data.get("type", "chat")

            if msg_type == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
                continue

            api_key = data.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "content": "ANTHROPIC_API_KEY not configured. Add it in Settings → SOC Analyst API Key.",
                }))
                continue

            messages = data.get("messages", [])
            client = anthropic.Anthropic(api_key=api_key)

            # Agentic loop with streaming
            max_iterations = 8
            for iteration in range(max_iterations):
                # Stream the response
                full_text = ""
                tool_uses = []

                with client.messages.stream(
                    model="claude-opus-4-6",
                    max_tokens=4096,
                    system=_CHAT_SYSTEM_PROMPT,
                    tools=_CHAT_TOOLS,
                    messages=messages,
                ) as stream:
                    current_tool: dict | None = None
                    current_tool_input = ""
                    stop_reason = None

                    for event in stream:
                        etype = type(event).__name__

                        if etype == "RawMessageStartEvent":
                            pass
                        elif etype == "RawContentBlockStartEvent":
                            block = event.content_block
                            if block.type == "text":
                                current_tool = None
                            elif block.type == "tool_use":
                                current_tool = {"id": block.id, "name": block.name, "input": ""}
                                current_tool_input = ""
                                await websocket.send_text(json.dumps({
                                    "type": "tool_start",
                                    "tool": block.name,
                                }))
                        elif etype == "RawContentBlockDeltaEvent":
                            delta = event.delta
                            if delta.type == "text_delta":
                                full_text += delta.text
                                await websocket.send_text(json.dumps({
                                    "type": "text_delta",
                                    "text": delta.text,
                                }))
                            elif delta.type == "input_json_delta":
                                current_tool_input += delta.partial_json
                        elif etype == "RawContentBlockStopEvent":
                            if current_tool:
                                try:
                                    current_tool["input"] = json.loads(current_tool_input) if current_tool_input else {}
                                except Exception:
                                    current_tool["input"] = {}
                                tool_uses.append(current_tool)
                                current_tool = None
                                current_tool_input = ""
                        elif etype == "RawMessageDeltaEvent":
                            if hasattr(event.delta, "stop_reason"):
                                stop_reason = event.delta.stop_reason

                # Append assistant message to history
                assistant_msg = stream.get_final_message()
                messages.append({"role": "assistant", "content": assistant_msg.content})
                stop_reason = assistant_msg.stop_reason

                if stop_reason != "tool_use" or not tool_uses:
                    break

                # Execute tools and send results
                tool_results = []
                for tu in tool_uses:
                    await websocket.send_text(json.dumps({
                        "type": "tool_running",
                        "tool": tu["name"],
                        "input": tu["input"],
                    }))
                    result_text = await _execute_chat_tool(tu["name"], dict(tu["input"]))
                    try:
                        result_preview = json.loads(result_text)
                        summary = result_preview.get("summary") or result_preview.get("status") or "done"
                    except Exception:
                        summary = "done"
                    await websocket.send_text(json.dumps({
                        "type": "tool_result",
                        "tool": tu["name"],
                        "summary": str(summary),
                    }))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tu["id"],
                        "content": result_text,
                    })

                messages.append({"role": "user", "content": tool_results})

            await websocket.send_text(json.dumps({"type": "done"}))

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_text(json.dumps({"type": "error", "content": str(exc)}))
        except Exception:
            pass
