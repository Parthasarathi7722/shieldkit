"""
ShieldKit — Centralised Configuration
Loads from .env or environment variables. Lazy singleton pattern.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_BASE = Path(__file__).resolve().parent
_CFG: "Config | None" = None


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


@dataclass
class Config:
    # ── AI Provider ──────────────────────────────────────────────
    ai_provider: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    ai_base_url: str = ""

    # ── Server ───────────────────────────────────────────────────
    server_host: str = "0.0.0.0"
    server_port: int = 8000

    # ── Modes ────────────────────────────────────────────────────
    mock_mode: bool = True  # safe default

    # ── DuckDB ───────────────────────────────────────────────────
    duckdb_path: str = str(_BASE / "data" / "shieldkit.duckdb")

    # ── Log Collection ───────────────────────────────────────────
    log_sources: list[dict[str, Any]] = field(default_factory=list)
    log_retention_days: int = 90

    # ── Cloud Credentials ────────────────────────────────────────
    aws_profile: str = ""
    aws_region: str = "us-east-1"
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""
    gcp_project_id: str = ""

    # ── Tool Paths (auto-detected or overridden) ─────────────────
    syft_bin: str = "syft"
    grype_bin: str = "grype"
    trivy_bin: str = "trivy"
    nuclei_bin: str = "nuclei"
    prowler_bin: str = "prowler"
    checkov_bin: str = "checkov"
    scoutsuite_bin: str = "scout"
    zap_docker_image: str = "ghcr.io/zaproxy/zaproxy:stable"

    # ── ZAP DAST ────────────────────────────────────────────────
    zap_host: str = "localhost"
    zap_port: int = 8080
    zap_api_key: str = ""
    zap_use_docker: bool = True

    # ── Secrets Provider ─────────────────────────────────────────
    secrets_provider: str = "local_encrypted"  # local_encrypted|hashicorp_vault|aws_secrets|azure_keyvault|gcp_secret
    secrets_master_key: str = ""               # SHIELDKIT_MASTER_KEY (for local_encrypted)
    vault_addr: str = ""                       # VAULT_ADDR
    vault_token: str = ""                      # VAULT_TOKEN
    vault_mount: str = "secret"               # VAULT_MOUNT
    vault_path_prefix: str = "shieldkit"      # VAULT_PATH_PREFIX
    aws_sm_region: str = ""                    # AWS_SM_REGION
    aws_sm_prefix: str = "shieldkit/"         # AWS_SM_PREFIX
    azure_vault_url: str = ""                  # AZURE_VAULT_URL
    gcp_sm_project: str = ""                   # GCP_SM_PROJECT

    # ── Database Backend ─────────────────────────────────────────
    db_backend: str = "local"                  # local|motherduck|s3_sync|postgres
    motherduck_token: str = ""                 # MOTHERDUCK_TOKEN
    motherduck_db: str = "shieldkit"           # MOTHERDUCK_DB
    db_s3_bucket: str = ""                     # DB_S3_BUCKET
    db_s3_key: str = "shieldkit/shieldkit.duckdb"  # DB_S3_KEY
    db_s3_region: str = ""                     # DB_S3_REGION
    db_postgres_url: str = ""                  # DB_POSTGRES_URL

    # ── Tool Registry ────────────────────────────────────────────
    tool_registry: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        env_file = _BASE / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("\"'"))

        self.ai_provider = _env("AI_PROVIDER", "anthropic")
        self.ai_api_key = _env("AI_API_KEY")
        self.ai_model = _env("AI_MODEL", "claude-sonnet-4-20250514")
        self.ai_base_url = _env("AI_BASE_URL", "")
        self.server_host = _env("SERVER_HOST", self.server_host)
        self.server_port = int(_env("SERVER_PORT", str(self.server_port)))
        self.mock_mode = _env("SHIELDKIT_MODE", "mock").lower() == "mock"
        self.duckdb_path = _env("DUCKDB_PATH", self.duckdb_path)
        self.log_retention_days = int(_env("LOG_RETENTION_DAYS", "90"))

        # Cloud
        self.aws_profile = _env("AWS_PROFILE")
        self.aws_region = _env("AWS_REGION", "us-east-1")
        self.azure_subscription_id = _env("AZURE_SUBSCRIPTION_ID")
        self.azure_tenant_id = _env("AZURE_TENANT_ID")
        self.gcp_project_id = _env("GCP_PROJECT_ID")

        # Tool paths
        self.syft_bin = _env("SYFT_BIN", "syft")
        self.grype_bin = _env("GRYPE_BIN", "grype")
        self.trivy_bin = _env("TRIVY_BIN", "trivy")
        self.nuclei_bin = _env("NUCLEI_BIN", "nuclei")
        self.prowler_bin = _env("PROWLER_BIN", "prowler")
        self.checkov_bin = _env("CHECKOV_BIN", "checkov")
        self.scoutsuite_bin = _env("SCOUTSUITE_BIN", "scout")

        # Secrets provider
        self.secrets_provider = _env("SECRETS_PROVIDER", "local_encrypted")
        self.secrets_master_key = _env("SHIELDKIT_MASTER_KEY", "")
        self.vault_addr = _env("VAULT_ADDR", "")
        self.vault_token = _env("VAULT_TOKEN", "")
        self.vault_mount = _env("VAULT_MOUNT", "secret")
        self.vault_path_prefix = _env("VAULT_PATH_PREFIX", "shieldkit")
        self.aws_sm_region = _env("AWS_SM_REGION", self.aws_region)
        self.aws_sm_prefix = _env("AWS_SM_PREFIX", "shieldkit/")
        self.azure_vault_url = _env("AZURE_VAULT_URL", "")
        self.gcp_sm_project = _env("GCP_SM_PROJECT", self.gcp_project_id)

        # Database backend
        self.db_backend = _env("DB_BACKEND", "local")
        self.motherduck_token = _env("MOTHERDUCK_TOKEN", "")
        self.motherduck_db = _env("MOTHERDUCK_DB", "shieldkit")
        self.db_s3_bucket = _env("DB_S3_BUCKET", "")
        self.db_s3_key = _env("DB_S3_KEY", "shieldkit/shieldkit.duckdb")
        self.db_s3_region = _env("DB_S3_REGION", self.aws_region)
        self.db_postgres_url = _env("DB_POSTGRES_URL", "")

        # ZAP
        self.zap_host = _env("ZAP_HOST", "localhost")
        self.zap_port = int(_env("ZAP_PORT", "8080"))
        self.zap_api_key = _env("ZAP_API_KEY", "")
        self.zap_use_docker = _env("ZAP_USE_DOCKER", "true").lower() in ("true", "1", "yes")
        self.zap_docker_image = _env("ZAP_DOCKER_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")

        # Tool registry
        reg_path = _BASE / "tool_registry.json"
        if reg_path.exists():
            raw = json.loads(reg_path.read_text())
            self.tool_registry = {
                k: v for k, v in raw.get("tools", {}).items()
                if not k.startswith("__comment")
            }

        # Ensure data dir exists
        Path(self.duckdb_path).parent.mkdir(parents=True, exist_ok=True)


def get_config() -> Config:
    global _CFG
    if _CFG is None:
        _CFG = Config()
    return _CFG
