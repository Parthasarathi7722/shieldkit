"""
ShieldKit — Shared data models (Pydantic).
Used across scanners, logs, cloud, server, and MCP plugin.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ScanType(str, Enum):
    SBOM = "sbom"
    SCA = "sca"
    CONTAINER = "container"
    URL = "url"
    CLOUD = "cloud"
    IAC = "iac"
    DAST = "dast"


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class LogSourceType(str, Enum):
    S3 = "s3"
    CLOUDTRAIL = "cloudtrail"
    CLOUDWATCH = "cloudwatch"
    SYSLOG = "syslog"
    FILE = "file"
    WEBHOOK = "webhook"


# ── SBOM ─────────────────────────────────────────────────────────

class SBOMComponent(BaseModel):
    name: str
    version: str
    type: str = "library"  # library | framework | application | container | os
    purl: str = ""
    licenses: list[str] = Field(default_factory=list)
    supplier: str = ""


class SBOMReport(BaseModel):
    target: str
    format: str = "cyclonedx"  # cyclonedx | spdx
    tool: str = "syft"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    component_count: int = 0
    components: list[SBOMComponent] = Field(default_factory=list)
    raw_output: str = ""


# ── Vulnerabilities ──────────────────────────────────────────────

class Vulnerability(BaseModel):
    id: str  # CVE-2024-XXXXX
    severity: Severity = Severity.UNKNOWN
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    description: str = ""
    data_source: str = ""
    urls: list[str] = Field(default_factory=list)
    cvss_score: float | None = None


class ScanResult(BaseModel):
    scan_type: ScanType
    target: str
    tool: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    status: str = "running"  # running | completed | failed
    summary: dict[str, int] = Field(default_factory=dict)  # severity → count
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    sbom: SBOMReport | None = None
    raw_output: str = ""
    error: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)  # scanner-specific metadata


# ── Cloud Config ─────────────────────────────────────────────────

class CloudFinding(BaseModel):
    provider: CloudProvider
    service: str  # iam, s3, ec2, etc.
    region: str = ""
    resource_id: str = ""
    resource_arn: str = ""
    check_id: str = ""
    check_title: str = ""
    severity: Severity = Severity.UNKNOWN
    status: str = "FAIL"  # PASS | FAIL | WARN | INFO
    description: str = ""
    remediation: str = ""
    compliance: list[str] = Field(default_factory=list)  # CIS, SOC2, PCI-DSS


class CloudScanResult(BaseModel):
    provider: CloudProvider
    tool: str  # prowler | scoutsuite | checkov
    target: str = ""  # account id, project, subscription
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    status: str = "running"
    summary: dict[str, int] = Field(default_factory=dict)
    findings: list[CloudFinding] = Field(default_factory=list)
    raw_output: str = ""
    error: str = ""


# ── Log Pipeline ─────────────────────────────────────────────────

class NormalizedLog(BaseModel):
    timestamp: datetime
    source: str  # cloudtrail, syslog, vpc-flow, etc.
    source_type: LogSourceType
    severity: Severity = Severity.INFO
    event_type: str = ""  # login, api_call, network, system, etc.
    actor: str = ""  # user, role, service
    action: str = ""  # e.g. ConsoleLogin, PutObject, ssh
    target_resource: str = ""
    source_ip: str = ""
    region: str = ""
    account_id: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class LogQuery(BaseModel):
    query: str = ""  # natural language or SQL
    source: str = ""  # filter by source
    severity: Severity | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    limit: int = 100


class LogStats(BaseModel):
    total_logs: int = 0
    sources: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    time_range: dict[str, str] = Field(default_factory=dict)
    top_actors: list[dict[str, Any]] = Field(default_factory=list)
    top_actions: list[dict[str, Any]] = Field(default_factory=list)


# ── Target Resolution ────────────────────────────────────────────

class TargetType(str, Enum):
    AUTO        = "auto"
    FILE_UPLOAD = "file_upload"
    PUBLIC_URL  = "public_url"
    PRIVATE_URL = "private_url"
    S3          = "s3"
    CONTAINER   = "container"
    GIT         = "git"
    LOCAL_PATH  = "local_path"


class TargetCredentials(BaseModel):
    type: str = "bearer"      # bearer | basic | header
    token: str = ""           # may be sk:// ref
    username: str = ""        # may be sk:// ref
    password: str = ""        # may be sk:// ref
    headers: dict = {}
    profile: str = ""         # named credential profile (cred_profile_{name})
    # S3-specific
    access_key: str = ""
    secret_key: str = ""
    region: str = ""


# ── Server Request/Response ──────────────────────────────────────

class ScanRequest(BaseModel):
    scan_type: ScanType
    target: str
    options: dict[str, Any] = Field(default_factory=dict)


class CloudScanRequest(BaseModel):
    provider: CloudProvider
    services: list[str] = Field(default_factory=list)  # empty = all
    compliance: list[str] = Field(default_factory=list)  # CIS, SOC2, etc.
    regions: list[str] = Field(default_factory=list)


class LogIngestRequest(BaseModel):
    source_type: LogSourceType
    config: dict[str, Any] = Field(default_factory=dict)
    # S3: {bucket, prefix, region}
    # File: {path, format}
    # Webhook: {name}
    # Syslog: {host, port}


class ToolStatus(BaseModel):
    name: str
    installed: bool = False
    version: str = ""
    path: str = ""
    error: str = ""
