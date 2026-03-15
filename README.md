# ShieldKit — DevSecOps Security Suite

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Mode](https://img.shields.io/badge/default%20mode-mock-yellow.svg)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)

ShieldKit is an open-source security platform that brings SBOM generation, vulnerability scanning, container security, IaC misconfiguration detection, DAST, cloud posture assessment, and log analytics into a single browser UI and REST API. It ships a built-in **SOC Analyst chatbot** (Claude-powered), a **CI/CD Integration** config generator for 8 platforms, a **Secrets Manager** (AES-256 / Vault / AWS SM / Azure KV / GCP SM), and **persistent DuckDB backends** (local / MotherDuck / S3 sync / PostgreSQL).

It runs standalone in **mock mode with zero external tools** — open the browser and every feature works with sample data. Switch to live mode to run real scans against real targets. Connects to [SOCPilot](https://github.com/Parthasarathi7722/mcp-security-ops-suit) as an MCP server for AI-powered investigations.

> Architecture diagrams, ER models, and sequence diagrams live in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## What's Inside

| Category | Tool | What It Does |
| --- | --- | --- |
| SBOM Generation | Syft | Software Bill of Materials — CycloneDX / SPDX |
| SCA | Grype | CVE scanning against dependency databases |
| Container Scanning | Trivy | OS + app vulnerabilities in container images |
| URL Scanning | Nuclei | Endpoint vuln detection via community templates |
| DAST | OWASP ZAP | Dynamic app security testing — baseline / full / API modes |
| Cloud Security | Prowler | AWS / Azure / GCP posture against CIS, SOC2, PCI-DSS |
| Cloud Auditing | ScoutSuite | Multi-cloud assessment with HTML reports |
| IaC Scanning | Checkov | Terraform, CloudFormation, K8s, Dockerfile checks |
| Log Analytics | DuckDB | Embedded SQL for CloudTrail, syslog, VPC flow logs |
| SOC Chatbot | Claude | AI analyst with live tool access — chat to scan & investigate |

---

## Prerequisites

| Requirement | Version | Notes |
| --- | --- | --- |
| Python | 3.10+ | For running the FastAPI server directly |
| Docker | 24+ | Optional — required for Docker Compose quickstart and ZAP DAST |
| pip packages | see `requirements.txt` | `pip install -r requirements.txt` |

Security tools (Syft, Grype, Trivy, etc.) are **not required** to start — mock mode works without them.

---

## Quick Start

### Option A — Docker Compose (recommended, zero config)

```bash
git clone https://github.com/Parthasarathi7722/shieldkit.git
cd shieldkit
docker compose up
```

Open **http://localhost:8000**. That's it. Mock mode is the default — every feature works with sample data, no configuration needed.

To add the AI chatbot or run live scans, copy the env template and fill in your keys:

```bash
cp .env.example .env        # edit .env: add AI_API_KEY, SHIELDKIT_MODE=live, etc.
docker compose up
```

For DAST scanning with OWASP ZAP:

```bash
docker compose --profile tools up   # starts ShieldKit + ZAP container
```

### Option B — Python (no Docker)

```bash
git clone https://github.com/Parthasarathi7722/shieldkit.git
cd shieldkit
pip install -r requirements.txt
python run.py
```

Open **http://localhost:8000** — mock mode, no tools required.

> `run.py` sets `SHIELDKIT_MODE=mock` by default and handles the Python package path.
> For live mode: `SHIELDKIT_MODE=live python run.py`

### Option C — Interactive Setup Wizard (live mode)

```bash
python onboard.py          # guided wizard: creates .env, installs tools
python run.py              # reads .env automatically
```

### Verify the server is running

```bash
curl http://localhost:8000/health

# Quick scan smoke test
curl -s -X POST http://localhost:8000/scan/sca \
  -H "Content-Type: application/json" \
  -d '{"target":"nginx:latest"}'
```

---

## Configuration

### Environment Variables

A fully annotated template is provided:

```bash
cp .env.example .env    # then edit .env with your values
```

All keys are optional — the server starts in mock mode without any `.env`. Key variables:

```bash
# ── Mode ──────────────────────────────────────────────────
SHIELDKIT_MODE=mock          # mock | live

# ── Server ────────────────────────────────────────────────
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# ── Database ──────────────────────────────────────────────
DUCKDB_PATH=data/shieldkit.duckdb
LOG_RETENTION_DAYS=90

# ── Tool Paths (auto-detected from PATH if omitted) ───────
SYFT_BIN=syft
GRYPE_BIN=grype
TRIVY_BIN=trivy
NUCLEI_BIN=nuclei
CHECKOV_BIN=checkov
PROWLER_BIN=prowler
SCOUTSUITE_BIN=scout

# ── OWASP ZAP ─────────────────────────────────────────────
ZAP_USE_DOCKER=true                              # true = Docker image, false = native daemon
ZAP_DOCKER_IMAGE=ghcr.io/zaproxy/zaproxy:stable
ZAP_HOST=localhost                               # used only when ZAP_USE_DOCKER=false
ZAP_PORT=8080
ZAP_API_KEY=

# ── AWS ───────────────────────────────────────────────────
AWS_PROFILE=default
AWS_REGION=us-east-1

# ── Azure ─────────────────────────────────────────────────
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=

# ── GCP ───────────────────────────────────────────────────
GCP_PROJECT_ID=
```

---

## Installing Tools

### Via the Browser UI (recommended)

1. Open `http://localhost:8000` → **Tools & Config** tab
2. Pick a tier preset — **Starter**, **Full Scanner**, **Cloud**, **DAST**, or **Full**
3. Click **Install Selected** → choose an install method per tool → **Start Install**
4. After each install completes, click **Configure** to set credentials

### Via the onboarding CLI

```bash
python onboard.py --tier starter   # Syft + Grype + Trivy
python onboard.py --tier full      # + Nuclei + Checkov
python onboard.py --tier cloud     # + Prowler + ScoutSuite
python onboard.py --add zap        # Add OWASP ZAP only
python onboard.py --check          # Verify all installations
```

### Manually

```bash
# macOS (Homebrew)
brew install anchore/grype/grype anchore/syft/syft aquasecurity/trivy/trivy
pip install checkov prowler nuclei

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
wget -qO- https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux_64bit.tar.gz | tar xz -C /usr/local/bin trivy

# OWASP ZAP (Docker — recommended)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

---

## Saving Tool Configuration

Configure credentials and binary paths via the UI (Tools tab → Configure) or API:

```bash
# Save Grype settings
curl -X POST http://localhost:8000/tools/config/grype \
  -H "Content-Type: application/json" \
  -d '{"config": {"GRYPE_DB_UPDATE_ON_START": "true", "GRYPE_FAIL_ON_SEVERITY": "high"}}'

# Save Prowler cloud credentials
curl -X POST http://localhost:8000/tools/config/prowler \
  -H "Content-Type: application/json" \
  -d '{"config": {"AWS_PROFILE": "prod", "AWS_REGION": "us-east-1"}}'

# Save ZAP settings
curl -X POST http://localhost:8000/tools/config/zap \
  -H "Content-Type: application/json" \
  -d '{"config": {"ZAP_USE_DOCKER": "true", "ZAP_API_KEY": "changeme"}}'

# Read saved config
curl http://localhost:8000/tools/config
```

Configs persist to `data/tool_configs.json` and are applied to the process environment at save time.

---

## Running Scans

### From the Browser UI

**Scanner** tab → select scan type → enter target → (optionally pick a policy) → **Run Scan**

The target input area adapts dynamically as you work:

- **Target-type pills auto-filter** — when you switch scan type, the source pills (Auto / Upload / Public URL / Private URL / S3 / Git / Container) automatically hide options that are not valid for that type. For example, URL scans show only Auto / Public URL / Private URL; Container scans hide the Git pill; IaC scans hide the Container pill.
- **Contextual hint panel** — after selecting a target type, a hint panel appears below the target input showing accepted file formats, example values, and shell commands to prepare the artifact (e.g., `docker save nginx:latest -o nginx.tar` for container file uploads; `zip -r infra.zip terraform/` for IaC file uploads).
- **URL / S3 / GitHub auto-detection** — while typing in the target field in Auto mode, ShieldKit inspects the value and shows a dismissible banner when it detects a GitHub / GitLab / Bitbucket URL (suggests switching to Git), an `s3://` URI (suggests S3), or a plain `https://` URL (suggests Public URL). A one-click link in the banner switches the target type immediately.
- **Recent-uploads quick-pick** — when the Upload target type is active, a row appears below the dropzone listing the 8 most recent uploads retrieved from `/uploads`. Select one from the picker and click **Use** to reuse a previous artifact without re-uploading.

Each scan type has a dedicated options panel:
- **SBOM / SCA / Container / IaC** — policy picker, format/severity options
- **URL (Nuclei)** — template categories, severity, rate limit, concurrency, custom templates
- **DAST (ZAP)** — scan mode (baseline / full / api), auth method, attack strength, alert threshold

### Via the API

```bash
# SBOM — generate software bill of materials
curl -X POST http://localhost:8000/scan/sbom \
  -H "Content-Type: application/json" \
  -d '{"target": "nginx:latest"}'

# SCA — dependency vulnerability scan
curl -X POST http://localhost:8000/scan/sca \
  -H "Content-Type: application/json" \
  -d '{"target": "nginx:latest", "options": {"severity": "critical,high"}}'

# Container — OS + app vulnerability scan
curl -X POST http://localhost:8000/scan/container \
  -H "Content-Type: application/json" \
  -d '{"target": "myapp:v1.2.3", "options": {"ignore_unfixed": true}}'

# URL — Nuclei endpoint scan
curl -X POST http://localhost:8000/scan/url \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "options": {
      "categories": ["cves", "misconfigs", "exposures"],
      "severity": ["critical", "high"],
      "rate_limit": 100
    }
  }'

# IaC — Terraform misconfiguration scan
curl -X POST http://localhost:8000/scan/iac \
  -H "Content-Type: application/json" \
  -d '{"target": "./terraform/", "options": {"framework": "terraform"}}'

# DAST — ZAP baseline (passive, safe for production)
curl -X POST http://localhost:8000/scan/zap \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_mode": "baseline", "auth_method": "none"}'

# DAST — ZAP full active scan with form authentication
curl -X POST http://localhost:8000/scan/zap \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_mode": "full",
    "auth_method": "form",
    "auth_config": {
      "login_url": "https://example.com/login",
      "username_field": "username",
      "password_field": "password",
      "username": "testuser",
      "password": "testpass"
    },
    "attack_strength": "high",
    "alert_threshold": "medium"
  }'

# Full parallel scan — SBOM + SCA + Container in one call
curl -X POST http://localhost:8000/scan/full \
  -H "Content-Type: application/json" \
  -d '{"target": "nginx:latest"}'

# Cloud posture assessment
curl -X POST http://localhost:8000/cloud/scan \
  -H "Content-Type: application/json" \
  -d '{"provider": "aws", "tool": "prowler", "compliance": ["cis", "soc2"]}'
```

---

## Scan Policies

Named, reusable scan settings per tool. Create via the UI (Tools tab → Configure → Policies) or API.

Policies can store a **Default Target** (a target type and value) at the bottom of the policy editor. When you apply a policy from the Scanner tab, the target field and the target-type pill are automatically pre-filled with the stored defaults, removing the need to re-enter a target for recurring scans.

```bash
# Create a strict production policy for Grype
curl -X POST http://localhost:8000/tools/policies/grype \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "Strict Production",
      "description": "Block critical and high — only fixed CVEs",
      "settings": {"severity": "critical,high", "only_fixed": "true"}
    }
  }'

# Terraform-only Checkov policy
curl -X POST http://localhost:8000/tools/policies/checkov \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "Terraform CIS",
      "settings": {"framework": "terraform", "soft_fail": "false"}
    }
  }'

# List policies for a tool
curl http://localhost:8000/tools/policies/grype

# Delete a policy
curl -X DELETE http://localhost:8000/tools/policies/grype/Strict%20Production
```

---

## SOC Analyst Chatbot

The **SOC Analyst** tab embeds a Claude-powered AI analyst with live access to all ShieldKit scanning tools. It can run scans mid-conversation, correlate findings, query logs, and generate incident reports.

### Setup

1. Get an Anthropic API key at [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
2. In the UI, go to **Settings** → paste your key in **SOC Analyst API Key** → **Save Settings**
3. Open the **SOC Analyst** tab and start chatting

### What it can do

- Run any scan type on a target you describe in natural language
- Query and correlate security logs
- Fetch recent scan history and summarize risk
- Generate prioritized remediation guidance
- Chain multiple scans and explain what it found

### Example prompts

```
Scan nginx:latest for vulnerabilities and tell me what to fix first.

Run a DAST baseline scan on https://example.com and summarize the findings.

Check the IaC in ./terraform for misconfigs and give me a risk score.

Show me the last 5 scans and which ones had critical findings.

Query logs for suspicious activity from IP 203.0.113.45 in the last 24 hours.
```

### API (programmatic use)

```bash
# Single-turn via REST
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": "Scan nginx:latest and summarize risks"}],
    "api_key": "sk-ant-api03-..."
  }'

# Streaming via WebSocket — connect to ws://localhost:8000/chat/ws
# Send: {"type":"chat","messages":[...],"api_key":"sk-ant-..."}
# Receive: text_delta | tool_start | tool_running | tool_result | done | error
```

---

## CI/CD Integration

The **CI/CD Integration** tab generates ready-to-copy pipeline configs for 8 platforms. No backend required — configs are generated in the browser.

### Supported Platforms

| Platform | Output File |
| --- | --- |
| GitHub Actions | `.github/workflows/shieldkit.yml` |
| Jenkins | `Jenkinsfile` |
| GitLab CI | `.gitlab-ci.yml` |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` |
| ArgoCD | `shieldkit-presync-job.yaml` |
| CircleCI | `.circleci/config.yml` |
| Azure DevOps | `azure-pipelines.yml` |
| AWS CodeBuild | `buildspec.yml` |

### How to use

1. Open the **CI/CD Integration** tab
2. Select your platform
3. Check which scans to include (SBOM, SCA, Container, IaC, DAST, Cloud)
4. Set the **Fail Build On** severity threshold (Critical / Critical+High / Critical+High+Medium / Never)
5. Enter the scan target and your ShieldKit URL
6. Choose **Docker** (spin up ShieldKit in the pipeline) or **Hosted** (connect to a running instance)
7. Click **Generate Config** → **Copy** or **Download**
8. Follow the platform-specific setup steps shown below the config

---

## Log Analytics & Investigation

### Ingest logs

```bash
# Load sample mock data (no real sources needed)
curl -X POST http://localhost:8000/logs/ingest/mock

# CloudTrail from S3
curl -X POST http://localhost:8000/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{"source_type": "cloudtrail", "config": {"bucket": "my-trail-bucket", "region": "us-east-1"}}'

# Local log file
curl -X POST http://localhost:8000/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{"source_type": "file", "config": {"path": "/var/log/app.json", "format": "json"}}'

# Syslog listener (collects for 10 seconds)
curl -X POST http://localhost:8000/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{"source_type": "syslog", "config": {"host": "0.0.0.0", "port": 514}}'
```

### Query logs

```bash
# Structured search
curl -X POST http://localhost:8000/logs/query \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "203.0.113.45", "severity": "high", "limit": 50}'

# Raw SQL (full DuckDB dialect)
curl -X POST http://localhost:8000/logs/query \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT source_type, COUNT(*) as n FROM logs GROUP BY source_type"}'

# Aggregate statistics
curl http://localhost:8000/logs/stats
```

### Investigate & correlate

```bash
# Unified timeline — logs + scans + cloud findings in one stream
curl "http://localhost:8000/investigate/timeline?hours=24"

# Full profile for an IP — first seen, all actions, severity breakdown
curl http://localhost:8000/investigate/ip/203.0.113.45

# Package investigation — SBOM occurrences + CVEs + related logs
curl http://localhost:8000/investigate/package/express

# CVE cross-scan view — all scans that found it + matching cloud findings
curl http://localhost:8000/investigate/vuln/CVE-2024-50623
```

### Useful correlation queries

```sql
-- Packages with critical CVEs deployed across multiple targets
SELECT v.package, v.vuln_id, v.severity, v.cvss_score,
       COUNT(DISTINCT sr.target) as affected_targets
FROM vulnerabilities v
JOIN scan_results sr ON v.scan_id = sr.id
WHERE v.severity = 'critical'
GROUP BY v.package, v.vuln_id, v.severity, v.cvss_score
ORDER BY affected_targets DESC, v.cvss_score DESC;

-- Suspicious IPs: failed auth attempts in the last 24 hours
SELECT l.source_ip, l.actor, COUNT(*) as failed_auths,
       MIN(l.timestamp) as first_attempt
FROM logs l
WHERE l.event_type = 'authentication'
  AND l.severity IN ('medium', 'high', 'critical')
  AND l.timestamp > now() - INTERVAL '24 hours'
GROUP BY l.source_ip, l.actor
ORDER BY failed_auths DESC;

-- IaC checks that also appear as live cloud posture failures
SELECT DISTINCT v.vuln_id as check_id, v.severity,
       cf.service, cf.resource_arn, cf.status
FROM vulnerabilities v
JOIN scan_results sr ON v.scan_id = sr.id
JOIN cloud_findings cf ON cf.check_id = v.vuln_id
WHERE sr.scan_type = 'iac'
ORDER BY v.severity;

-- Full audit trail during an incident window
SELECT timestamp::VARCHAR as ts, 'log' as kind,
       actor, action, source_ip, target_resource as target
FROM logs
WHERE timestamp BETWEEN '2025-01-15 02:00' AND '2025-01-15 03:00'
UNION ALL
SELECT started_at::VARCHAR, 'scan', '', scan_type, '', target
FROM scan_results
WHERE started_at BETWEEN '2025-01-15 02:00' AND '2025-01-15 03:00'
ORDER BY ts;
```

---

## Browser UI Tabs

| Tab | What it does |
| --- | --- |
| **Dashboard** | Clickable stat cards (Critical/High/Cloud/Logs), live scan history with report modal, quick-action buttons |
| **Scanner** | Select scan type → target pills auto-filter to valid types → contextual hints + file-format guidance → URL/S3/GitHub auto-detection → recent-uploads quick-pick → configure options / policy → run → live results |
| **Cloud Security** | Provider + compliance selector → run posture scan → findings table |
| **Log Explorer** | Search / SQL query panel · Stats sidebar · Log results table · Investigate & Correlate panel |
| **Tools & Config** | Install tools (tier presets / batch install) · Configure credentials · Manage scan policies |
| **CI/CD Integration** | Generate pipeline configs for 8 platforms with security gates |
| **SOC Analyst** | AI chatbot with live scanning tools — investigate threats in natural language |
| **Infrastructure** | Secrets Manager (AES-256 / Vault / AWS SM / Azure KV / GCP SM) + DuckDB persistence (local / MotherDuck / S3 sync / PostgreSQL) |
| **Settings** | API endpoint, WebSocket URL, Anthropic API key for SOC Analyst |

---

## API Reference

Full interactive docs at `http://localhost:8000/docs` (Swagger UI).

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Server status and mode |
| POST | `/scan/sbom` | Generate SBOM (Syft) |
| POST | `/scan/sca` | Vulnerability scan (Grype) |
| POST | `/scan/container` | Container scan (Trivy) |
| POST | `/scan/url` | URL / endpoint scan (Nuclei) |
| POST | `/scan/iac` | IaC misconfiguration scan (Checkov) |
| POST | `/scan/zap` | DAST scan (OWASP ZAP) |
| POST | `/scan/full` | Parallel SBOM + SCA + Container |
| POST | `/scan/upload` | Upload a file artifact for scanning (multipart/form-data) |
| GET | `/uploads` | List previously uploaded files |
| DELETE | `/uploads/{id}` | Delete an uploaded file |
| POST | `/cloud/scan` | Cloud posture scan |
| POST | `/cloud/scan-all` | Scan all configured cloud providers |
| GET | `/cloud/providers` | Supported providers and tools |
| GET | `/cloud/compliance` | Available compliance frameworks |
| POST | `/logs/ingest` | Ingest logs from a source |
| POST | `/logs/ingest/mock` | Ingest sample log data |
| POST | `/logs/query` | SQL or structured log search |
| GET | `/logs/stats` | Aggregate log statistics |
| GET | `/history/scans` | Scan history from DuckDB |
| GET | `/history/vulnerabilities` | CVE history from DuckDB |
| GET | `/investigate/timeline` | Unified event timeline |
| GET | `/investigate/ip/{ip}` | IP activity profile |
| GET | `/investigate/package/{name}` | Package SBOM + CVE + log correlation |
| GET | `/investigate/vuln/{id}` | CVE cross-scan view |
| GET | `/tools/status` | Installation status of all tools |
| GET | `/tools/registry` | Full tool registry JSON |
| GET | `/tools/config` | All saved tool configurations |
| GET | `/tools/config/{tool}` | Single tool configuration |
| POST | `/tools/config/{tool}` | Save tool configuration |
| POST | `/tools/install/{tool}` | Run install command for a tool |
| GET | `/tools/policies/{tool}` | List scan policies for a tool |
| POST | `/tools/policies/{tool}` | Create or update a scan policy |
| DELETE | `/tools/policies/{tool}/{name}` | Delete a scan policy |
| GET | `/secrets/providers` | Supported secrets provider types |
| GET | `/secrets/config` | Current secrets provider config |
| POST | `/secrets/config` | Save secrets provider config (`{"config": {...}}`) |
| POST | `/secrets/test` | Test secrets provider connectivity (`{"config": {...}}`) |
| POST | `/secrets/set` | Store a secret (`{"key": "name", "value": "..."}`) |
| GET | `/secrets/list` | List stored secret key names (never values) |
| DELETE | `/secrets/{key}` | Delete a secret |
| GET | `/db/backends` | Supported database backends |
| GET | `/db/config` | Current database backend config |
| POST | `/db/config` | Save database backend config (`{"config": {...}}`) |
| POST | `/db/test` | Test database backend connection (`{"config": {...}}`) |
| POST | `/db/sync` | Trigger manual S3 sync (`{"direction": "upload" or "download"}`) |
| GET | `/db/status` | Current database connection status |
| POST | `/chat` | SOC Analyst — single-turn REST (`{"messages": [{"role": "user", "content": "..."}], "api_key": "..."}`) |
| WS | `/chat/ws` | SOC Analyst — streaming WebSocket |

---

## Deployment Tiers

| Tier | Tools Included | Use Case |
| --- | --- | --- |
| **Starter** | Syft, Grype, Trivy | Dev / CI — SBOM + CVE + container |
| **Full Scanner** | Starter + Nuclei, Checkov | + URL endpoint tests + IaC checks |
| **Cloud Security** | Full Scanner + Prowler, ScoutSuite | + AWS / Azure / GCP posture |
| **DAST** | Full Scanner + OWASP ZAP | + Dynamic app security testing |
| **Full** | All of the above | Complete DevSecOps coverage |
| **Custom** | Pick your tools | Targeted deployment |

---

## SOCPilot MCP Integration

ShieldKit exposes itself as an MCP server for [SOCPilot](https://github.com/Parthasarathi7722/mcp-security-ops-suit). Add to SOCPilot's `mcp_config.json`:

```json
{
  "mcpServers": {
    "shieldkit": {
      "command": "python",
      "args": ["-m", "shieldkit.mcp_plugin"],
      "env": { "SHIELDKIT_MODE": "live" }
    }
  }
}
```

This exposes 9 tools to the SOCPilot AI agent:

| MCP Tool | Maps To |
| --- | --- |
| `shieldkit_sbom` | `POST /scan/sbom` |
| `shieldkit_sca` | `POST /scan/sca` |
| `shieldkit_container_scan` | `POST /scan/container` |
| `shieldkit_url_scan` | `POST /scan/url` |
| `shieldkit_iac_scan` | `POST /scan/iac` |
| `shieldkit_cloud_scan` | `POST /cloud/scan` |
| `shieldkit_log_query` | `POST /logs/query` |
| `shieldkit_log_stats` | `GET /logs/stats` |
| `shieldkit_log_ingest` | `POST /logs/ingest` |

**Example SOCPilot prompt:**

> "Alert SEC-7721: suspicious activity on payments-api container.
> Run SBOM + SCA on the image, check cloud posture for the hosting account,
> and search logs for the source IP 203.0.113.45."

---

## Secrets Manager

Store API keys and credentials securely. Reference them as `sk://key-name` anywhere in tool configs — the server resolves to plaintext only at scan time.

| Provider | Description |
| --- | --- |
| **Local (AES-256)** | Fernet-encrypted file in `data/secrets.enc`. Zero external dependencies. Default. |
| **HashiCorp Vault** | KV v2. Token auth. No SDK required — pure REST. |
| **AWS Secrets Manager** | boto3. `shieldkit/{key}` naming convention. |
| **Azure Key Vault** | `azure-identity` + `azure-keyvault-secrets`. DefaultAzureCredential. |
| **GCP Secret Manager** | `google-cloud-secret-manager`. `projects/{project}/secrets/shieldkit-{key}`. |

Configure in the **Infrastructure** tab or via API (`POST /secrets/config`).

```bash
# Store a secret
curl -X POST http://localhost:8000/secrets/set \
  -H "Content-Type: application/json" \
  -d '{"key": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE"}'

# Returns: {"ref": "sk://aws_access_key"}
# Use in tool config: {"aws_access_key_id": "sk://aws_access_key"}
```

---

## Database Persistence

DuckDB data survives server restarts and CI runner teardowns with cloud backends.

| Backend | Description | Connection |
| --- | --- | --- |
| **Local** | `data/shieldkit.duckdb` (default) | Lost on ephemeral runners |
| **MotherDuck** | DuckDB Cloud — free tier available | `md:shieldkit?token=...` |
| **S3 Sync** | Download on startup, upload on shutdown | Any S3-compatible store |
| **PostgreSQL** | DuckDB ATTACH via postgres extension | `postgresql://user:pass@host/db` |

Configure in the **Infrastructure** tab or set `DB_BACKEND` env var.

---

## Onboarding CLI

```bash
python onboard.py              # Full interactive wizard
python onboard.py --check      # Verify all tool installations
python onboard.py --list       # List available tools and status
python onboard.py --add trivy  # Add and configure a single tool
python onboard.py --tier cloud # Set up a deployment tier
```

---

## Project Structure

```
shieldkit/
├── server.py               # FastAPI app — all HTTP + WebSocket endpoints
├── config.py               # Centralised env-var config, lazy singleton
├── models.py               # Shared Pydantic models (ScanResult, Vulnerability, …)
├── secrets_manager.py      # Secrets abstraction — 5 provider backends
├── db_backends.py          # DuckDB persistence — local/MotherDuck/S3/Postgres
├── onboard.py              # Interactive setup wizard
├── run.py                  # Startup script — sets sys.path, loads .env
├── tool_registry.json      # Tool metadata, install commands, config fields
├── ARCHITECTURE.md         # System diagrams, flowcharts, ER models
├── scanners/
│   ├── base.py             # BaseScanner + async _run_cmd + check_tool
│   ├── sbom.py             # SBOMScanner  → Syft
│   ├── sca.py              # SCAScanner   → Grype
│   ├── container.py        # ContainerScanner → Trivy
│   ├── url_scanner.py      # URLScanner   → Nuclei
│   ├── iac.py              # IaCScanner   → Checkov
│   └── zap_scanner.py      # ZAPScanner   → OWASP ZAP (Docker + daemon)
├── cloud/
│   ├── cloud_manager.py        # Routes to Prowler or ScoutSuite
│   ├── prowler_scanner.py      # Prowler multi-cloud assessment
│   └── scoutsuite_scanner.py   # ScoutSuite auditing
├── logs/
│   ├── collector.py        # S3 / CloudTrail / file / syslog / webhook
│   ├── parser.py           # Auto-detect + normalize → NormalizedLog
│   ├── store.py            # DuckDB schema, insert, query, stats
│   └── pipeline.py         # Collect → parse → store orchestration
├── mcp_plugin/
│   ├── mcp_server.py       # MCP JSON-RPC server (9 tools for SOCPilot)
│   └── __main__.py         # Entry point: python -m shieldkit.mcp_plugin
├── ui/
│   └── index.html          # Single-file SPA — all 10 tabs, styles, JS (~6500 lines)
├── data/
│   ├── shieldkit.duckdb    # All persistent data (auto-created)
│   ├── tool_configs.json   # Saved tool configurations (auto-created)
│   ├── tool_policies.json  # Saved scan policies (auto-created)
│   ├── secrets.enc         # AES-256 encrypted secrets (auto-created)
│   ├── secrets_config.json # Secrets provider selection (auto-created)
│   └── db_config.json      # Database backend selection (auto-created)
├── Dockerfile
├── docker-compose.yml
├── .env.example            # Annotated config template — copy to .env
└── requirements.txt
```

---

## License

MIT

---

**Part of the Chaos to Control ecosystem:**
- [SOCPilot](https://github.com/Parthasarathi7722/mcp-security-ops-suit) — AI-powered SOC co-pilot
- [DevSecOps Pipeline](https://github.com/Parthasarathi7722/devsecops-pipeline) — CI/CD security gates
- [Cloud Security Checklists](https://github.com/Parthasarathi7722/cloud-security-checklists) — AWS hardening by service
