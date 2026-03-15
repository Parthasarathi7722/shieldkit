# ShieldKit — Architecture Diagrams

---

## System Architecture

```mermaid
graph TB
    subgraph UI["Browser UI (SPA — ui/index.html)"]
        D[Dashboard]
        S[Scanner]
        C[Cloud Security]
        L[Log Explorer]
        T[Tools & Config]
        CICD[CI/CD Integration]
        SOC[SOC Analyst Chatbot]
        INFRA[Infrastructure]
        SET[Settings]
    end

    subgraph API["FastAPI Server — server.py"]
        SCAN["/scan/*"]
        CLOUD["/cloud/*"]
        LOGS["/logs/*"]
        INV["/investigate/*"]
        TOOLS["/tools/*"]
        CHAT["/chat + /chat/ws"]
        SEC["/secrets/*"]
        DBAPI["/db/*"]
    end

    subgraph SCANNERS["Scan Pipeline — scanners/"]
        SYFT[Syft — SBOM]
        GRYPE[Grype — SCA]
        TRIVY[Trivy — Container]
        NUCLEI[Nuclei — URL]
        CHECKOV[Checkov — IaC]
        ZAP[OWASP ZAP — DAST]
    end

    subgraph CLOUD_MGR["Cloud Manager — cloud/"]
        PROWLER[Prowler]
        SCOUT[ScoutSuite]
    end

    subgraph LOGPIPE["Log Pipeline — logs/"]
        COLLECT[Collector]
        PARSE[Parser]
        STORE[LogStore]
    end

    subgraph AI["SOC Analyst — Anthropic Claude"]
        CLAUDE[claude-opus-4-6]
        TOOLS_9[9 ShieldKit MCP Tools]
    end

    subgraph DB["DuckDB — data/shieldkit.duckdb"]
        SR[scan_results]
        VL[vulnerabilities]
        SB[sbom_components]
        CF[cloud_findings]
        LG[logs]
    end

    subgraph SM["Secrets Manager — secrets_manager.py"]
        LOCAL[Local AES-256\ndata/secrets.enc]
        VAULT[HashiCorp Vault]
        AWSSM[AWS Secrets Mgr]
        AZUREKV[Azure Key Vault]
        GCPSM[GCP Secret Mgr]
    end

    subgraph DBB["DB Backends — db_backends.py"]
        DBLOC[Local DuckDB file]
        DBMD[MotherDuck Cloud]
        DBS3[S3 Sync]
        DBPG[PostgreSQL ATTACH]
    end

    subgraph MCP["MCP Plugin — mcp_plugin/"]
        MCP_SRV[MCP JSON-RPC Server]
    end

    UI -->|HTTP + WebSocket| API
    SCAN --> SCANNERS
    CLOUD --> CLOUD_MGR
    LOGS --> LOGPIPE
    CHAT --> AI
    AI --> TOOLS_9
    TOOLS_9 --> SCANNERS
    TOOLS_9 --> CLOUD_MGR
    TOOLS_9 -->|SQL| DB
    SCANNERS --> SR
    SCANNERS --> VL
    SCANNERS --> SB
    CLOUD_MGR --> CF
    LOGPIPE --> LG
    INV -->|SQL JOINs| DB
    SEC --> SM
    DBAPI --> DBB
    DBB --> DB
    MCP_SRV --> SCANNERS
    MCP_SRV --> CLOUD_MGR
    MCP_SRV -->|SQL| DB
```

---

## Scan Lifecycle

```mermaid
flowchart TD
    A([API Request\nPOST /scan/sca]) --> B[Load Config\nget_config]
    B --> C{SHIELDKIT_MODE}
    C -->|mock| D[Return MOCK_VULNS\nno tools needed]
    C -->|live| E[Check tool installed\nshutil.which grype]
    E -->|not found| F([Error: tool not installed])
    E -->|found| G[asyncio subprocess\ngrype target -o json]
    G --> H[Parse JSON output\nlist of Vulnerability]
    D --> I[ScanResult\nstatus=completed]
    H --> I
    I --> J[_store_scan_result\nINSERT INTO scan_results]
    J --> K[_store_vulnerabilities\nINSERT per CVE]
    J --> L[_store_sbom_components\nSBOM scans only]
    K --> M([JSON Response])
    L --> M
```

---

## SOC Analyst Chatbot — Agentic Loop

```mermaid
sequenceDiagram
    participant UI as Browser (SOC Tab)
    participant WS as WebSocket /chat/ws
    participant LLM as Claude claude-opus-4-6
    participant TOOLS as ShieldKit Tool Executor

    UI->>WS: {type:"chat", messages:[...], api_key:"sk-..."}
    WS->>LLM: messages + 9 tool definitions (stream=true)

    loop Agentic loop (max 8 iterations)
        LLM-->>WS: stream: text_delta events
        WS-->>UI: {type:"text_delta", text:"..."}
        LLM-->>WS: tool_use block (e.g. shieldkit_sca)
        WS-->>UI: {type:"tool_start", tool:"shieldkit_sca"}
        WS->>TOOLS: _execute_chat_tool("shieldkit_sca", {target:...})
        TOOLS-->>WS: JSON scan result
        WS-->>UI: {type:"tool_result", tool:..., summary:...}
        WS->>LLM: tool_result message
        Note over LLM: Continues reasoning with tool output
    end

    LLM-->>WS: final text response (stop_reason=end_turn)
    WS-->>UI: {type:"done"}
```

---

## Log Ingestion Pipeline

```mermaid
flowchart LR
    subgraph SOURCES["External Sources"]
        S3[S3 / CloudTrail]
        SYSLOG[Syslog UDP 514]
        FILE[Local Files JSONL]
        WEBHOOK[Webhooks]
    end

    subgraph PIPELINE["Log Pipeline — logs/"]
        COL[LogCollector\nasync generator]
        PAR[LogParser\nauto-detect format]
        STO[LogStore\nbatch=500]
    end

    subgraph DETECT["Format Auto-Detection"]
        CT[CloudTrail\neventName field]
        SL[Syslog\nregex pattern]
        VPC[VPC Flow\nsrcaddr field]
        GEN[Generic JSON]
    end

    subgraph DB["DuckDB"]
        LG[logs table\n5 indexes]
    end

    SOURCES --> COL
    COL --> PAR
    PAR --> DETECT
    DETECT --> STO
    STO --> DB
```

---

## DuckDB Correlation Model

```mermaid
erDiagram
    scan_results {
        int id PK
        varchar scan_type
        varchar target
        varchar tool
        timestamp started_at
        varchar status
        json summary
    }
    vulnerabilities {
        int id PK
        int scan_id FK
        varchar vuln_id
        varchar severity
        varchar package
        varchar fixed_version
        double cvss_score
    }
    sbom_components {
        int id PK
        int scan_id FK
        varchar target
        varchar name
        varchar version
        varchar purl
    }
    cloud_findings {
        int id PK
        varchar provider
        varchar check_id
        varchar severity
        varchar status
        varchar resource_arn
    }
    logs {
        int id PK
        timestamp timestamp
        varchar source_type
        varchar severity
        varchar actor
        varchar source_ip
        varchar action
        json raw
    }

    scan_results ||--o{ vulnerabilities : "scan_id"
    scan_results ||--o{ sbom_components : "scan_id"
    vulnerabilities }o--o{ cloud_findings : "check_id / vuln_id"
    sbom_components }o--o{ vulnerabilities : "package name"
    logs }o--o{ vulnerabilities : "source_ip / timestamp"
```

---

## Tool Install & Configuration Flow

```mermaid
sequenceDiagram
    participant UI as Browser (Tools Tab)
    participant API as FastAPI Server
    participant FS as data/tool_configs.json
    participant REG as tool_registry.json

    UI->>API: GET /tools/registry
    API->>REG: read JSON
    REG-->>API: {tools: {grype: {install_methods, config_fields, ...}}}
    API-->>UI: full registry

    Note over UI: User selects tier → checks tools → Install Selected

    UI->>API: POST /tools/install/grype\n{method:"default"}
    API->>REG: _get_install_command(grype, default)
    REG-->>API: "curl -sSfL ... | sh"
    API->>API: asyncio.create_subprocess_exec
    API-->>UI: {status, command, stdout, stderr}

    Note over UI: User opens Configure modal → fills form → Save

    UI->>API: POST /tools/config/grype\n{config:{GRYPE_BIN:...}}
    API->>FS: _save_tool_configs(data)
    API->>API: os.environ[key] = value
    API-->>UI: {status:"saved"}
```

---

## Policy Builder Workflow

```mermaid
sequenceDiagram
    participant U as Browser UI
    participant API as FastAPI Server
    participant FS as data/tool_policies.json

    U->>API: GET /tools/policies/grype
    API->>FS: _load_tool_policies()
    FS-->>API: {grype: [...]}
    API-->>U: {policies: [...]}

    Note over U: User fills policy form (name, severity, only_fixed)

    U->>API: POST /tools/policies/grype\n{policy: {name, description, settings}}
    API->>FS: _save_tool_policies(data)
    API-->>U: {status: "saved"}

    Note over U: User selects policy in scan panel → settings pre-fill

    U->>API: POST /scan/sca\n{target, options: {severity, only_fixed}}
    Note over API: options merged from selected policy
    API-->>U: ScanResult
```

---

## CI/CD Integration — Config Generation

```mermaid
flowchart TD
    A([User opens CI/CD Tab]) --> B[initCICDTab\nrenders platform cards + checkboxes]
    B --> C{Select Platform}
    C -->|GitHub| D[_genGitHub cfg]
    C -->|Jenkins| E[_genJenkins cfg]
    C -->|GitLab| F[_genGitLab cfg]
    C -->|Bitbucket| G[_genBitbucket cfg]
    C -->|ArgoCD| H[_genArgoCD cfg]
    C -->|CircleCI| I[_genCircleCI cfg]
    C -->|Azure DevOps| J[_genAzure cfg]
    C -->|AWS CodeBuild| K[_genCodeBuild cfg]

    D & E & F & G & H & I & J & K --> L[_scanStepsBash\nbuilds curl commands\nfor each selected scan type]
    L --> M{Deployment Mode}
    M -->|Docker| N[Adds service block\n+ health wait]
    M -->|Hosted| O[Adds SHIELDKIT_URL var\n+ verify step]
    N & O --> P[Rendered YAML/Jenkinsfile\nin cicdConfigPreview]
    P --> Q[_renderCICDInstructions\nplatform-specific setup steps]
```

---

## MCP Plugin — External SOCPilot Integration

```mermaid
sequenceDiagram
    participant SOC as SOCPilot Agent
    participant MCP as mcp_plugin/mcp_server.py
    participant SK as ShieldKit Scanners

    SOC->>MCP: JSON-RPC initialize
    MCP-->>SOC: {capabilities: {tools:{}}, serverInfo}

    SOC->>MCP: tools/list
    MCP-->>SOC: [9 tool definitions]

    Note over SOC: Agent decides to run shieldkit_sca

    SOC->>MCP: tools/call\n{name:"shieldkit_sca", arguments:{target:"nginx:latest"}}
    MCP->>SK: SCAScanner.run("nginx:latest", mock=False)
    SK-->>MCP: ScanResult model
    MCP-->>SOC: {content:[{type:"text", text:"...JSON..."}]}
```

---

## Secrets Manager — Provider Selection & sk:// Reference Resolution

```mermaid
flowchart TD
    A([Tool Config saved\nwith sk://aws_key]) --> B[scan triggered\nPOST /scan/sca]
    B --> C[resolve_config_dict\nsecrets_manager.py]
    C --> D{is_secret_ref?}
    D -->|No| E[Use value as-is]
    D -->|Yes — sk://aws_key| F[get_provider\nload secrets_config.json]
    F --> G{provider}
    G -->|local_encrypted| H[LocalEncryptedProvider\ndata/secrets.enc\nFernet AES-256]
    G -->|hashicorp_vault| I[HashiCorpVaultProvider\nREST API — KV v2]
    G -->|aws_secrets| J[AWSSecretsManagerProvider\nboto3]
    G -->|azure_keyvault| K[AzureKeyVaultProvider\nazure-identity]
    G -->|gcp_secret| L[GCPSecretManagerProvider\ngoogle-cloud-secret-manager]
    H & I & J & K & L --> M[plaintext value]
    M --> N[Scanner receives\nresolved config dict]
    E --> N

    subgraph KEY["Master Key Resolution — local_encrypted only"]
        K1{SHIELDKIT_MASTER_KEY\nenv var set?}
        K1 -->|Yes| K2[Use env var key]
        K1 -->|No| K3{data/.master.key\nexists?}
        K3 -->|Yes| K4[Load from file]
        K3 -->|No| K5[Auto-generate\nFernet.generate_key\nchmod 0o600]
    end
```

---

## Database Backend — Startup Selection

```mermaid
flowchart TD
    A([Server startup]) --> B[DBBackendManager\ndb_backends.py]
    B --> C[load_db_config\ndata/db_config.json]
    C --> D{DB_BACKEND}

    D -->|local default| E[LocalDuckDBBackend\ndata/shieldkit.duckdb]
    D -->|motherduck| F[MotherDuckBackend\nmd:shieldkit?token=...\nDuckDB Cloud]
    D -->|s3_sync| G[S3SyncDuckDBBackend]
    D -->|postgres| H[PostgresDuckDBBackend\nDuckDB ATTACH]

    G --> G1[download on startup\nfrom s3://bucket/key]
    G1 --> G2[run scans against\nlocal copy]
    G2 --> G3[upload on shutdown\nback to S3]

    H --> H1[duckdb.connect memory]
    H1 --> H2["ATTACH postgresql://... AS pg"]
    H2 --> H3[queries run across\nboth DuckDB + Postgres]

    E & F & G2 & H3 --> I[LogStore gets\nconnection string]
    I --> J[_init_schema\ncreate tables + indexes\nif not exists]
```

---

## Infrastructure Tab — Secrets + DB Config Flow

```mermaid
sequenceDiagram
    participant UI as Browser (Infrastructure Tab)
    participant API as FastAPI /secrets/* /db/*
    participant SM as secrets_manager.py
    participant DBB as db_backends.py
    participant FS as data/ files

    UI->>API: GET /secrets/providers
    API->>SM: PROVIDER_METADATA dict
    SM-->>API: {providers: {local_encrypted, hashicorp_vault, ...}}
    API-->>UI: provider cards + config fields

    UI->>API: GET /secrets/config
    API->>FS: load secrets_config.json
    FS-->>API: {provider, ...fields}
    API-->>UI: current saved config

    Note over UI: User fills provider fields → Save Config

    UI->>API: POST /secrets/config {"config": {...}}
    API->>SM: save_secrets_config (strips tokens/keys)
    API->>SM: invalidate_provider_cache
    API-->>UI: {status: "saved"}

    Note over UI: User stores a secret

    UI->>API: POST /secrets/set {"key": "anthropic_api_key", "value": "sk-ant-..."}
    API->>SM: get_provider → provider.set(key, value)
    SM->>FS: encrypt → data/secrets.enc
    API-->>UI: {ref: "sk://anthropic_api_key"}

    Note over UI: sk:// reference shown as badge in tool config
```
