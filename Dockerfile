FROM python:3.12-slim AS base

# ── System deps ──────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git ca-certificates gnupg && \
    rm -rf /var/lib/apt/lists/*

# ── Node.js 20 (for npx-based MCP servers if needed) ────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*

# ── Go (for nuclei) ─────────────────────────────────────────────
RUN curl -fsSL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ── Security Tools ───────────────────────────────────────────────
# Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    mv /root/go/bin/nuclei /usr/local/bin/

# Prowler + Checkov + ScoutSuite
RUN pip install --no-cache-dir prowler checkov scoutsuite

# ── Application ──────────────────────────────────────────────────
RUN groupadd -g 1001 shieldkit && useradd -u 1001 -g shieldkit -m shieldkit

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data && chown -R shieldkit:shieldkit /app

USER shieldkit

ENV PYTHONUNBUFFERED=1 \
    SHIELDKIT_MODE=mock \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=8000 \
    DUCKDB_PATH=/app/data/shieldkit.duckdb

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["uvicorn", "shieldkit.server:app", "--host", "0.0.0.0", "--port", "8000"]
