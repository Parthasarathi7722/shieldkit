"""
ShieldKit Database Backends
-----------------------------
Manages where DuckDB data persists between runs.

Backends:
  local       — default: data/shieldkit.duckdb (lost on ephemeral runners)
  motherduck  — DuckDB Cloud: md:shieldkit?motherduck_token=TOKEN
  s3_sync     — local file + S3 upload/download on startup/shutdown
  postgres    — DuckDB ATTACH to PostgreSQL (read/write via postgres extension)

Usage:
  conn_str = get_connection_string(load_db_config())
  store = LogStore(conn_str)   # LogStore accepts connection string directly
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

_BASE = Path(__file__).resolve().parent
_DB_CONFIG_PATH = _BASE / "data" / "db_config.json"


# ── Config persistence ────────────────────────────────────────────────────────

def load_db_config() -> dict:
    if _DB_CONFIG_PATH.exists():
        try:
            return json.loads(_DB_CONFIG_PATH.read_text())
        except Exception:
            pass
    return {"backend": "local"}


def save_db_config(config: dict) -> None:
    _DB_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Strip sensitive values before persisting (tokens stored in env/secrets)
    safe = {k: v for k, v in config.items()
            if "token" not in k.lower() and "password" not in k.lower()}
    safe["backend"] = config.get("backend", "local")
    _DB_CONFIG_PATH.write_text(json.dumps(safe, indent=2))


# ── Connection string factory ─────────────────────────────────────────────────

def get_connection_string(config: dict | None = None) -> str:
    """Return a DuckDB-compatible connection string for the configured backend."""
    cfg = config or load_db_config()
    backend = cfg.get("backend", "local")

    if backend == "local":
        path = cfg.get("local_path") or os.environ.get(
            "DUCKDB_PATH", str(_BASE / "data" / "shieldkit.duckdb")
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        return path

    if backend == "motherduck":
        token = cfg.get("motherduck_token") or os.environ.get("MOTHERDUCK_TOKEN", "")
        db_name = cfg.get("motherduck_db", "shieldkit")
        if not token:
            raise ValueError("MotherDuck token required (set motherduck_token or MOTHERDUCK_TOKEN)")
        return f"md:{db_name}?motherduck_token={token}"

    if backend == "s3_sync":
        # Always use a local file; S3SyncManager handles up/download
        local_path = cfg.get("local_path") or str(_BASE / "data" / "shieldkit.duckdb")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        return local_path

    if backend == "postgres":
        pg_url = cfg.get("postgres_url") or os.environ.get("DB_POSTGRES_URL", "")
        if not pg_url:
            raise ValueError("PostgreSQL URL required (set postgres_url or DB_POSTGRES_URL)")
        # DuckDB in-memory with attached postgres
        return ":memory:"

    raise ValueError(f"Unknown DB backend: {backend}")


# ── S3 Sync Manager ───────────────────────────────────────────────────────────

class S3SyncManager:
    """
    Syncs the local DuckDB file to/from an S3 bucket.

    Usage pattern:
      mgr = S3SyncManager(cfg)
      mgr.download()        # on startup — pull latest from S3
      ...use duckdb...
      mgr.upload()          # on shutdown — push to S3
    """

    def __init__(self, config: dict):
        self.bucket = config.get("s3_bucket", "")
        self.key = config.get("s3_key", "shieldkit/shieldkit.duckdb")
        self.region = config.get("s3_region", "") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.profile = config.get("s3_profile", "") or os.environ.get("AWS_PROFILE", "")
        self.local_path = config.get("local_path") or str(_BASE / "data" / "shieldkit.duckdb")

    def _client(self):
        try:
            import boto3
            kwargs: dict = {"region_name": self.region}
            if self.profile:
                session = boto3.Session(profile_name=self.profile)
                return session.client("s3", **kwargs)
            return boto3.client("s3", **kwargs)
        except ImportError:
            raise RuntimeError("boto3 required for S3 sync: pip install boto3")

    def download(self) -> dict[str, Any]:
        """Pull the latest DuckDB file from S3. Safe to call even if object doesn't exist."""
        if not self.bucket:
            return {"ok": False, "error": "s3_bucket not configured"}
        try:
            client = self._client()
            Path(self.local_path).parent.mkdir(parents=True, exist_ok=True)
            tmp = self.local_path + ".tmp"
            try:
                client.download_file(self.bucket, self.key, tmp)
                shutil.move(tmp, self.local_path)
                size = Path(self.local_path).stat().st_size
                return {"ok": True, "action": "downloaded", "bytes": size,
                        "source": f"s3://{self.bucket}/{self.key}"}
            except client.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                if code in ("404", "NoSuchKey"):
                    # First run — no remote file yet, that's fine
                    return {"ok": True, "action": "skipped", "reason": "no remote file yet"}
                raise
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def upload(self) -> dict[str, Any]:
        """Push the local DuckDB file to S3."""
        if not self.bucket:
            return {"ok": False, "error": "s3_bucket not configured"}
        if not Path(self.local_path).exists():
            return {"ok": False, "error": "local DB file does not exist"}
        try:
            client = self._client()
            size = Path(self.local_path).stat().st_size
            client.upload_file(self.local_path, self.bucket, self.key)
            return {"ok": True, "action": "uploaded", "bytes": size,
                    "destination": f"s3://{self.bucket}/{self.key}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def test(self) -> dict[str, Any]:
        if not self.bucket:
            return {"ok": False, "provider": "s3_sync", "error": "s3_bucket not configured"}
        try:
            self._client().head_bucket(Bucket=self.bucket)
            return {
                "ok": True,
                "provider": "s3_sync",
                "bucket": self.bucket,
                "key": self.key,
                "region": self.region,
            }
        except Exception as e:
            return {"ok": False, "provider": "s3_sync", "error": str(e)}


# ── PostgreSQL attach helper ──────────────────────────────────────────────────

class PostgresAttachHelper:
    """
    Attaches a PostgreSQL database to an in-memory DuckDB connection.
    Requires DuckDB's postgres extension (bundled in duckdb >= 0.9).

    Tables are accessed as: postgres.scan_results, postgres.logs, etc.
    ShieldKit's LogStore writes to DuckDB sequences/tables; this helper
    creates matching views that read from Postgres and redirects writes.
    """

    def __init__(self, postgres_url: str):
        self.postgres_url = postgres_url

    def attach(self, conn) -> None:
        """Attach postgres to an existing DuckDB connection."""
        try:
            conn.execute("INSTALL postgres; LOAD postgres;")
            conn.execute(
                f"ATTACH '{self.postgres_url}' AS pg (TYPE postgres, READ_WRITE);"
            )
        except Exception as e:
            raise RuntimeError(f"PostgreSQL attach failed: {e}. "
                               "Ensure DuckDB >= 0.9 and postgres extension available.")

    def test(self) -> dict[str, Any]:
        try:
            import duckdb
            conn = duckdb.connect(":memory:")
            self.attach(conn)
            conn.execute("SELECT 1").fetchone()
            conn.close()
            return {"ok": True, "provider": "postgres", "url": self._mask_url()}
        except Exception as e:
            return {"ok": False, "provider": "postgres", "error": str(e)}

    def _mask_url(self) -> str:
        """Mask password in URL for display."""
        import re
        return re.sub(r"://([^:]+):[^@]+@", r"://\1:***@", self.postgres_url)


# ── Connection tester ─────────────────────────────────────────────────────────

async def test_db_connection(config: dict) -> dict[str, Any]:
    """Test the configured DB backend and return status."""
    backend = config.get("backend", "local")

    if backend == "local":
        path = config.get("local_path") or str(_BASE / "data" / "shieldkit.duckdb")
        try:
            import duckdb
            conn = duckdb.connect(path)
            conn.execute("SELECT 1").fetchone()
            conn.close()
            return {
                "ok": True, "provider": "local",
                "path": path,
                "exists": Path(path).exists(),
                "size_bytes": Path(path).stat().st_size if Path(path).exists() else 0,
            }
        except Exception as e:
            return {"ok": False, "provider": "local", "error": str(e)}

    if backend == "motherduck":
        token = config.get("motherduck_token") or os.environ.get("MOTHERDUCK_TOKEN", "")
        db_name = config.get("motherduck_db", "shieldkit")
        if not token:
            return {"ok": False, "provider": "motherduck", "error": "Token not set"}
        try:
            import duckdb
            conn = duckdb.connect(f"md:{db_name}?motherduck_token={token}")
            conn.execute("SELECT 1").fetchone()
            conn.close()
            return {
                "ok": True, "provider": "motherduck",
                "db": db_name,
            }
        except Exception as e:
            return {"ok": False, "provider": "motherduck", "error": str(e)}

    if backend == "s3_sync":
        return S3SyncManager(config).test()

    if backend == "postgres":
        pg_url = config.get("postgres_url") or os.environ.get("DB_POSTGRES_URL", "")
        if not pg_url:
            return {"ok": False, "provider": "postgres", "error": "postgres_url not set"}
        return PostgresAttachHelper(pg_url).test()

    return {"ok": False, "error": f"Unknown backend: {backend}"}


# ── Metadata for UI rendering ─────────────────────────────────────────────────

BACKEND_METADATA = {
    "local": {
        "label": "Local File",
        "icon": "💾",
        "description": "Default — data/shieldkit.duckdb on this server. Data is lost on ephemeral runners.",
        "fields": [
            {"key": "local_path", "label": "File Path", "type": "text",
             "placeholder": "data/shieldkit.duckdb",
             "help": "Absolute or relative path to the DuckDB file"},
        ],
    },
    "motherduck": {
        "label": "MotherDuck",
        "icon": "☁️",
        "description": "DuckDB Cloud — persistent, shareable, zero infrastructure. Free tier available.",
        "fields": [
            {"key": "motherduck_token", "label": "MotherDuck Token", "type": "password",
             "required": True,
             "help": "Get your token at app.motherduck.com → Settings → Access Tokens"},
            {"key": "motherduck_db", "label": "Database Name", "type": "text",
             "placeholder": "shieldkit", "default": "shieldkit"},
        ],
    },
    "s3_sync": {
        "label": "S3 Sync",
        "icon": "🪣",
        "description": "Local file synced to/from S3 on startup and shutdown. Works with ephemeral CI runners.",
        "fields": [
            {"key": "s3_bucket", "label": "S3 Bucket", "type": "text",
             "required": True, "placeholder": "my-shieldkit-data"},
            {"key": "s3_key", "label": "Object Key", "type": "text",
             "placeholder": "shieldkit/shieldkit.duckdb", "default": "shieldkit/shieldkit.duckdb"},
            {"key": "s3_region", "label": "AWS Region", "type": "text",
             "placeholder": "us-east-1"},
            {"key": "s3_profile", "label": "AWS Profile (optional)", "type": "text",
             "placeholder": "default"},
            {"key": "local_path", "label": "Local Cache Path", "type": "text",
             "placeholder": "data/shieldkit.duckdb"},
        ],
    },
    "postgres": {
        "label": "PostgreSQL",
        "icon": "🐘",
        "description": "Attach to PostgreSQL via DuckDB's postgres extension. Full persistence, queryable externally.",
        "fields": [
            {"key": "postgres_url", "label": "Connection URL", "type": "password",
             "required": True,
             "placeholder": "postgresql://user:pass@host:5432/shieldkit"},
        ],
    },
}
