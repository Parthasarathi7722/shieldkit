"""
Log Store — DuckDB-backed log storage and analytics.
Handles: insertion, querying (SQL + natural language), stats, retention.
Zero infrastructure — single embedded file.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..models import LogStats, NormalizedLog, Severity


class LogStore:
    """DuckDB-backed log storage with SQL query support."""

    def __init__(self, db_path: str = "data/shieldkit.duckdb"):
        self.db_path = db_path
        self._conn = None

    @property
    def conn(self):
        if self._conn is None:
            import duckdb
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = duckdb.connect(self.db_path)
            self._init_schema()
        return self._conn

    def _init_schema(self):
        # Create sequences first — tables reference them in DEFAULT expressions
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS log_seq START 1")
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS scan_seq START 1")
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS vuln_seq START 1")
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS sbom_seq START 1")
        self.conn.execute("CREATE SEQUENCE IF NOT EXISTS cloud_seq START 1")

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id              INTEGER PRIMARY KEY DEFAULT(nextval('log_seq')),
                timestamp       TIMESTAMP NOT NULL,
                source          VARCHAR NOT NULL,
                source_type     VARCHAR NOT NULL,
                severity        VARCHAR DEFAULT 'info',
                event_type      VARCHAR DEFAULT '',
                actor           VARCHAR DEFAULT '',
                action          VARCHAR DEFAULT '',
                target_resource VARCHAR DEFAULT '',
                source_ip       VARCHAR DEFAULT '',
                region          VARCHAR DEFAULT '',
                account_id      VARCHAR DEFAULT '',
                raw             JSON,
                tags            VARCHAR[] DEFAULT [],
                ingested_at     TIMESTAMP DEFAULT current_timestamp
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_actor ON logs(actor)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)
        """)

        # Scan results table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id              INTEGER PRIMARY KEY DEFAULT(nextval('scan_seq')),
                scan_type       VARCHAR NOT NULL,
                target          VARCHAR NOT NULL,
                tool            VARCHAR NOT NULL,
                started_at      TIMESTAMP NOT NULL,
                completed_at    TIMESTAMP,
                status          VARCHAR DEFAULT 'running',
                summary         JSON,
                raw_output      VARCHAR DEFAULT '',
                created_at      TIMESTAMP DEFAULT current_timestamp
            )
        """)

        # Vulnerabilities table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id                  INTEGER PRIMARY KEY DEFAULT(nextval('vuln_seq')),
                scan_id             INTEGER,
                vuln_id             VARCHAR NOT NULL,
                severity            VARCHAR DEFAULT 'unknown',
                package             VARCHAR DEFAULT '',
                installed_version   VARCHAR DEFAULT '',
                fixed_version       VARCHAR DEFAULT '',
                description         VARCHAR DEFAULT '',
                cvss_score          DOUBLE,
                data_source         VARCHAR DEFAULT '',
                discovered_at       TIMESTAMP DEFAULT current_timestamp
            )
        """)

        # SBOM inventory table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS sbom_components (
                id              INTEGER PRIMARY KEY DEFAULT(nextval('sbom_seq')),
                scan_id         INTEGER,
                target          VARCHAR NOT NULL,
                name            VARCHAR NOT NULL,
                version         VARCHAR DEFAULT '',
                type            VARCHAR DEFAULT 'library',
                purl            VARCHAR DEFAULT '',
                licenses        VARCHAR[] DEFAULT [],
                discovered_at   TIMESTAMP DEFAULT current_timestamp
            )
        """)

        # Cloud findings table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cloud_findings (
                id              INTEGER PRIMARY KEY DEFAULT(nextval('cloud_seq')),
                provider        VARCHAR NOT NULL,
                tool            VARCHAR NOT NULL,
                service         VARCHAR DEFAULT '',
                region          VARCHAR DEFAULT '',
                resource_id     VARCHAR DEFAULT '',
                resource_arn    VARCHAR DEFAULT '',
                check_id        VARCHAR DEFAULT '',
                check_title     VARCHAR DEFAULT '',
                severity        VARCHAR DEFAULT 'unknown',
                status          VARCHAR DEFAULT 'FAIL',
                description     VARCHAR DEFAULT '',
                remediation     VARCHAR DEFAULT '',
                compliance      VARCHAR[] DEFAULT [],
                discovered_at   TIMESTAMP DEFAULT current_timestamp
            )
        """)

    def insert_log(self, log: NormalizedLog):
        self.conn.execute("""
            INSERT INTO logs (timestamp, source, source_type, severity, event_type,
                            actor, action, target_resource, source_ip, region,
                            account_id, raw, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            log.timestamp, log.source, log.source_type.value, log.severity.value,
            log.event_type, log.actor, log.action, log.target_resource,
            log.source_ip, log.region, log.account_id,
            json.dumps(log.raw), log.tags,
        ])

    def insert_logs_batch(self, logs: list[NormalizedLog]):
        for log in logs:
            self.insert_log(log)

    def query_sql(self, sql: str, limit: int = 100) -> list[dict]:
        """Execute raw SQL query against the log store."""
        if "limit" not in sql.lower():
            sql = f"{sql.rstrip(';')} LIMIT {limit}"
        result = self.conn.execute(sql)
        columns = [desc[0] for desc in result.description]
        rows = result.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    def search_logs(
        self,
        source: str = "",
        severity: str = "",
        actor: str = "",
        action: str = "",
        source_ip: str = "",
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        keyword: str = "",
        limit: int = 100,
    ) -> list[dict]:
        """Structured search across normalized log fields."""
        conditions = []
        params = []

        if source:
            conditions.append("source = ?")
            params.append(source)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if actor:
            conditions.append("actor ILIKE ?")
            params.append(f"%{actor}%")
        if action:
            conditions.append("action ILIKE ?")
            params.append(f"%{action}%")
        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        if keyword:
            conditions.append("(action ILIKE ? OR actor ILIKE ? OR target_resource ILIKE ? OR CAST(raw AS VARCHAR) ILIKE ?)")
            params.extend([f"%{keyword}%"] * 4)

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM logs WHERE {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        result = self.conn.execute(sql, params)
        columns = [desc[0] for desc in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]

    def get_stats(self) -> LogStats:
        """Get aggregate statistics about stored logs."""
        total = self.conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

        sources = dict(self.conn.execute(
            "SELECT source, COUNT(*) as cnt FROM logs GROUP BY source ORDER BY cnt DESC"
        ).fetchall())

        severity_counts = dict(self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity ORDER BY cnt DESC"
        ).fetchall())

        time_range = {}
        row = self.conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM logs").fetchone()
        if row[0]:
            time_range = {"earliest": str(row[0]), "latest": str(row[1])}

        top_actors = [
            {"actor": r[0], "count": r[1]}
            for r in self.conn.execute(
                "SELECT actor, COUNT(*) as cnt FROM logs WHERE actor != '' GROUP BY actor ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        ]

        top_actions = [
            {"action": r[0], "count": r[1]}
            for r in self.conn.execute(
                "SELECT action, COUNT(*) as cnt FROM logs WHERE action != '' GROUP BY action ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        ]

        return LogStats(
            total_logs=total,
            sources=sources,
            severity_counts=severity_counts,
            time_range=time_range,
            top_actors=top_actors,
            top_actions=top_actions,
        )

    def cleanup(self, retention_days: int = 90):
        """Delete logs older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        self.conn.execute("DELETE FROM logs WHERE timestamp < ?", [cutoff])

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
