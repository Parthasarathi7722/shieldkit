"""
Log Pipeline — End-to-end orchestration: collect → parse → normalize → store.
Connects LogCollector, LogParser, and LogStore into a single pipeline.
"""

from __future__ import annotations

from typing import Any

from ..config import get_config
from ..models import LogSourceType, NormalizedLog
from .collector import LogCollector
from .parser import LogParser
from .store import LogStore


class LogPipeline:
    """Orchestrates the full log ingestion pipeline."""

    def __init__(self, store: LogStore | None = None):
        cfg = get_config()
        self.collector = LogCollector()
        self.parser = LogParser()
        self.store = store or LogStore(cfg.duckdb_path)
        self._ingest_count = 0

    async def ingest(
        self,
        source_type: LogSourceType,
        config: dict[str, Any],
        batch_size: int = 500,
    ) -> dict[str, Any]:
        """
        Run the full pipeline: collect → parse → store.
        Returns summary of ingestion.
        """
        batch: list[NormalizedLog] = []
        total = 0
        errors = 0

        async for raw_log in self.collector.collect(source_type, config):
            try:
                normalized = self.parser.parse(raw_log)
                batch.append(normalized)
                total += 1

                if len(batch) >= batch_size:
                    self.store.insert_logs_batch(batch)
                    batch = []

            except Exception:
                errors += 1
                continue

        # Flush remaining
        if batch:
            self.store.insert_logs_batch(batch)

        self._ingest_count += total
        return {
            "total_ingested": total,
            "errors": errors,
            "source_type": source_type.value,
        }

    async def ingest_mock(self) -> dict[str, Any]:
        """Ingest mock log data for testing."""
        batch: list[NormalizedLog] = []
        total = 0

        async for raw_log in self.collector.collect_mock():
            normalized = self.parser.parse(raw_log)
            batch.append(normalized)
            total += 1

        self.store.insert_logs_batch(batch)
        self._ingest_count += total

        return {
            "total_ingested": total,
            "errors": 0,
            "source_type": "mock",
        }

    def query(self, sql: str, limit: int = 100) -> list[dict]:
        """Execute SQL query against the log store."""
        return self.store.query_sql(sql, limit)

    def search(self, **kwargs) -> list[dict]:
        """Structured search across log fields."""
        return self.store.search_logs(**kwargs)

    def stats(self):
        """Get aggregate log statistics."""
        return self.store.get_stats()

    def close(self):
        self.store.close()
