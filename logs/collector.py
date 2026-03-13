"""
Log Collector — Ingests raw logs from multiple sources.
Supports: S3 buckets, CloudTrail, local files, syslog, webhooks.
"""

from __future__ import annotations

import json
import gzip
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator

from ..models import LogSourceType


class LogCollector:
    """Collects raw log entries from various sources."""

    async def collect(
        self, source_type: LogSourceType, config: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Route to the appropriate collector based on source type."""
        collectors = {
            LogSourceType.S3: self._collect_s3,
            LogSourceType.CLOUDTRAIL: self._collect_cloudtrail,
            LogSourceType.FILE: self._collect_file,
            LogSourceType.SYSLOG: self._collect_syslog,
            LogSourceType.WEBHOOK: self._collect_webhook,
        }
        collector = collectors.get(source_type)
        if not collector:
            raise ValueError(f"Unsupported source type: {source_type}")
        async for record in collector(config):
            yield record

    async def _collect_s3(self, config: dict) -> AsyncIterator[dict]:
        """
        Collect logs from S3 bucket.
        Config: {bucket, prefix, region, profile?}
        Requires: boto3
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 required for S3 collection: pip install boto3")

        session_kwargs = {}
        if config.get("profile"):
            session_kwargs["profile_name"] = config["profile"]
        if config.get("region"):
            session_kwargs["region_name"] = config["region"]

        session = boto3.Session(**session_kwargs)
        s3 = session.client("s3")
        bucket = config["bucket"]
        prefix = config.get("prefix", "")

        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith((".json", ".json.gz", ".log", ".log.gz")):
                    continue

                response = s3.get_object(Bucket=bucket, Key=key)
                body = response["Body"].read()

                if key.endswith(".gz"):
                    body = gzip.decompress(body)

                text = body.decode("utf-8", errors="replace")
                for line in text.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        record["_source_key"] = key
                        yield record
                    except json.JSONDecodeError:
                        yield {"raw": line, "_source_key": key}

    async def _collect_cloudtrail(self, config: dict) -> AsyncIterator[dict]:
        """
        Collect CloudTrail logs from S3.
        Config: {bucket, prefix?, region, profile?}
        CloudTrail stores gzipped JSON with Records array.
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 required for CloudTrail: pip install boto3")

        session_kwargs = {}
        if config.get("profile"):
            session_kwargs["profile_name"] = config["profile"]
        if config.get("region"):
            session_kwargs["region_name"] = config["region"]

        session = boto3.Session(**session_kwargs)
        s3 = session.client("s3")
        bucket = config["bucket"]
        prefix = config.get("prefix", "AWSLogs/")

        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".json.gz"):
                    continue

                response = s3.get_object(Bucket=bucket, Key=key)
                body = gzip.decompress(response["Body"].read())
                data = json.loads(body.decode("utf-8"))

                for record in data.get("Records", []):
                    record["_source"] = "cloudtrail"
                    record["_source_key"] = key
                    yield record

    async def _collect_file(self, config: dict) -> AsyncIterator[dict]:
        """
        Collect logs from local files.
        Config: {path, format?}  format: json | text
        """
        file_path = Path(config["path"])
        fmt = config.get("format", "json")

        if file_path.is_dir():
            files = sorted(file_path.glob("**/*"))
        else:
            files = [file_path]

        for f in files:
            if not f.is_file():
                continue
            content = f.read_text(errors="replace")
            for line in content.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if fmt == "json":
                    try:
                        record = json.loads(line)
                        record["_source_file"] = str(f)
                        yield record
                    except json.JSONDecodeError:
                        yield {"raw": line, "_source_file": str(f)}
                else:
                    yield {"raw": line, "_source_file": str(f)}

    async def _collect_syslog(self, config: dict) -> AsyncIterator[dict]:
        """
        Collect syslog messages.
        Config: {host?, port?}
        Listens on UDP for syslog messages.
        """
        import asyncio

        host = config.get("host", "0.0.0.0")
        port = config.get("port", 514)

        class SyslogProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.messages: list[dict] = []

            def datagram_received(self, data, addr):
                msg = data.decode("utf-8", errors="replace").strip()
                self.messages.append({
                    "raw": msg,
                    "_source": "syslog",
                    "_source_addr": f"{addr[0]}:{addr[1]}",
                    "_received_at": datetime.utcnow().isoformat(),
                })

        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            SyslogProtocol, local_addr=(host, port)
        )

        # Collect for configured duration then yield
        await asyncio.sleep(config.get("collect_seconds", 10))
        transport.close()

        for msg in protocol.messages:
            yield msg

    async def _collect_webhook(self, config: dict) -> AsyncIterator[dict]:
        """
        Webhook collector is handled by the server.
        This returns any buffered webhook payloads.
        Config: {buffer: list[dict]}
        """
        for payload in config.get("buffer", []):
            payload["_source"] = "webhook"
            yield payload

    # ── Mock Data ────────────────────────────────────────────────

    async def collect_mock(self) -> AsyncIterator[dict[str, Any]]:
        """Return realistic mock log data for testing."""
        mock_logs = [
            {"eventTime": "2025-12-15T02:14:33Z", "eventName": "ConsoleLogin", "sourceIPAddress": "198.51.100.23", "userIdentity": {"type": "IAMUser", "userName": "admin@company.com", "arn": "arn:aws:iam::123456789012:user/admin"}, "responseElements": {"ConsoleLogin": "Success"}, "awsRegion": "us-east-1", "eventSource": "signin.amazonaws.com", "_source": "cloudtrail"},
            {"eventTime": "2025-12-15T02:14:35Z", "eventName": "ConsoleLogin", "sourceIPAddress": "203.0.113.45", "userIdentity": {"type": "IAMUser", "userName": "admin@company.com", "arn": "arn:aws:iam::123456789012:user/admin"}, "responseElements": {"ConsoleLogin": "Success"}, "awsRegion": "eu-west-1", "eventSource": "signin.amazonaws.com", "_source": "cloudtrail"},
            {"eventTime": "2025-12-15T02:15:01Z", "eventName": "GetObject", "sourceIPAddress": "203.0.113.45", "userIdentity": {"type": "IAMUser", "userName": "admin@company.com"}, "requestParameters": {"bucketName": "company-secrets", "key": "credentials/prod.env"}, "awsRegion": "us-east-1", "eventSource": "s3.amazonaws.com", "_source": "cloudtrail"},
            {"eventTime": "2025-12-15T02:15:30Z", "eventName": "AssumeRole", "sourceIPAddress": "203.0.113.45", "userIdentity": {"type": "IAMUser", "userName": "admin@company.com"}, "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/AdminAccess"}, "awsRegion": "us-east-1", "eventSource": "sts.amazonaws.com", "_source": "cloudtrail"},
            {"eventTime": "2025-12-15T02:16:00Z", "eventName": "CreateAccessKey", "sourceIPAddress": "203.0.113.45", "userIdentity": {"type": "AssumedRole", "userName": "admin@company.com"}, "requestParameters": {"userName": "backdoor-user"}, "awsRegion": "us-east-1", "eventSource": "iam.amazonaws.com", "_source": "cloudtrail"},
            {"raw": "Dec 15 02:14:33 web-prod-01 sshd[12345]: Failed password for root from 198.51.100.50 port 22 ssh2", "_source": "syslog"},
            {"raw": "Dec 15 02:14:34 web-prod-01 sshd[12345]: Failed password for root from 198.51.100.50 port 22 ssh2", "_source": "syslog"},
            {"raw": "Dec 15 02:14:35 web-prod-01 sshd[12345]: Accepted publickey for deploy from 10.0.1.5 port 22 ssh2", "_source": "syslog"},
            {"raw": "Dec 15 02:15:01 web-prod-01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.34 DST=10.0.1.10 PROTO=TCP DPT=3389", "_source": "syslog"},
        ]
        for log in mock_logs:
            yield log
