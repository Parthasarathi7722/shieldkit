"""
Log Parser — Normalizes raw logs into structured NormalizedLog entries.
Handles: CloudTrail, VPC Flow Logs, syslog, generic JSON.
Uses pattern matching and field extraction for consistent schema.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..models import LogSourceType, NormalizedLog, Severity


class LogParser:
    """Parses and normalizes raw log entries from various sources."""

    SYSLOG_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)$"
    )

    UFW_PATTERN = re.compile(
        r"\[UFW\s+(?P<action>\w+)\]\s+.*SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)"
        r".*PROTO=(?P<proto>\S+).*DPT=(?P<dpt>\d+)"
    )

    SSH_AUTH_PATTERN = re.compile(
        r"(?P<result>Accepted|Failed)\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+"
        r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    )

    def parse(self, raw: dict[str, Any]) -> NormalizedLog:
        """Route to the appropriate parser based on source detection."""
        source = raw.get("_source", "")
        if source == "cloudtrail" or "eventName" in raw:
            return self._parse_cloudtrail(raw)
        elif source == "syslog" or ("raw" in raw and self._looks_like_syslog(raw.get("raw", ""))):
            return self._parse_syslog(raw)
        elif "vpc-flow" in source or self._looks_like_vpc_flow(raw):
            return self._parse_vpc_flow(raw)
        else:
            return self._parse_generic(raw)

    def _parse_cloudtrail(self, raw: dict) -> NormalizedLog:
        user_identity = raw.get("userIdentity", {})
        event_name = raw.get("eventName", "")

        actor = (
            user_identity.get("userName", "")
            or user_identity.get("principalId", "")
            or user_identity.get("arn", "")
        )

        severity = self._classify_cloudtrail_severity(event_name, raw)

        event_type = self._classify_cloudtrail_event(event_name)

        timestamp = self._parse_timestamp(raw.get("eventTime", ""))

        return NormalizedLog(
            timestamp=timestamp,
            source="cloudtrail",
            source_type=LogSourceType.CLOUDTRAIL,
            severity=severity,
            event_type=event_type,
            actor=actor,
            action=event_name,
            target_resource=self._extract_cloudtrail_resource(raw),
            source_ip=raw.get("sourceIPAddress", ""),
            region=raw.get("awsRegion", ""),
            account_id=user_identity.get("accountId", ""),
            raw=raw,
            tags=self._cloudtrail_tags(event_name, raw),
        )

    def _classify_cloudtrail_severity(self, event: str, raw: dict) -> Severity:
        critical_events = {
            "CreateAccessKey", "DeleteTrail", "StopLogging",
            "PutBucketPolicy", "DeactivateMFADevice", "CreateLoginProfile",
            "AttachUserPolicy", "AttachRolePolicy",
        }
        high_events = {
            "ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser",
            "PutBucketAcl", "AuthorizeSecurityGroupIngress",
            "RunInstances", "CreateRole",
        }
        if event in critical_events:
            return Severity.CRITICAL
        if event in high_events:
            return Severity.HIGH
        if raw.get("errorCode"):
            return Severity.MEDIUM
        return Severity.INFO

    def _classify_cloudtrail_event(self, event: str) -> str:
        if "Login" in event or "Auth" in event:
            return "authentication"
        if "Create" in event or "Put" in event or "Attach" in event:
            return "modification"
        if "Delete" in event or "Remove" in event or "Detach" in event:
            return "deletion"
        if "Get" in event or "List" in event or "Describe" in event:
            return "read"
        if "AssumeRole" in event:
            return "privilege_escalation"
        return "api_call"

    def _extract_cloudtrail_resource(self, raw: dict) -> str:
        params = raw.get("requestParameters", {})
        if isinstance(params, dict):
            for key in ["bucketName", "instanceId", "roleArn", "userName", "functionName", "tableName"]:
                if key in params:
                    val = params[key]
                    if key == "bucketName" and "key" in params:
                        return f"s3://{val}/{params['key']}"
                    return str(val)
        resources = raw.get("resources", [])
        if resources and isinstance(resources[0], dict):
            return resources[0].get("ARN", "")
        return ""

    def _cloudtrail_tags(self, event: str, raw: dict) -> list[str]:
        tags = []
        if raw.get("errorCode"):
            tags.append("error")
        if event in {"ConsoleLogin", "AssumeRole"}:
            tags.append("auth")
        if "Create" in event or "Delete" in event:
            tags.append("change")
        if event in {"CreateAccessKey", "AttachUserPolicy", "CreateLoginProfile"}:
            tags.append("persistence")
        if event == "AssumeRole":
            tags.append("privilege_escalation")
        return tags

    def _parse_syslog(self, raw: dict) -> NormalizedLog:
        message = raw.get("raw", "")
        match = self.SYSLOG_PATTERN.match(message)

        if not match:
            return self._parse_generic(raw)

        host = match.group("host")
        process = match.group("process")
        msg_body = match.group("message")

        # Try to parse time
        try:
            time_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
            ts = datetime.strptime(time_str, "%b %d %H:%M:%S").replace(year=datetime.utcnow().year)
        except ValueError:
            ts = datetime.utcnow()

        severity = Severity.INFO
        actor = ""
        action = process
        source_ip = ""
        target = ""
        tags = []
        event_type = "system"

        # SSH auth
        ssh_match = self.SSH_AUTH_PATTERN.search(msg_body)
        if ssh_match:
            event_type = "authentication"
            actor = ssh_match.group("user")
            source_ip = ssh_match.group("ip")
            if ssh_match.group("result") == "Failed":
                severity = Severity.MEDIUM
                tags.append("failed_auth")
            else:
                severity = Severity.INFO
                tags.append("successful_auth")

        # UFW
        ufw_match = self.UFW_PATTERN.search(msg_body)
        if ufw_match:
            event_type = "network"
            source_ip = ufw_match.group("src")
            target = f"{ufw_match.group('dst')}:{ufw_match.group('dpt')}"
            action = f"UFW_{ufw_match.group('action')}"
            severity = Severity.MEDIUM if ufw_match.group("action") == "BLOCK" else Severity.LOW
            tags.append("firewall")

        return NormalizedLog(
            timestamp=ts,
            source="syslog",
            source_type=LogSourceType.SYSLOG,
            severity=severity,
            event_type=event_type,
            actor=actor,
            action=action,
            target_resource=target,
            source_ip=source_ip,
            raw=raw,
            tags=tags,
        )

    def _parse_vpc_flow(self, raw: dict) -> NormalizedLog:
        return NormalizedLog(
            timestamp=datetime.utcnow(),
            source="vpc-flow",
            source_type=LogSourceType.S3,
            severity=Severity.INFO,
            event_type="network",
            source_ip=raw.get("srcaddr", ""),
            target_resource=f"{raw.get('dstaddr', '')}:{raw.get('dstport', '')}",
            action=raw.get("action", ""),
            raw=raw,
            tags=["network", "vpc"],
        )

    def _parse_generic(self, raw: dict) -> NormalizedLog:
        ts_str = raw.get("timestamp", raw.get("@timestamp", raw.get("time", "")))
        ts = self._parse_timestamp(ts_str) if ts_str else datetime.utcnow()

        return NormalizedLog(
            timestamp=ts,
            source=raw.get("_source", "unknown"),
            source_type=LogSourceType.FILE,
            severity=self._guess_severity(raw),
            event_type=raw.get("event_type", raw.get("type", "unknown")),
            actor=raw.get("user", raw.get("actor", "")),
            action=raw.get("action", raw.get("event", "")),
            source_ip=raw.get("source_ip", raw.get("ip", "")),
            raw=raw,
        )

    def _looks_like_syslog(self, text: str) -> bool:
        return bool(self.SYSLOG_PATTERN.match(text))

    def _looks_like_vpc_flow(self, raw: dict) -> bool:
        return "srcaddr" in raw and "dstaddr" in raw and "action" in raw

    def _parse_timestamp(self, ts: str) -> datetime:
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                     "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"]:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        return datetime.utcnow()

    def _guess_severity(self, raw: dict) -> Severity:
        text = str(raw).lower()
        if "critical" in text or "emergency" in text:
            return Severity.CRITICAL
        if "error" in text or "fail" in text:
            return Severity.HIGH
        if "warn" in text:
            return Severity.MEDIUM
        return Severity.INFO
