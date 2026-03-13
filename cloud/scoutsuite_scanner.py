"""
ScoutSuite Scanner — Multi-cloud security auditing (AWS, Azure, GCP).
Generates HTML reports and JSON findings for cross-cloud posture comparison.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import CloudFinding, CloudProvider, CloudScanResult, Severity


class ScoutSuiteScanner:
    """ScoutSuite wrapper for multi-cloud security auditing."""

    def __init__(self, binary: str = "scout"):
        self.binary = binary

    async def scan(
        self,
        provider: CloudProvider,
        services: list[str] | None = None,
        mock: bool = False,
    ) -> CloudScanResult:
        result = CloudScanResult(
            provider=provider,
            tool="scoutsuite",
            started_at=datetime.utcnow(),
        )

        try:
            if mock:
                return self._mock_scan(provider, result)

            cmd = [self.binary, provider.value, "--no-browser", "--result-format", "json"]
            if services:
                cmd.extend(["--services", *services])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            # ScoutSuite writes results to scoutsuite-results/scoutsuite_results_*.json
            findings = self._parse_results_dir()
            result.findings = findings
            result.summary = self._summarize(findings)
            result.status = "completed"

        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_results_dir(self) -> list[CloudFinding]:
        """Parse ScoutSuite's output directory for findings."""
        findings = []
        results_dir = Path("scoutsuite-results")
        if not results_dir.exists():
            return findings

        for json_file in results_dir.glob("scoutsuite_results_*.json"):
            try:
                data = json.loads(json_file.read_text())
                findings.extend(self._extract_findings(data))
            except (json.JSONDecodeError, KeyError):
                continue
        return findings

    def _extract_findings(self, data: dict) -> list[CloudFinding]:
        findings = []
        provider = data.get("provider_code", "aws").lower()
        services = data.get("services", {})

        for svc_name, svc_data in services.items():
            for rule_name, rule in svc_data.get("findings", {}).items():
                if rule.get("flagged_items", 0) == 0:
                    continue
                for item in rule.get("items", []):
                    findings.append(CloudFinding(
                        provider=CloudProvider(provider),
                        service=svc_name,
                        check_id=rule_name,
                        check_title=rule.get("description", rule_name),
                        severity=self._map_severity(rule.get("level", "warning")),
                        status="FAIL",
                        resource_id=item,
                        description=rule.get("rationale", ""),
                        remediation=rule.get("remediation", ""),
                        compliance=rule.get("compliance", []),
                    ))
        return findings

    def _map_severity(self, level: str) -> Severity:
        return {"danger": Severity.CRITICAL, "warning": Severity.HIGH,
                "info": Severity.INFO}.get(level.lower(), Severity.MEDIUM)

    def _summarize(self, findings: list[CloudFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        counts["total"] = len(findings)
        return counts

    def _mock_scan(self, provider: CloudProvider, result: CloudScanResult) -> CloudScanResult:
        # Reuse prowler mock data structure for consistency
        from .prowler_scanner import MOCK_FINDINGS
        raw = MOCK_FINDINGS.get(provider.value, [])
        findings = [
            CloudFinding(
                provider=provider, service=f["service"], region=f["region"],
                resource_arn=f["resource"], check_id=f["check"],
                check_title=f["title"],
                severity=Severity(f["severity"]) if f["severity"] in [e.value for e in Severity] else Severity.MEDIUM,
                status=f["status"], description=f["title"],
                remediation=f["remediation"], compliance=f["compliance"],
            )
            for f in raw if f["status"] == "FAIL"
        ]
        result.findings = findings
        result.summary = self._summarize(findings)
        result.status = "completed"
        result.completed_at = datetime.utcnow()
        return result
