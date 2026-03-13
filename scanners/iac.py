"""
IaC Scanner — Static analysis for Infrastructure as Code using Checkov.
Supports Terraform, CloudFormation, Kubernetes, Dockerfiles, Helm, ARM, Bicep.
"""

from __future__ import annotations

from ..models import ScanResult, ScanType, Severity, Vulnerability
from .base import BaseScanner


class IaCScanner(BaseScanner):
    scan_type = ScanType.IAC
    tool_name = "checkov"
    binary = "checkov"

    MOCK_FINDINGS = [
        {"id": "CKV_AWS_18", "severity": "high", "resource": "aws_s3_bucket.data", "file": "main.tf:12", "desc": "S3 bucket access logging is not enabled"},
        {"id": "CKV_AWS_145", "severity": "high", "resource": "aws_s3_bucket.data", "file": "main.tf:12", "desc": "S3 bucket not encrypted with KMS CMK"},
        {"id": "CKV_AWS_23", "severity": "high", "resource": "aws_security_group.web", "file": "network.tf:5", "desc": "Security group allows ingress from 0.0.0.0/0 to port 22"},
        {"id": "CKV_AWS_79", "severity": "medium", "resource": "aws_instance.app", "file": "compute.tf:1", "desc": "IMDSv2 is not enforced on EC2 instance"},
        {"id": "CKV_DOCKER_2", "severity": "medium", "resource": "Dockerfile", "file": "Dockerfile:1", "desc": "Dockerfile HEALTHCHECK instruction is missing"},
        {"id": "CKV_K8S_43", "severity": "medium", "resource": "Deployment.app", "file": "k8s/deployment.yaml:1", "desc": "Container image tag is not fixed (uses :latest)"},
        {"id": "CKV_AWS_144", "severity": "low", "resource": "aws_s3_bucket.logs", "file": "storage.tf:20", "desc": "S3 bucket cross-region replication not enabled"},
    ]

    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        mock = options.get("mock", False)
        framework = options.get("framework", "")  # terraform, cloudformation, kubernetes, dockerfile

        if mock:
            return self._mock_result(target, result)

        cmd = [self.binary, "-d", target, "-o", "json", "--quiet", "--compact"]
        if framework:
            cmd.extend(["--framework", framework])

        stdout, stderr, rc = await self._run_cmd(cmd, timeout=300)
        result.raw_output = stdout
        parsed = self._parse_json(stdout)

        vulns = self._parse_checkov(parsed)
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        return result

    def _parse_checkov(self, data: dict | list) -> list[Vulnerability]:
        vulns = []
        results_list = data if isinstance(data, list) else [data]
        for block in results_list:
            for check in block.get("results", {}).get("failed_checks", []):
                vulns.append(Vulnerability(
                    id=check.get("check_id", ""),
                    severity=self._map_severity(check.get("severity", "MEDIUM")),
                    package=check.get("resource", ""),
                    description=check.get("check_result", {}).get("evaluated_keys", [check.get("name", "")])
                    if isinstance(check.get("check_result"), dict) else check.get("name", ""),
                    installed_version=f"{check.get('repo_file_path', '')}:{check.get('file_line_range', [''])[0]}",
                    urls=[check.get("guideline", "")] if check.get("guideline") else [],
                ))
        return vulns

    def _map_severity(self, sev: str) -> Severity:
        return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
                "INFO": Severity.INFO}.get(sev.upper(), Severity.MEDIUM)

    def _summarize(self, vulns: list[Vulnerability]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        counts["total"] = len(vulns)
        return counts

    def _mock_result(self, target: str, result: ScanResult) -> ScanResult:
        vulns = [
            Vulnerability(
                id=f["id"], severity=Severity(f["severity"]),
                package=f["resource"], installed_version=f["file"],
                description=f["desc"],
            )
            for f in self.MOCK_FINDINGS
        ]
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        result.status = "completed"
        return result
