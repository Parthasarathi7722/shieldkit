"""
Prowler Scanner — Cloud security assessment for AWS, Azure, GCP.
Compliance frameworks: CIS, SOC2, PCI-DSS, HIPAA, GDPR, NIST-800-53.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

from ..models import CloudFinding, CloudProvider, CloudScanResult, Severity


MOCK_FINDINGS = {
    "aws": [
        {"service": "iam", "check": "iam_root_mfa_enabled", "title": "Root account MFA is not enabled", "severity": "critical", "status": "FAIL", "resource": "arn:aws:iam::123456789012:root", "region": "us-east-1", "remediation": "Enable MFA on root account: IAM → Security credentials → Assign MFA", "compliance": ["CIS-1.5", "SOC2-CC6.1", "PCI-DSS-8.3"]},
        {"service": "s3", "check": "s3_bucket_public_access", "title": "S3 bucket has public access enabled", "severity": "critical", "status": "FAIL", "resource": "arn:aws:s3:::company-data-prod", "region": "us-east-1", "remediation": "Enable S3 Block Public Access at account and bucket level", "compliance": ["CIS-2.1.5", "SOC2-CC6.1"]},
        {"service": "ec2", "check": "ec2_imdsv2_enforced", "title": "EC2 instance not using IMDSv2", "severity": "high", "status": "FAIL", "resource": "i-0abc123def456", "region": "us-east-1", "remediation": "Enforce IMDSv2: aws ec2 modify-instance-metadata-options --http-tokens required", "compliance": ["CIS-5.6"]},
        {"service": "cloudtrail", "check": "cloudtrail_multi_region", "title": "CloudTrail multi-region is enabled", "severity": "info", "status": "PASS", "resource": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main", "region": "us-east-1", "remediation": "", "compliance": ["CIS-3.1"]},
        {"service": "rds", "check": "rds_encryption_at_rest", "title": "RDS instance encryption at rest disabled", "severity": "high", "status": "FAIL", "resource": "arn:aws:rds:us-east-1:123456789012:db:prod-db", "region": "us-east-1", "remediation": "Enable encryption: create encrypted snapshot → restore from snapshot", "compliance": ["CIS-2.3.1", "PCI-DSS-3.4"]},
        {"service": "iam", "check": "iam_password_policy_min_length", "title": "IAM password policy requires minimum 14 characters", "severity": "info", "status": "PASS", "resource": "arn:aws:iam::123456789012:account", "region": "global", "remediation": "", "compliance": ["CIS-1.8"]},
    ],
    "azure": [
        {"service": "identity", "check": "aad_mfa_all_users", "title": "MFA not enforced for all Azure AD users", "severity": "critical", "status": "FAIL", "resource": "/subscriptions/sub-123/providers/Microsoft.AAD", "region": "global", "remediation": "Enable Security Defaults or Conditional Access MFA policy", "compliance": ["CIS-1.1.1"]},
        {"service": "storage", "check": "storage_soft_delete", "title": "Blob soft delete not enabled on storage account", "severity": "medium", "status": "FAIL", "resource": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/proddata", "region": "eastus", "remediation": "Enable soft delete in Storage Account → Data protection", "compliance": ["CIS-3.8"]},
        {"service": "network", "check": "nsg_unrestricted_ssh", "title": "NSG allows unrestricted SSH from internet", "severity": "high", "status": "FAIL", "resource": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web", "region": "eastus", "remediation": "Restrict SSH to known IP ranges or use Azure Bastion", "compliance": ["CIS-6.2"]},
    ],
    "gcp": [
        {"service": "iam", "check": "iam_service_account_keys", "title": "User-managed service account keys exist (prefer workload identity)", "severity": "high", "status": "FAIL", "resource": "projects/my-project/serviceAccounts/sa@my-project.iam.gserviceaccount.com", "region": "global", "remediation": "Delete user-managed keys, use workload identity federation instead", "compliance": ["CIS-1.4"]},
        {"service": "compute", "check": "compute_serial_port_disabled", "title": "Serial port access enabled on VM instance", "severity": "medium", "status": "FAIL", "resource": "projects/my-project/zones/us-central1-a/instances/prod-vm", "region": "us-central1", "remediation": "Disable serial port: gcloud compute instances add-metadata --metadata serial-port-enable=FALSE", "compliance": ["CIS-4.5"]},
        {"service": "storage", "check": "gcs_bucket_public", "title": "GCS bucket is publicly accessible", "severity": "critical", "status": "FAIL", "resource": "gs://company-backups", "region": "us", "remediation": "Remove allUsers/allAuthenticatedUsers from bucket IAM", "compliance": ["CIS-5.1"]},
    ],
}


class ProwlerScanner:
    """Prowler wrapper for multi-cloud security posture assessment."""

    def __init__(self, binary: str = "prowler"):
        self.binary = binary

    async def scan(
        self,
        provider: CloudProvider,
        services: list[str] | None = None,
        compliance: list[str] | None = None,
        regions: list[str] | None = None,
        mock: bool = False,
    ) -> CloudScanResult:
        result = CloudScanResult(
            provider=provider,
            tool="prowler",
            started_at=datetime.utcnow(),
        )

        try:
            if mock:
                return self._mock_scan(provider, result)

            cmd = [self.binary, provider.value, "--output-formats", "json", "--quiet"]
            if services:
                cmd.extend(["--services", ",".join(services)])
            if compliance:
                cmd.extend(["--compliance", ",".join(compliance)])
            if regions:
                cmd.extend(["--region", ",".join(regions)])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            findings = self._parse_prowler_json(stdout.decode())
            result.findings = findings
            result.summary = self._summarize(findings)
            result.status = "completed"

        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_prowler_json(self, raw: str) -> list[CloudFinding]:
        findings = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(CloudFinding(
                provider=CloudProvider(data.get("Provider", "aws").lower()),
                service=data.get("ServiceName", ""),
                region=data.get("Region", ""),
                resource_id=data.get("ResourceId", ""),
                resource_arn=data.get("ResourceArn", ""),
                check_id=data.get("CheckID", ""),
                check_title=data.get("CheckTitle", ""),
                severity=self._map_severity(data.get("Severity", "info")),
                status=data.get("Status", "FAIL"),
                description=data.get("StatusExtended", ""),
                remediation=data.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                compliance=[c.get("Framework", "") for c in data.get("Compliance", [])],
            ))
        return findings

    def _map_severity(self, sev: str) -> Severity:
        return {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW,
                "informational": Severity.INFO, "info": Severity.INFO,
                }.get(sev.lower(), Severity.UNKNOWN)

    def _summarize(self, findings: list[CloudFinding]) -> dict[str, int]:
        counts: dict[str, int] = {"pass": 0, "fail": 0}
        for f in findings:
            if f.status == "PASS":
                counts["pass"] += 1
            else:
                counts["fail"] += 1
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        counts["total"] = len(findings)
        return counts

    def _mock_scan(self, provider: CloudProvider, result: CloudScanResult) -> CloudScanResult:
        raw = MOCK_FINDINGS.get(provider.value, [])
        findings = [
            CloudFinding(
                provider=provider,
                service=f["service"],
                region=f["region"],
                resource_arn=f["resource"],
                check_id=f["check"],
                check_title=f["title"],
                severity=self._map_severity(f["severity"]),
                status=f["status"],
                description=f["title"],
                remediation=f["remediation"],
                compliance=f["compliance"],
            )
            for f in raw
        ]
        result.findings = findings
        result.summary = self._summarize(findings)
        result.status = "completed"
        result.completed_at = datetime.utcnow()
        return result
