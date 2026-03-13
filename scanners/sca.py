"""
SCA Scanner — Software Composition Analysis using Grype.
Scans container images, directories, or SBOM files for known vulnerabilities.
"""

from __future__ import annotations

from ..models import ScanResult, ScanType, Severity, Vulnerability
from .base import BaseScanner


class SCAScanner(BaseScanner):
    scan_type = ScanType.SCA
    tool_name = "grype"
    binary = "grype"

    MOCK_VULNS = [
        {"id": "CVE-2024-50623", "severity": "critical", "package": "cleo-harmony", "installed": "5.7.0", "fixed": "5.8.0.21", "cvss": 9.8, "desc": "Unrestricted file upload/download in Cleo Harmony — actively exploited by Cl0p ransomware"},
        {"id": "CVE-2024-3094", "severity": "critical", "package": "xz-utils", "installed": "5.6.0", "fixed": "5.6.2", "cvss": 10.0, "desc": "Backdoor in xz/liblzma — supply chain compromise affecting sshd"},
        {"id": "CVE-2024-21626", "severity": "high", "package": "runc", "installed": "1.1.11", "fixed": "1.1.12", "cvss": 8.6, "desc": "Container escape via leaked file descriptor in runc"},
        {"id": "CVE-2023-44487", "severity": "high", "package": "golang.org/x/net", "installed": "0.16.0", "fixed": "0.17.0", "cvss": 7.5, "desc": "HTTP/2 Rapid Reset DDoS attack vector"},
        {"id": "CVE-2024-29944", "severity": "medium", "package": "express", "installed": "4.18.2", "fixed": "4.19.0", "cvss": 6.1, "desc": "Open redirect vulnerability in Express.js"},
        {"id": "CVE-2023-45853", "severity": "low", "package": "zlib", "installed": "1.3", "fixed": "1.3.1", "cvss": 3.7, "desc": "Integer overflow in minizip zipOpenNewFileInZip4_64"},
    ]

    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        mock = options.get("mock", False)
        severity_filter = options.get("severity", "")  # e.g. "critical,high"

        if mock:
            return self._mock_result(target, result, severity_filter)

        cmd = [self.binary, target, "-o", "json", "--quiet"]
        if severity_filter:
            cmd.extend(["--only-fixed", "--fail-on", severity_filter.split(",")[0]])

        stdout, stderr, rc = await self._run_cmd(cmd, timeout=180)
        result.raw_output = stdout
        parsed = self._parse_json(stdout)

        vulns = self._parse_vulns(parsed)
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        return result

    def _parse_vulns(self, data: dict) -> list[Vulnerability]:
        vulns = []
        for match in data.get("matches", []):
            vuln_data = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            vulns.append(Vulnerability(
                id=vuln_data.get("id", ""),
                severity=self._map_severity(vuln_data.get("severity", "Unknown")),
                package=artifact.get("name", ""),
                installed_version=artifact.get("version", ""),
                fixed_version=vuln_data.get("fix", {}).get("versions", [""])[0] if vuln_data.get("fix", {}).get("versions") else "",
                description=vuln_data.get("description", "")[:200],
                data_source=vuln_data.get("dataSource", ""),
                urls=vuln_data.get("urls", [])[:3],
                cvss_score=self._extract_cvss(vuln_data),
            ))
        return vulns

    def _extract_cvss(self, vuln: dict) -> float | None:
        for cvss in vuln.get("cvss", []):
            if "metrics" in cvss:
                return cvss["metrics"].get("baseScore")
        return None

    def _map_severity(self, sev: str) -> Severity:
        mapping = {
            "Critical": Severity.CRITICAL, "High": Severity.HIGH,
            "Medium": Severity.MEDIUM, "Low": Severity.LOW,
            "Negligible": Severity.INFO,
        }
        return mapping.get(sev, Severity.UNKNOWN)

    def _summarize(self, vulns: list[Vulnerability]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        counts["total"] = len(vulns)
        return counts

    def _mock_result(self, target: str, result: ScanResult, severity_filter: str) -> ScanResult:
        vulns = [
            Vulnerability(
                id=v["id"], severity=Severity(v["severity"]), package=v["package"],
                installed_version=v["installed"], fixed_version=v["fixed"],
                description=v["desc"], cvss_score=v["cvss"],
            )
            for v in self.MOCK_VULNS
        ]
        if severity_filter:
            allowed = set(severity_filter.split(","))
            vulns = [v for v in vulns if v.severity.value in allowed]

        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        result.status = "completed"
        return result
