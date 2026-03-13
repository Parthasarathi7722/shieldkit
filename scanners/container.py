"""
Container Scanner — Image and filesystem scanning using Trivy.
Covers OS packages, language-specific dependencies, secrets, and misconfigurations.
"""

from __future__ import annotations

from ..models import ScanResult, ScanType, Severity, Vulnerability
from .base import BaseScanner


class ContainerScanner(BaseScanner):
    scan_type = ScanType.CONTAINER
    tool_name = "trivy"
    binary = "trivy"

    MOCK_VULNS = [
        {"id": "CVE-2024-21626", "severity": "critical", "pkg": "runc", "installed": "1.1.11", "fixed": "1.1.12", "cvss": 8.6, "desc": "Container breakout via leaked file descriptor — runc WORKDIR flaw"},
        {"id": "CVE-2024-32002", "severity": "critical", "pkg": "git", "installed": "2.43.0", "fixed": "2.43.5", "cvss": 9.0, "desc": "Git clone RCE via symlink handling on case-insensitive filesystems"},
        {"id": "CVE-2024-3094", "severity": "critical", "pkg": "xz-utils", "installed": "5.6.0", "fixed": "5.6.2", "cvss": 10.0, "desc": "xz/liblzma backdoor — supply chain compromise affecting OpenSSH"},
        {"id": "CVE-2023-44487", "severity": "high", "pkg": "nghttp2", "installed": "1.57.0", "fixed": "1.58.0", "cvss": 7.5, "desc": "HTTP/2 Rapid Reset attack — protocol-level DDoS"},
        {"id": "CVE-2024-0567", "severity": "medium", "pkg": "gnutls", "installed": "3.8.2", "fixed": "3.8.3", "cvss": 5.9, "desc": "Cocoa certificate verification bypass via crafted timestamps"},
        {"id": "CVE-2023-50387", "severity": "medium", "pkg": "systemd", "installed": "254", "fixed": "255", "cvss": 5.3, "desc": "KeyTrap — DNSSEC validation CPU exhaustion"},
    ]

    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        mock = options.get("mock", False)
        scan_mode = options.get("mode", "image")  # image | fs | config | repo

        if mock:
            return self._mock_result(target, result)

        cmd = [self.binary, scan_mode, target, "--format", "json", "--quiet"]

        severity = options.get("severity", "")
        if severity:
            cmd.extend(["--severity", severity.upper()])

        ignore_unfixed = options.get("ignore_unfixed", True)
        if ignore_unfixed:
            cmd.append("--ignore-unfixed")

        stdout, stderr, rc = await self._run_cmd(cmd, timeout=300)
        result.raw_output = stdout
        parsed = self._parse_json(stdout)

        vulns = self._parse_vulns(parsed)
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        return result

    def _parse_vulns(self, data: dict) -> list[Vulnerability]:
        vulns = []
        for target_result in data.get("Results", []):
            for v in target_result.get("Vulnerabilities", []):
                vulns.append(Vulnerability(
                    id=v.get("VulnerabilityID", ""),
                    severity=self._map_severity(v.get("Severity", "UNKNOWN")),
                    package=v.get("PkgName", ""),
                    installed_version=v.get("InstalledVersion", ""),
                    fixed_version=v.get("FixedVersion", ""),
                    description=v.get("Description", "")[:200],
                    data_source=v.get("DataSource", {}).get("Name", "") if isinstance(v.get("DataSource"), dict) else "",
                    urls=([v["PrimaryURL"]] if v.get("PrimaryURL") else [])[:3],
                    cvss_score=self._extract_cvss(v),
                ))
        return vulns

    def _extract_cvss(self, v: dict) -> float | None:
        cvss = v.get("CVSS", {})
        for source in cvss.values():
            if isinstance(source, dict) and "V3Score" in source:
                return source["V3Score"]
        return None

    def _map_severity(self, sev: str) -> Severity:
        return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
                "UNKNOWN": Severity.UNKNOWN}.get(sev.upper(), Severity.UNKNOWN)

    def _summarize(self, vulns: list[Vulnerability]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        counts["total"] = len(vulns)
        return counts

    def _mock_result(self, target: str, result: ScanResult) -> ScanResult:
        vulns = [
            Vulnerability(
                id=v["id"], severity=Severity(v["severity"]), package=v["pkg"],
                installed_version=v["installed"], fixed_version=v["fixed"],
                description=v["desc"], cvss_score=v["cvss"],
            )
            for v in self.MOCK_VULNS
        ]
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        result.status = "completed"
        return result
