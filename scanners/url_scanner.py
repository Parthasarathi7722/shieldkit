"""
URL / Endpoint Scanner — Vulnerability scanning using Nuclei.
Scans URLs and endpoints against community + custom templates.
"""

from __future__ import annotations

from ..models import ScanResult, ScanType, Severity, Vulnerability
from .base import BaseScanner


class URLScanner(BaseScanner):
    scan_type = ScanType.URL
    tool_name = "nuclei"
    binary = "nuclei"

    MOCK_FINDINGS = [
        {"id": "CVE-2024-50623", "severity": "critical", "template": "cleo-harmony-rce", "matched": "/api/upload", "desc": "Unrestricted file upload leading to RCE — Cleo Harmony"},
        {"id": "ssl-expired-cert", "severity": "high", "template": "ssl-expired", "matched": "https://target:443", "desc": "SSL certificate expired — enables MitM attacks"},
        {"id": "exposed-env", "severity": "high", "template": "exposed-dotenv", "matched": "/.env", "desc": "Exposed .env file containing environment variables and secrets"},
        {"id": "open-redirect", "severity": "medium", "template": "open-redirect-detect", "matched": "/auth/callback?redirect=", "desc": "Open redirect vulnerability in authentication callback"},
        {"id": "x-frame-options-missing", "severity": "low", "template": "missing-x-frame", "matched": "/", "desc": "Missing X-Frame-Options header — clickjacking risk"},
        {"id": "server-header-disclosure", "severity": "info", "template": "tech-detect", "matched": "/", "desc": "Server header reveals nginx/1.24.0"},
    ]

    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        mock = options.get("mock", False)
        templates = options.get("templates", "")  # custom template path
        severity = options.get("severity", "")

        if mock:
            return self._mock_result(target, result)

        cmd = [self.binary, "-u", target, "-jsonl", "-silent"]
        if templates:
            cmd.extend(["-t", templates])
        if severity:
            cmd.extend(["-severity", severity])

        stdout, stderr, rc = await self._run_cmd(cmd, timeout=600)
        result.raw_output = stdout

        vulns = self._parse_nuclei_output(stdout)
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        return result

    def _parse_nuclei_output(self, raw: str) -> list[Vulnerability]:
        vulns = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            data = self._parse_json(line)
            if not data:
                continue
            info = data.get("info", {})
            vulns.append(Vulnerability(
                id=data.get("template-id", data.get("matcher-name", "")),
                severity=self._map_severity(info.get("severity", "info")),
                package=data.get("matched-at", ""),
                description=info.get("description", info.get("name", ""))[:200],
                urls=[data.get("matched-at", "")],
            ))
        return vulns

    def _map_severity(self, sev: str) -> Severity:
        return {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW,
                "info": Severity.INFO}.get(sev.lower(), Severity.UNKNOWN)

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
                package=f["matched"], description=f["desc"],
            )
            for f in self.MOCK_FINDINGS
        ]
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        result.status = "completed"
        return result
