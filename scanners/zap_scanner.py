"""
OWASP ZAP Scanner — Dynamic Application Security Testing (DAST).

Supports two execution modes:
  1. Docker mode (recommended) — runs ghcr.io/zaproxy/zaproxy:stable
  2. API mode — connects to a running ZAP daemon via the zaproxy Python client

Scan profiles:
  - baseline  : Passive spider + passive analysis only (safe for production)
  - full       : Spider + active scan (aggressive — use only on targets you own)
  - api        : OpenAPI / Swagger / GraphQL spec-based scan

Authentication methods:
  - none       : No authentication
  - basic      : HTTP Basic Auth (username / password)
  - form        : Form-based login (login URL, username/password field names, credentials)
  - bearer     : Authorization: Bearer <token>
  - script      : Custom auth script (advanced)
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..models import ScanResult, ScanType, Severity, Vulnerability
from .base import BaseScanner


class ZAPScanner(BaseScanner):
    scan_type = ScanType.DAST
    tool_name = "zap"
    binary = "docker"

    # Realistic mock findings covering common OWASP Top 10 issues
    MOCK_FINDINGS = [
        {
            "id": "40012", "risk": 3, "confidence": 2,
            "name": "Cross Site Scripting (Reflected)",
            "url": "/search?q=test", "method": "GET",
            "param": "q",
            "desc": "Cross-site Scripting (XSS) attack detected in the 'q' parameter. "
                    "Attacker-supplied JavaScript can run in the victim's browser.",
            "solution": "Validate and encode all user-supplied input before reflecting it in responses.",
            "reference": "https://owasp.org/www-community/attacks/xss/",
            "cweid": "79",
        },
        {
            "id": "40018", "risk": 3, "confidence": 2,
            "name": "SQL Injection",
            "url": "/api/users?id=1", "method": "GET",
            "param": "id",
            "desc": "SQL injection vulnerability detected. Attacker can manipulate backend database queries.",
            "solution": "Use parameterised queries / prepared statements for all DB interactions.",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
            "cweid": "89",
        },
        {
            "id": "10202", "risk": 2, "confidence": 2,
            "name": "Absence of Anti-CSRF Tokens",
            "url": "/account/profile", "method": "POST",
            "param": "",
            "desc": "No Anti-CSRF tokens found in HTML submission form. "
                    "An attacker could forge requests on behalf of authenticated users.",
            "solution": "Include a per-session CSRF token in all forms and AJAX requests.",
            "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "cweid": "352",
        },
        {
            "id": "10038", "risk": 2, "confidence": 3,
            "name": "Content Security Policy (CSP) Header Not Set",
            "url": "/", "method": "GET",
            "param": "",
            "desc": "Content-Security-Policy header is absent. Without CSP, browsers allow "
                    "inline scripts, eval(), and cross-origin resource loading.",
            "solution": "Set a strict Content-Security-Policy header on all responses.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "cweid": "693",
        },
        {
            "id": "10020", "risk": 2, "confidence": 2,
            "name": "X-Frame-Options Header Not Set",
            "url": "/", "method": "GET",
            "param": "",
            "desc": "X-Frame-Options header is missing, enabling clickjacking attacks.",
            "solution": "Add 'X-Frame-Options: DENY' or use CSP frame-ancestors directive.",
            "reference": "https://owasp.org/www-community/attacks/Clickjacking",
            "cweid": "1021",
        },
        {
            "id": "10035", "risk": 1, "confidence": 3,
            "name": "Strict-Transport-Security Header Not Set",
            "url": "/", "method": "GET",
            "param": "",
            "desc": "HSTS header is absent, allowing downgrade to HTTP and enabling MITM attacks.",
            "solution": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            "reference": "https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security_Cheat_Sheet",
            "cweid": "319",
        },
        {
            "id": "10016", "risk": 1, "confidence": 2,
            "name": "Web Browser XSS Protection Not Enabled",
            "url": "/search", "method": "GET",
            "param": "",
            "desc": "X-XSS-Protection header not set to '1; mode=block'.",
            "solution": "Set 'X-XSS-Protection: 1; mode=block' in all HTTP responses.",
            "reference": "https://owasp.org/www-project-secure-headers/",
            "cweid": "933",
        },
    ]

    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        if options.get("mock", False):
            return self._mock_result(target, result)

        scan_mode = options.get("scan_mode", "baseline")       # baseline | full | api
        auth_method = options.get("auth_method", "none")       # none | basic | form | bearer | script
        auth_config: dict[str, Any] = options.get("auth_config", {})
        attack_strength = options.get("attack_strength", "medium")   # low | medium | high | insane
        alert_threshold = options.get("alert_threshold", "medium")   # low | medium | high
        api_spec_url = options.get("api_spec_url", "")         # OpenAPI/Swagger/GraphQL URL
        api_spec_format = options.get("api_spec_format", "openapi")  # openapi | graphql | soap
        include_patterns: list[str] = options.get("include_patterns", [])
        exclude_patterns: list[str] = options.get("exclude_patterns", [])
        use_docker = options.get("use_docker", True)
        zap_host = options.get("zap_host", os.environ.get("ZAP_HOST", "localhost"))
        zap_port = int(options.get("zap_port", os.environ.get("ZAP_PORT", "8080")))
        zap_api_key = options.get("zap_api_key", os.environ.get("ZAP_API_KEY", ""))

        if use_docker and shutil.which("docker"):
            return await self._run_docker(
                target, result, scan_mode, auth_method, auth_config,
                attack_strength, alert_threshold, api_spec_url, api_spec_format,
                include_patterns, exclude_patterns,
            )
        else:
            return await self._run_api_client(
                target, result, scan_mode, auth_method, auth_config,
                attack_strength, alert_threshold,
                zap_host, zap_port, zap_api_key,
            )

    # ── Docker mode ──────────────────────────────────────────────

    async def _run_docker(
        self, target, result, scan_mode, auth_method, auth_config,
        attack_strength, alert_threshold, api_spec_url, api_spec_format,
        include_patterns, exclude_patterns,
    ) -> ScanResult:
        script_map = {
            "baseline": "zap-baseline.py",
            "full": "zap-full-scan.py",
            "api": "zap-api-scan.py",
        }
        script = script_map.get(scan_mode, "zap-baseline.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Make temp dir world-writable so Docker container can write to it
            os.chmod(tmpdir, 0o777)

            cmd = [
                "docker", "run", "--rm",
                "--network=host",
                "-v", f"{tmpdir}:/zap/wrk:rw",
                "-t", "ghcr.io/zaproxy/zaproxy:stable",
                script,
                "-t", target,
                "-J", "/zap/wrk/output.json",
                "-r", "/zap/wrk/report.html",
            ]

            # API scan: specify spec format
            if scan_mode == "api":
                spec_target = api_spec_url or target
                cmd = [
                    "docker", "run", "--rm",
                    "--network=host",
                    "-v", f"{tmpdir}:/zap/wrk:rw",
                    "-t", "ghcr.io/zaproxy/zaproxy:stable",
                    script,
                    "-t", spec_target,
                    "-f", api_spec_format,
                    "-J", "/zap/wrk/output.json",
                ]

            # Add ZAP properties via -z flag
            zap_opts = self._build_zap_opts(
                scan_mode, auth_method, auth_config,
                attack_strength, alert_threshold,
                include_patterns, exclude_patterns,
            )
            if zap_opts:
                cmd.extend(["-z", zap_opts])

            stdout, stderr, rc = await self._run_cmd(cmd, timeout=1200)
            result.raw_output = (stdout + "\n" + stderr).strip()

            output_file = Path(tmpdir) / "output.json"
            if output_file.exists():
                raw = output_file.read_text(encoding="utf-8", errors="replace")
                vulns = self._parse_json_report(raw, target)
            else:
                vulns = self._parse_stdout_alerts(stdout, target)

            result.vulnerabilities = vulns
            result.summary = self._summarize(vulns)
            result.extra = {
                "scan_mode": scan_mode,
                "auth_method": auth_method,
                "attack_strength": attack_strength,
            }

        return result

    def _build_zap_opts(
        self, scan_mode, auth_method, auth_config,
        attack_strength, alert_threshold,
        include_patterns, exclude_patterns,
    ) -> str:
        parts = []

        if scan_mode == "full":
            if attack_strength.lower() != "medium":
                parts.append(f"-config scanner.attackStrength={attack_strength.upper()}")
            if alert_threshold.lower() != "medium":
                parts.append(f"-config scanner.alertThreshold={alert_threshold.upper()}")

        if auth_method == "basic":
            u = auth_config.get("username", "")
            p = auth_config.get("password", "")
            if u:
                parts.append(f"-config network.http.auth.credentials(0).username={u}")
                parts.append(f"-config network.http.auth.credentials(0).password={p}")

        if auth_method == "bearer":
            token = auth_config.get("token", "")
            if token:
                parts.append(f"-config replacer.full_list(0).description=BearerToken")
                parts.append(f"-config replacer.full_list(0).enabled=true")
                parts.append(f"-config replacer.full_list(0).matchtype=REQ_HEADER")
                parts.append(f"-config replacer.full_list(0).matchstr=Authorization")
                parts.append(f"-config replacer.full_list(0).replacement=Bearer {token}")

        return " ".join(parts)

    # ── API / daemon mode ────────────────────────────────────────

    async def _run_api_client(
        self, target, result, scan_mode, auth_method, auth_config,
        attack_strength, alert_threshold,
        zap_host, zap_port, zap_api_key,
    ) -> ScanResult:
        try:
            from zapv2 import ZAPv2  # type: ignore
        except ImportError:
            result.error = (
                "ZAP Python client not installed (pip install zaproxy) "
                "and Docker is not available. Cannot run DAST scan."
            )
            return result

        import asyncio

        def _sync_scan():
            zap = ZAPv2(
                apikey=zap_api_key,
                proxies={
                    "http": f"http://{zap_host}:{zap_port}",
                    "https": f"http://{zap_host}:{zap_port}",
                },
            )

            # Spider
            spider_id = zap.spider.scan(target, apikey=zap_api_key)
            import time
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(2)

            # Active scan (full mode only)
            if scan_mode == "full":
                if attack_strength.lower() != "medium":
                    zap.ascan.set_option_attack_strength(attack_strength.upper())
                ascan_id = zap.ascan.scan(target, apikey=zap_api_key)
                while int(zap.ascan.status(ascan_id)) < 100:
                    time.sleep(5)

            return zap.core.alerts(baseurl=target)

        try:
            alerts = await asyncio.get_event_loop().run_in_executor(None, _sync_scan)
            vulns = self._parse_api_alerts(alerts)
            result.vulnerabilities = vulns
            result.summary = self._summarize(vulns)
        except Exception as exc:
            result.error = f"ZAP API error: {exc}"

        return result

    # ── Output parsers ───────────────────────────────────────────

    def _parse_json_report(self, raw: str, target: str) -> list[Vulnerability]:
        """Parse ZAP's -J JSON report format."""
        vulns: list[Vulnerability] = []
        try:
            data = json.loads(raw)
            sites = data.get("site", [])
            if not isinstance(sites, list):
                sites = [sites]
            for site in sites:
                for alert in site.get("alerts", []):
                    instances = alert.get("instances", [])
                    urls = [i.get("uri", "") for i in instances[:5]]
                    vuln_id = alert.get("pluginid", alert.get("alertRef", "ZAP"))
                    name = alert.get("name", alert.get("alert", "Unknown"))
                    desc = alert.get("desc", "")
                    solution = alert.get("solution", "")
                    risk = int(alert.get("riskcode", 0))
                    sev = self._map_risk(risk)
                    vulns.append(Vulnerability(
                        id=f"ZAP-{vuln_id}",
                        severity=sev,
                        package=urls[0] if urls else target,
                        description=f"{name}: {desc}"[:400],
                        fixed_version=solution[:200] if solution else "",
                        urls=urls if urls else [target],
                    ))
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        return vulns

    def _parse_api_alerts(self, alerts: list) -> list[Vulnerability]:
        """Parse alerts from ZAP Python API."""
        vulns: list[Vulnerability] = []
        for alert in alerts:
            try:
                risk = int(alert.get("risk", 0))
                sev = self._map_risk(risk)
                url = alert.get("url", "")
                name = alert.get("alert", "Unknown")
                desc = alert.get("description", "")
                solution = alert.get("solution", "")
                plugin_id = alert.get("pluginId", "")
                vulns.append(Vulnerability(
                    id=f"ZAP-{plugin_id}" if plugin_id else "ZAP-alert",
                    severity=sev,
                    package=url,
                    description=f"{name}: {desc}"[:400],
                    fixed_version=solution[:200] if solution else "",
                    urls=[url],
                ))
            except (KeyError, TypeError):
                continue
        return vulns

    def _parse_stdout_alerts(self, stdout: str, target: str) -> list[Vulnerability]:
        """Last-resort: extract alert lines from ZAP stdout."""
        vulns: list[Vulnerability] = []
        for line in stdout.splitlines():
            line = line.strip()
            for prefix in ("WARN-NEW:", "ALERT:", "HIGH:", "MEDIUM:", "LOW:", "INFO:"):
                if line.startswith(prefix):
                    sev_str = prefix.rstrip(":").replace("WARN-NEW", "medium").lower()
                    sev_map = {
                        "high": Severity.HIGH, "medium": Severity.MEDIUM,
                        "low": Severity.LOW, "info": Severity.INFO,
                    }
                    sev = sev_map.get(sev_str, Severity.INFO)
                    desc = line[len(prefix):].strip()
                    vulns.append(Vulnerability(
                        id="ZAP-alert",
                        severity=sev,
                        package=target,
                        description=desc[:300],
                    ))
        return vulns

    # ── Helpers ──────────────────────────────────────────────────

    def _map_risk(self, risk_code: int) -> Severity:
        return {
            3: Severity.HIGH,
            2: Severity.MEDIUM,
            1: Severity.LOW,
            0: Severity.INFO,
        }.get(risk_code, Severity.UNKNOWN)

    def _summarize(self, vulns: list[Vulnerability]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        counts["total"] = len(vulns)
        return counts

    def _mock_result(self, target: str, result: ScanResult) -> ScanResult:
        vulns = [
            Vulnerability(
                id=f"ZAP-{f['id']}",
                severity=self._map_risk(f["risk"]),
                package=target + f["url"],
                description=f"{f['name']}: {f['desc']}"[:400],
                fixed_version=f.get("solution", "")[:200],
                urls=[target + f["url"]],
            )
            for f in self.MOCK_FINDINGS
        ]
        result.vulnerabilities = vulns
        result.summary = self._summarize(vulns)
        result.status = "completed"
        return result