"""
SBOM Scanner — Generates Software Bill of Materials using Syft.
Supports container images, directories, and archives.
Output: CycloneDX JSON or SPDX JSON.
"""

from __future__ import annotations

from ..models import SBOMComponent, SBOMReport, ScanResult, ScanType, Severity
from .base import BaseScanner


class SBOMScanner(BaseScanner):
    scan_type = ScanType.SBOM
    tool_name = "syft"
    binary = "syft"

    MOCK_SBOM = {
        "components": [
            {"name": "express", "version": "4.18.2", "type": "library", "purl": "pkg:npm/express@4.18.2", "licenses": ["MIT"]},
            {"name": "lodash", "version": "4.17.21", "type": "library", "purl": "pkg:npm/lodash@4.17.21", "licenses": ["MIT"]},
            {"name": "axios", "version": "1.6.5", "type": "library", "purl": "pkg:npm/axios@1.6.5", "licenses": ["MIT"]},
            {"name": "jsonwebtoken", "version": "9.0.2", "type": "library", "purl": "pkg:npm/jsonwebtoken@9.0.2", "licenses": ["MIT"]},
            {"name": "pg", "version": "8.11.3", "type": "library", "purl": "pkg:npm/pg@8.11.3", "licenses": ["MIT"]},
            {"name": "bcrypt", "version": "5.1.1", "type": "library", "purl": "pkg:npm/bcrypt@5.1.1", "licenses": ["MIT"]},
            {"name": "helmet", "version": "7.1.0", "type": "library", "purl": "pkg:npm/helmet@7.1.0", "licenses": ["MIT"]},
            {"name": "cors", "version": "2.8.5", "type": "library", "purl": "pkg:npm/cors@2.8.5", "licenses": ["MIT"]},
            {"name": "dotenv", "version": "16.3.1", "type": "library", "purl": "pkg:npm/dotenv@16.3.1", "licenses": ["BSD-2-Clause"]},
            {"name": "winston", "version": "3.11.0", "type": "library", "purl": "pkg:npm/winston@3.11.0", "licenses": ["MIT"]},
        ]
    }

    async def _execute(self, target: str, result: ScanResult, **options) -> ScanResult:
        fmt = options.get("format", "cyclonedx-json")
        mock = options.get("mock", False)

        if mock:
            return self._mock_result(target, result, fmt)

        cmd = [self.binary, target, "-o", fmt, "--quiet"]
        stdout, stderr, rc = await self._run_cmd(cmd, timeout=120)

        if rc != 0:
            result.error = stderr
            result.status = "failed"
            return result

        result.raw_output = stdout
        parsed = self._parse_json(stdout)
        sbom_report = self._parse_sbom(target, parsed, fmt)
        result.sbom = sbom_report
        result.summary = {"components": sbom_report.component_count}
        return result

    def _parse_sbom(self, target: str, data: dict, fmt: str) -> SBOMReport:
        components = []
        raw_components = []

        if "components" in data:  # CycloneDX
            raw_components = data["components"]
        elif "packages" in data:  # SPDX
            raw_components = data["packages"]

        for comp in raw_components:
            components.append(SBOMComponent(
                name=comp.get("name", comp.get("SPDXID", "unknown")),
                version=comp.get("version", comp.get("versionInfo", "")),
                type=comp.get("type", "library"),
                purl=comp.get("purl", comp.get("externalRefs", [{}])[0].get("referenceLocator", "") if comp.get("externalRefs") else ""),
                licenses=[
                    lic.get("license", {}).get("id", lic.get("license", {}).get("name", ""))
                    for lic in comp.get("licenses", [])
                    if isinstance(lic, dict)
                ] or [],
                supplier=comp.get("supplier", {}).get("name", "") if isinstance(comp.get("supplier"), dict) else "",
            ))

        return SBOMReport(
            target=target,
            format=fmt.split("-")[0],
            tool="syft",
            component_count=len(components),
            components=components,
        )

    def _mock_result(self, target: str, result: ScanResult, fmt: str) -> ScanResult:
        components = [SBOMComponent(**c) for c in self.MOCK_SBOM["components"]]
        result.sbom = SBOMReport(
            target=target,
            format=fmt.split("-")[0],
            tool="syft",
            component_count=len(components),
            components=components,
        )
        result.summary = {"components": len(components)}
        result.status = "completed"
        return result
