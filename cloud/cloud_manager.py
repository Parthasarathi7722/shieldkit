"""
Cloud Manager — Unified interface for multi-cloud security scanning.
Routes to Prowler or ScoutSuite based on provider and user preference.
"""

from __future__ import annotations

from typing import Any

from ..models import CloudProvider, CloudScanResult
from .prowler_scanner import ProwlerScanner
from .scoutsuite_scanner import ScoutSuiteScanner


class CloudManager:
    """Orchestrates cloud security scans across providers and tools."""

    def __init__(self, prowler_bin: str = "prowler", scoutsuite_bin: str = "scout"):
        self.prowler = ProwlerScanner(prowler_bin)
        self.scoutsuite = ScoutSuiteScanner(scoutsuite_bin)

    async def scan(
        self,
        provider: CloudProvider,
        tool: str = "prowler",
        services: list[str] | None = None,
        compliance: list[str] | None = None,
        regions: list[str] | None = None,
        mock: bool = False,
    ) -> CloudScanResult:
        """Run a cloud security scan using the specified tool."""
        if tool == "scoutsuite":
            return await self.scoutsuite.scan(provider, services=services, mock=mock)
        else:
            return await self.prowler.scan(
                provider, services=services, compliance=compliance,
                regions=regions, mock=mock,
            )

    async def scan_all_providers(
        self,
        providers: list[CloudProvider] | None = None,
        tool: str = "prowler",
        mock: bool = False,
    ) -> list[CloudScanResult]:
        """Scan multiple cloud providers in sequence."""
        import asyncio
        if providers is None:
            providers = [CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP]
        tasks = [self.scan(p, tool=tool, mock=mock) for p in providers]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def get_supported_providers(self) -> dict[str, list[str]]:
        return {
            "prowler": ["aws", "azure", "gcp"],
            "scoutsuite": ["aws", "azure", "gcp"],
        }

    def get_compliance_frameworks(self) -> dict[str, list[str]]:
        return {
            "aws": ["cis_1.5", "soc2", "pci-dss", "hipaa", "gdpr", "nist-800-53"],
            "azure": ["cis_2.0", "soc2", "pci-dss", "hipaa"],
            "gcp": ["cis_2.0", "soc2", "pci-dss"],
        }
