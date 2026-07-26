from __future__ import annotations

import asyncio
import logging

from ..config import Settings
from ..ioc import ClassifiedIoC
from ..models import BehaviourReport, RelationsReport, Report
from ..providers.abuseipdb import AbuseIpdbClient
from ..providers.virustotal import VirusTotalClient
from . import normalize
from .cache import TTLCache

logger = logging.getLogger(__name__)

RELATION_BY_FAMILY = {
    "file": "contacted_domains",
    "ip": "resolutions",
    "domain": "resolutions",
}

RELATION_LIMIT = 40


class IntelService:
    """Answers indicator lookups from upstream providers, with local caching.

    A primary lookup costs one VirusTotal request. Sandbox behaviour and related
    indicators are fetched only when asked for, so a single search stays within
    a free-tier rate limit of four requests per minute.
    """

    def __init__(self, settings: Settings) -> None:
        """Create a service reading credentials and cache lifetime from `settings`."""
        self._settings = settings
        self._objects = TTLCache(settings.cache_ttl_seconds)
        self._behaviour = TTLCache(settings.cache_ttl_seconds)
        self._relations = TTLCache(settings.cache_ttl_seconds)

    def _virustotal(self) -> VirusTotalClient:
        return VirusTotalClient(
            self._settings.virustotal_api_key, self._settings.request_timeout_seconds
        )

    async def lookup(self, ioc: ClassifiedIoC) -> Report:
        """Return the normalised report for `ioc`.

        IP indicators are additionally enriched with AbuseIPDB reporting history
        when that provider is configured.

        Args:
            ioc: The classified indicator to look up.

        Returns:
            The report, flagged as cached when no upstream call was needed.

        Raises:
            ProviderError: If VirusTotal rejects, throttles or cannot serve the
                request. The subclass carries the status to surface.
        """

        async def fetch() -> dict:
            async with self._virustotal() as client:
                return await client.fetch_object(ioc)

        attributes, cached = await self._objects.get_or_fetch(
            f"object:{ioc.family}:{ioc.value}", fetch
        )

        abuse = None
        if ioc.family == "ip" and self._settings.abuseipdb_configured:
            abuse = await AbuseIpdbClient(
                self._settings.abuseipdb_api_key, self._settings.request_timeout_seconds
            ).check(ioc.value)

        return normalize.build_report(ioc, attributes, abuse=abuse, cached=cached)

    async def behaviour(self, ioc: ClassifiedIoC) -> BehaviourReport:
        """Return sandbox behaviour and ATT&CK coverage for the file `ioc`.

        Args:
            ioc: A classified indicator whose family is `file`.

        Returns:
            The behaviour report, flagged as cached when no upstream call was needed.

        Raises:
            ProviderError: If VirusTotal rejects, throttles or cannot serve the request.
        """

        async def fetch() -> tuple[dict, dict]:
            async with self._virustotal() as client:
                summary, trees = await asyncio.gather(
                    client.fetch_behaviour_summary(ioc.value),
                    client.fetch_mitre_trees(ioc.value),
                    return_exceptions=True,
                )
            return (
                summary if isinstance(summary, dict) else {},
                trees if isinstance(trees, dict) else {},
            )

        (summary, trees), cached = await self._behaviour.get_or_fetch(
            f"behaviour:{ioc.value}", fetch
        )
        return normalize.build_behaviour(summary, trees, cached=cached)

    async def relations(self, ioc: ClassifiedIoC) -> RelationsReport:
        """Return indicators connected to `ioc`.

        Files yield the domains contacted during detonation; IPs and domains
        yield their observed passive DNS resolutions.

        Args:
            ioc: The classified indicator whose connections are wanted.

        Returns:
            The related indicators, flagged as cached when no upstream call was needed.

        Raises:
            ProviderError: If VirusTotal rejects, throttles or cannot serve the request.
        """
        relationship = RELATION_BY_FAMILY.get(ioc.family)
        if relationship is None:
            return RelationsReport(relation="none", items=[])

        async def fetch() -> list[dict]:
            async with self._virustotal() as client:
                return await client.fetch_relationship(ioc, relationship, RELATION_LIMIT)

        objects, cached = await self._relations.get_or_fetch(
            f"relations:{ioc.family}:{ioc.value}", fetch
        )
        items = normalize.build_related(objects, relationship)
        return RelationsReport(
            relation=relationship,
            items=items,
            truncated=len(objects) >= RELATION_LIMIT,
            cached=cached,
        )
