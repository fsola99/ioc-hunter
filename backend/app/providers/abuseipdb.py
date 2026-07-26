from __future__ import annotations

import logging
from datetime import datetime

import httpx

from ..models import AbuseIpdbSummary

logger = logging.getLogger(__name__)

BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIpdbClient:
    """Reads IP reporting history from AbuseIPDB.

    Enrichment is best-effort: a failed or unauthorised call yields `None` so an
    IP report still renders with its VirusTotal data.
    """

    def __init__(self, api_key: str, timeout: float = 10.0) -> None:
        """Create a client authenticating with `api_key`.

        Args:
            api_key: AbuseIPDB API credential. An empty value disables lookups.
            timeout: Seconds to wait for each request.
        """
        self._api_key = api_key
        self._timeout = timeout

    async def check(self, ip_address: str, max_age_days: int = 90) -> AbuseIpdbSummary | None:
        """Return the reporting history for `ip_address`.

        Args:
            ip_address: The IP address to look up.
            max_age_days: How far back reports are counted.

        Returns:
            The reporting summary, or `None` when AbuseIPDB is unconfigured or
            the request did not succeed.
        """
        if not self._api_key:
            return None

        try:
            async with httpx.AsyncClient(base_url=BASE_URL, timeout=self._timeout) as client:
                response = await client.get(
                    "/check",
                    params={"ipAddress": ip_address, "maxAgeInDays": max_age_days},
                    headers={"Key": self._api_key, "Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            logger.warning("AbuseIPDB request failed for %s: %s", ip_address, exc)
            return None

        if response.status_code != 200:
            logger.warning(
                "AbuseIPDB returned status %s for %s", response.status_code, ip_address
            )
            return None

        data = response.json().get("data", {})
        return AbuseIpdbSummary(
            confidence_score=data.get("abuseConfidenceScore", 0),
            total_reports=data.get("totalReports", 0),
            distinct_reporters=data.get("numDistinctUsers", 0),
            country_code=data.get("countryCode"),
            isp=data.get("isp"),
            usage_type=data.get("usageType"),
            is_tor=bool(data.get("isTor", False)),
            last_reported_at=_parse_timestamp(data.get("lastReportedAt")),
        )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
