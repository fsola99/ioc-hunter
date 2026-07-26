from __future__ import annotations

import base64
import logging

import httpx

from ..errors import (
    IndicatorNotFound,
    ProviderAuthError,
    ProviderNotConfigured,
    ProviderQuotaExceeded,
    ProviderUnavailable,
)
from ..ioc import ClassifiedIoC

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui"

_COLLECTIONS = {
    "file": "files",
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
}


def url_identifier(url: str) -> str:
    """Return the VirusTotal object id for `url`.

    VirusTotal addresses URL objects by their unpadded base64url encoding.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def object_id(ioc: ClassifiedIoC) -> str:
    """Return the VirusTotal object id addressing `ioc`."""
    return url_identifier(ioc.value) if ioc.family == "url" else ioc.value


def collection(ioc: ClassifiedIoC) -> str:
    """Return the VirusTotal collection holding objects of this indicator's family."""
    return _COLLECTIONS[ioc.family]


def gui_link(ioc: ClassifiedIoC) -> str:
    """Return the VirusTotal web interface URL for `ioc`."""
    segment = {"file": "file", "ip": "ip-address", "domain": "domain", "url": "url"}
    return f"{GUI_URL}/{segment[ioc.family]}/{object_id(ioc)}"


class VirusTotalClient:
    """Reads indicator intelligence from the VirusTotal v3 API.

    Each method issues exactly one upstream request, so callers control how much
    of a free-tier quota a single user action consumes.
    """

    def __init__(self, api_key: str, timeout: float = 20.0) -> None:
        """Create a client authenticating with `api_key`.

        Args:
            api_key: VirusTotal API credential.
            timeout: Seconds to wait for each request.
        """
        self._api_key = api_key
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "VirusTotalClient":
        self._client = httpx.AsyncClient(
            base_url=BASE_URL,
            timeout=self._timeout,
            headers={"x-apikey": self._api_key, "accept": "application/json"},
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, params: dict[str, str | int] | None = None) -> dict:
        if not self._api_key:
            raise ProviderNotConfigured(
                "No VirusTotal API key is configured. Set VT_API_KEY in your .env file.",
                provider="VirusTotal",
            )
        if self._client is None:
            raise RuntimeError("VirusTotalClient must be used as an async context manager.")

        try:
            response = await self._client.get(path, params=params)
        except httpx.TimeoutException as exc:
            raise ProviderUnavailable(
                "VirusTotal did not respond in time.", provider="VirusTotal"
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(
                f"Could not reach VirusTotal: {exc}", provider="VirusTotal"
            ) from exc

        if response.status_code == 200:
            return response.json()
        if response.status_code == 404:
            raise IndicatorNotFound(
                "VirusTotal has no record of this indicator.", provider="VirusTotal"
            )
        if response.status_code in (401, 403):
            raise ProviderAuthError(
                "VirusTotal rejected the API key. Check VT_API_KEY in your .env file.",
                provider="VirusTotal",
            )
        if response.status_code == 429:
            raise ProviderQuotaExceeded(
                "VirusTotal quota exhausted. The free tier allows 4 lookups per minute "
                "and 500 per day.",
                provider="VirusTotal",
            )

        logger.warning("Unexpected VirusTotal status %s for %s", response.status_code, path)
        raise ProviderUnavailable(
            f"VirusTotal returned an unexpected status ({response.status_code}).",
            provider="VirusTotal",
        )

    async def fetch_object(self, ioc: ClassifiedIoC) -> dict:
        """Return the attributes VirusTotal holds for `ioc`.

        Raises:
            IndicatorNotFound: If VirusTotal has no record of the indicator.
            ProviderAuthError: If the configured credential was rejected.
            ProviderQuotaExceeded: If the account's rate limit is exhausted.
            ProviderUnavailable: If VirusTotal could not be reached.
        """
        payload = await self._get(f"/{collection(ioc)}/{object_id(ioc)}")
        return payload.get("data", {}).get("attributes", {})

    async def fetch_behaviour_summary(self, file_hash: str) -> dict:
        """Return merged sandbox behaviour recorded for the file at `file_hash`."""
        payload = await self._get(f"/files/{file_hash}/behaviour_summary")
        return payload.get("data", {})

    async def fetch_mitre_trees(self, file_hash: str) -> dict:
        """Return per-sandbox MITRE ATT&CK trees for the file at `file_hash`."""
        payload = await self._get(f"/files/{file_hash}/behaviour_mitre_trees")
        return payload.get("data", {})

    async def fetch_relationship(
        self, ioc: ClassifiedIoC, relationship: str, limit: int = 40
    ) -> list[dict]:
        """Return objects linked to `ioc` through `relationship`.

        Args:
            ioc: The indicator whose relationships are being read.
            relationship: A VirusTotal relationship name, such as `contacted_ips`.
            limit: Maximum number of related objects to request.

        Returns:
            The related objects, each with its VirusTotal `id` and `attributes`.
        """
        payload = await self._get(
            f"/{collection(ioc)}/{object_id(ioc)}/{relationship}", params={"limit": limit}
        )
        data = payload.get("data", [])
        return data if isinstance(data, list) else []
