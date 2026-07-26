from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from ..config import Settings, get_settings
from ..models import ProviderStatus, ServiceStatus
from ..services.attack import catalogue_size

router = APIRouter(prefix="/api", tags=["service"])

VERSION = "2.0.0"


@router.get("/health", response_model=ServiceStatus)
def health(settings: Annotated[Settings, Depends(get_settings)]) -> ServiceStatus:
    """Report service version and which intelligence providers are usable."""
    return ServiceStatus(
        status="ok" if settings.virustotal_configured else "degraded",
        version=VERSION,
        providers=[
            ProviderStatus(
                name="VirusTotal",
                configured=settings.virustotal_configured,
                detail=(
                    "Ready."
                    if settings.virustotal_configured
                    else "Set VT_API_KEY in your .env file to enable lookups."
                ),
            ),
            ProviderStatus(
                name="AbuseIPDB",
                configured=settings.abuseipdb_configured,
                detail=(
                    "Ready. IP reports include reporting history."
                    if settings.abuseipdb_configured
                    else "Optional. Set ABUSEIPDB_API_KEY to enrich IP reports."
                ),
            ),
            ProviderStatus(
                name="MITRE ATT&CK",
                configured=catalogue_size() > 0,
                detail=f"Bundled catalogue covers {catalogue_size()} techniques and sub-techniques.",
            ),
        ],
    )
