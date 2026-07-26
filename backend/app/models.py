from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from .ioc import IoCType


class Verdict(StrEnum):
    """Overall assessment of an indicator."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"


class EngineStats(BaseModel):
    """Counts of how scanning engines categorised an indicator."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0

    @property
    def total(self) -> int:
        """Number of engines that returned a categorisation."""
        return self.malicious + self.suspicious + self.harmless + self.undetected + self.timeout

    @property
    def flagged(self) -> int:
        """Number of engines that considered the indicator malicious or suspicious."""
        return self.malicious + self.suspicious


class VendorVerdict(BaseModel):
    """One scanning engine's categorisation of an indicator."""

    engine: str
    category: str
    result: str | None = None
    version: str | None = None
    updated: str | None = None


class Mitigation(BaseModel):
    """A MITRE ATT&CK mitigation recommended against a technique."""

    id: str
    name: str


class Technique(BaseModel):
    """A MITRE ATT&CK technique observed during sandbox detonation."""

    id: str
    name: str
    description: str | None = None
    link: str | None = None
    severities: list[str] = Field(default_factory=list)
    signatures: list[str] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)


class Tactic(BaseModel):
    """A MITRE ATT&CK tactic grouping observed techniques."""

    id: str
    name: str
    link: str | None = None
    techniques: list[Technique] = Field(default_factory=list)


class SandboxMitre(BaseModel):
    """MITRE ATT&CK coverage reported by a single sandbox."""

    sandbox: str
    tactics: list[Tactic] = Field(default_factory=list)


class AbuseIpdbSummary(BaseModel):
    """Reporting history for an IP address, as recorded by AbuseIPDB."""

    confidence_score: int
    total_reports: int
    distinct_reporters: int
    country_code: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    is_tor: bool = False
    last_reported_at: datetime | None = None


class FileDetail(BaseModel):
    """Attributes specific to a file indicator."""

    kind: Literal["file"] = "file"
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    size: int | None = None
    type_description: str | None = None
    magic: str | None = None
    names: list[str] = Field(default_factory=list)
    threat_label: str | None = None
    threat_categories: list[str] = Field(default_factory=list)
    signer: str | None = None
    signature_valid: bool | None = None


class IpDetail(BaseModel):
    """Attributes specific to an IP address indicator."""

    kind: Literal["ip"] = "ip"
    asn: int | None = None
    as_owner: str | None = None
    country: str | None = None
    continent: str | None = None
    network: str | None = None
    registry: str | None = None
    jarm: str | None = None
    abuseipdb: AbuseIpdbSummary | None = None


class DnsRecord(BaseModel):
    """A DNS record observed for a domain."""

    type: str
    value: str
    ttl: int | None = None


class DomainDetail(BaseModel):
    """Attributes specific to a domain indicator."""

    kind: Literal["domain"] = "domain"
    registrar: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    expires_at: datetime | None = None
    categories: dict[str, str] = Field(default_factory=dict)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    popularity_ranks: dict[str, int] = Field(default_factory=dict)


class UrlDetail(BaseModel):
    """Attributes specific to a URL indicator."""

    kind: Literal["url"] = "url"
    final_url: str | None = None
    title: str | None = None
    response_code: int | None = None
    content_type: str | None = None
    categories: dict[str, str] = Field(default_factory=dict)
    outgoing_links: list[str] = Field(default_factory=list)


Detail = Annotated[
    FileDetail | IpDetail | DomainDetail | UrlDetail,
    Field(discriminator="kind"),
]


class Report(BaseModel):
    """A normalised threat intelligence report for one indicator.

    The common fields carry across every indicator type; `detail` holds the
    attributes that only make sense for that type.
    """

    indicator: str
    raw_input: str
    ioc_type: IoCType
    verdict: Verdict
    stats: EngineStats
    detection_ratio: str
    reputation: int = 0
    community_votes_harmless: int = 0
    community_votes_malicious: int = 0
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_analysed: datetime | None = None
    vendors: list[VendorVerdict] = Field(default_factory=list)
    detail: Detail
    source_link: str
    retrieved_at: datetime
    cached: bool = False


class DnsLookup(BaseModel):
    """A hostname resolution observed during sandbox detonation."""

    hostname: str
    resolved_ips: list[str] = Field(default_factory=list)


class BehaviourReport(BaseModel):
    """Runtime activity observed when a file was detonated in a sandbox."""

    processes_created: list[str] = Field(default_factory=list)
    services_started: list[str] = Field(default_factory=list)
    mutexes_created: list[str] = Field(default_factory=list)
    files_opened: list[str] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    registry_keys_opened: list[str] = Field(default_factory=list)
    modules_loaded: list[str] = Field(default_factory=list)
    processes_terminated: list[str] = Field(default_factory=list)
    dns_lookups: list[DnsLookup] = Field(default_factory=list)
    mitre: list[SandboxMitre] = Field(default_factory=list)
    cached: bool = False


class RelatedIndicator(BaseModel):
    """An indicator connected to the one that was looked up."""

    indicator: str
    ioc_type: IoCType
    verdict: Verdict
    detections: int = 0
    total_engines: int = 0
    detail: str | None = None
    observed_at: datetime | None = None


class RelationsReport(BaseModel):
    """Indicators connected to the one that was looked up.

    For files these are the network endpoints contacted during detonation; for
    IPs and domains they are the observed passive DNS resolutions.
    """

    relation: str
    items: list[RelatedIndicator] = Field(default_factory=list)
    truncated: bool = False
    cached: bool = False


class ClassificationResult(BaseModel):
    """How the service interprets a candidate indicator string."""

    raw_input: str
    indicator: str
    ioc_type: IoCType
    family: str


class ProviderStatus(BaseModel):
    """Availability of an upstream intelligence provider."""

    name: str
    configured: bool
    detail: str


class ServiceStatus(BaseModel):
    """Health of the service and the providers it depends on."""

    status: str
    version: str
    providers: list[ProviderStatus]
