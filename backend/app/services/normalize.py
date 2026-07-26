from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..ioc import ClassifiedIoC, IoCType
from ..models import (
    AbuseIpdbSummary,
    BehaviourReport,
    Detail,
    DnsLookup,
    DnsRecord,
    DomainDetail,
    EngineStats,
    FileDetail,
    IpDetail,
    RelatedIndicator,
    Report,
    SandboxMitre,
    Tactic,
    Technique,
    UrlDetail,
    VendorVerdict,
    Verdict,
)
from ..providers import virustotal
from .mitre import mitigations_for

MALICIOUS_THRESHOLD = 3


def timestamp(value: Any) -> datetime | None:
    """Return `value` as a UTC datetime when it is a Unix timestamp."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def derive_verdict(stats: EngineStats) -> Verdict:
    """Return the overall assessment implied by `stats`.

    Three or more malicious categorisations read as malicious; one or two, or any
    suspicious categorisation, reads as suspicious, which keeps a single vendor
    false positive from condemning an indicator on its own.
    """
    if stats.malicious >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if stats.malicious or stats.suspicious:
        return Verdict.SUSPICIOUS
    if stats.total:
        return Verdict.HARMLESS
    return Verdict.UNKNOWN


def _engine_stats(attributes: dict) -> EngineStats:
    raw = attributes.get("last_analysis_stats") or {}
    return EngineStats(
        malicious=raw.get("malicious", 0) or 0,
        suspicious=raw.get("suspicious", 0) or 0,
        harmless=raw.get("harmless", 0) or 0,
        undetected=raw.get("undetected", 0) or 0,
        timeout=(raw.get("timeout", 0) or 0) + (raw.get("confirmed-timeout", 0) or 0),
    )


def _vendors(attributes: dict) -> list[VendorVerdict]:
    results = attributes.get("last_analysis_results") or {}
    priority = {"malicious": 0, "suspicious": 1, "harmless": 2, "undetected": 3}
    vendors = [
        VendorVerdict(
            engine=name,
            category=payload.get("category", "undetected"),
            result=payload.get("result"),
            version=payload.get("engine_version"),
            updated=payload.get("engine_update"),
        )
        for name, payload in results.items()
        if isinstance(payload, dict)
    ]
    vendors.sort(key=lambda v: (priority.get(v.category, 4), v.engine.lower()))
    return vendors


def _file_detail(attributes: dict) -> FileDetail:
    classification = attributes.get("popular_threat_classification") or {}
    signature = attributes.get("signature_info") or {}
    categories = [
        entry.get("value")
        for entry in classification.get("popular_threat_category", [])
        if entry.get("value")
    ]
    verified = signature.get("verified")
    return FileDetail(
        md5=attributes.get("md5"),
        sha1=attributes.get("sha1"),
        sha256=attributes.get("sha256"),
        size=attributes.get("size"),
        type_description=attributes.get("type_description"),
        magic=attributes.get("magic"),
        names=[name for name in (attributes.get("names") or [])[:12] if name],
        threat_label=classification.get("suggested_threat_label"),
        threat_categories=categories,
        signer=signature.get("signers"),
        signature_valid=(verified == "Signed") if verified else None,
    )


def _ip_detail(attributes: dict, abuse: AbuseIpdbSummary | None) -> IpDetail:
    return IpDetail(
        asn=attributes.get("asn"),
        as_owner=attributes.get("as_owner"),
        country=attributes.get("country"),
        continent=attributes.get("continent"),
        network=attributes.get("network"),
        registry=attributes.get("regional_internet_registry"),
        jarm=attributes.get("jarm"),
        abuseipdb=abuse,
    )


def _domain_detail(attributes: dict) -> DomainDetail:
    ranks = {
        source: payload.get("rank")
        for source, payload in (attributes.get("popularity_ranks") or {}).items()
        if isinstance(payload, dict) and isinstance(payload.get("rank"), int)
    }
    records = [
        DnsRecord(
            type=record.get("type", "?"),
            value=str(record.get("value", "")),
            ttl=record.get("ttl"),
        )
        for record in (attributes.get("last_dns_records") or [])
        if record.get("value")
    ]
    return DomainDetail(
        registrar=attributes.get("registrar"),
        created_at=timestamp(attributes.get("creation_date")),
        updated_at=timestamp(attributes.get("last_update_date")),
        expires_at=timestamp(attributes.get("expiration_date")),
        categories={k: v for k, v in (attributes.get("categories") or {}).items() if v},
        dns_records=records[:25],
        popularity_ranks=ranks,
    )


def _url_detail(attributes: dict) -> UrlDetail:
    return UrlDetail(
        final_url=attributes.get("last_final_url"),
        title=attributes.get("title"),
        response_code=attributes.get("last_http_response_code"),
        content_type=attributes.get("last_http_response_content_type"),
        categories={k: v for k, v in (attributes.get("categories") or {}).items() if v},
        outgoing_links=(attributes.get("outgoing_links") or [])[:20],
    )


def _detail(
    ioc: ClassifiedIoC, attributes: dict, abuse: AbuseIpdbSummary | None
) -> Detail:
    if ioc.family == "file":
        return _file_detail(attributes)
    if ioc.family == "ip":
        return _ip_detail(attributes, abuse)
    if ioc.family == "domain":
        return _domain_detail(attributes)
    return _url_detail(attributes)


def _seen_dates(ioc: ClassifiedIoC, attributes: dict) -> tuple[datetime | None, datetime | None]:
    if ioc.family == "file":
        return (
            timestamp(attributes.get("first_submission_date")),
            timestamp(attributes.get("last_submission_date")),
        )
    if ioc.family == "url":
        return (
            timestamp(attributes.get("first_submission_date")),
            timestamp(attributes.get("last_submission_date")),
        )
    return timestamp(attributes.get("creation_date")), timestamp(
        attributes.get("last_modification_date")
    )


def build_report(
    ioc: ClassifiedIoC,
    attributes: dict,
    *,
    abuse: AbuseIpdbSummary | None = None,
    cached: bool = False,
) -> Report:
    """Convert VirusTotal attributes into the service's normalised report shape.

    Args:
        ioc: The classified indicator the attributes describe.
        attributes: The `attributes` object from a VirusTotal v3 response.
        abuse: AbuseIPDB enrichment, applied to IP indicators only.
        cached: Whether the attributes were served from the local cache.

    Returns:
        A report whose common fields are populated for every indicator type and
        whose `detail` matches the indicator's family.
    """
    stats = _engine_stats(attributes)
    votes = attributes.get("total_votes") or {}
    first_seen, last_seen = _seen_dates(ioc, attributes)

    return Report(
        indicator=ioc.value,
        raw_input=ioc.raw,
        ioc_type=ioc.type,
        verdict=derive_verdict(stats),
        stats=stats,
        detection_ratio=f"{stats.flagged}/{stats.total}",
        reputation=attributes.get("reputation", 0) or 0,
        community_votes_harmless=votes.get("harmless", 0) or 0,
        community_votes_malicious=votes.get("malicious", 0) or 0,
        tags=[tag for tag in (attributes.get("tags") or []) if tag][:20],
        first_seen=first_seen,
        last_seen=last_seen,
        last_analysed=timestamp(attributes.get("last_analysis_date")),
        vendors=_vendors(attributes),
        detail=_detail(ioc, attributes, abuse),
        source_link=virustotal.gui_link(ioc),
        retrieved_at=datetime.now(tz=UTC),
        cached=cached,
    )


def _techniques(raw_techniques: list[dict]) -> list[Technique]:
    techniques = []
    for technique in raw_techniques:
        signatures = technique.get("signatures") or []
        technique_id = technique.get("id", "")
        techniques.append(
            Technique(
                id=technique_id,
                name=technique.get("name", "Unknown technique"),
                description=technique.get("description"),
                link=technique.get("link"),
                severities=sorted(
                    {sig.get("severity") for sig in signatures if sig.get("severity")}
                ),
                signatures=[
                    sig["description"] for sig in signatures if sig.get("description")
                ][:15],
                mitigations=mitigations_for(technique_id) if technique_id else [],
            )
        )
    return techniques


def build_behaviour(summary: dict, mitre_trees: dict, *, cached: bool = False) -> BehaviourReport:
    """Convert VirusTotal sandbox payloads into a behaviour report.

    Args:
        summary: The `data` object from a `behaviour_summary` response.
        mitre_trees: The `data` object from a `behaviour_mitre_trees` response.
        cached: Whether the payloads were served from the local cache.

    Returns:
        Observed runtime activity together with ATT&CK coverage per sandbox,
        each technique carrying its recommended mitigations.
    """
    sandboxes = []
    for sandbox_name, sandbox_data in (mitre_trees or {}).items():
        if not isinstance(sandbox_data, dict):
            continue
        tactics = [
            Tactic(
                id=tactic.get("id", ""),
                name=tactic.get("name", "Unknown tactic"),
                link=tactic.get("link"),
                techniques=_techniques(tactic.get("techniques") or []),
            )
            for tactic in sandbox_data.get("tactics", [])
        ]
        if tactics:
            sandboxes.append(SandboxMitre(sandbox=sandbox_name, tactics=tactics))

    def strings(key: str, limit: int = 60) -> list[str]:
        values = summary.get(key) or []
        return [str(value) for value in values if value][:limit]

    lookups = [
        DnsLookup(
            hostname=entry.get("hostname", ""),
            resolved_ips=[ip for ip in (entry.get("resolved_ips") or []) if ip],
        )
        for entry in (summary.get("dns_lookups") or [])
        if entry.get("hostname")
    ][:40]

    return BehaviourReport(
        processes_created=strings("processes_created"),
        services_started=strings("services_started"),
        mutexes_created=strings("mutexes_created"),
        files_opened=strings("files_opened"),
        files_written=strings("files_written"),
        registry_keys_opened=strings("registry_keys_opened"),
        modules_loaded=strings("modules_loaded"),
        processes_terminated=strings("processes_terminated"),
        dns_lookups=lookups,
        mitre=sandboxes,
        cached=cached,
    )


_RELATION_TYPES = {
    "contacted_ips": IoCType.IPV4,
    "contacted_domains": IoCType.DOMAIN,
    "contacted_urls": IoCType.URL,
    "resolutions": IoCType.DOMAIN,
}


def build_related(objects: list[dict], relationship: str) -> list[RelatedIndicator]:
    """Convert VirusTotal relationship objects into related indicators.

    Args:
        objects: The `data` list from a relationship response.
        relationship: The VirusTotal relationship name that produced `objects`.

    Returns:
        Related indicators ordered with the most-detected first.
    """
    default_type = _RELATION_TYPES.get(relationship, IoCType.DOMAIN)
    related: list[RelatedIndicator] = []

    for item in objects:
        attributes = item.get("attributes") or {}
        identifier = item.get("id", "")

        if relationship == "resolutions":
            identifier = attributes.get("host_name") or attributes.get("ip_address") or identifier
            ioc_type = IoCType.DOMAIN if attributes.get("host_name") else IoCType.IPV4
            observed = timestamp(attributes.get("date"))
        else:
            ioc_type = default_type
            if relationship == "contacted_urls":
                identifier = attributes.get("url") or identifier
            observed = timestamp(attributes.get("last_analysis_date"))

        stats = _engine_stats(attributes)
        related.append(
            RelatedIndicator(
                indicator=identifier,
                ioc_type=ioc_type,
                verdict=derive_verdict(stats),
                detections=stats.flagged,
                total_engines=stats.total,
                detail=attributes.get("as_owner") or attributes.get("title"),
                observed_at=observed,
            )
        )

    related.sort(key=lambda item: item.detections, reverse=True)
    return related
