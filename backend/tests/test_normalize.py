from datetime import UTC, datetime

from app.ioc import classify
from app.models import (
    AbuseIpdbSummary,
    DomainDetail,
    EngineStats,
    FileDetail,
    IpDetail,
    UrlDetail,
    Verdict,
)
from app.services.normalize import (
    build_behaviour,
    build_related,
    build_report,
    derive_verdict,
    timestamp,
)

from .conftest import BEHAVIOUR_SUMMARY, MITRE_TREES

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


class TestTimestamp:
    """Contract of `app.services.normalize.timestamp`."""

    def test_unix_seconds_convert_to_an_aware_utc_datetime(self):
        assert timestamp(1700000000) == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_missing_value_yields_no_datetime(self):
        assert timestamp(None) is None

    def test_zero_yields_no_datetime(self):
        assert timestamp(0) is None

    def test_non_numeric_value_yields_no_datetime(self):
        assert timestamp("2023-11-14") is None


class TestDeriveVerdict:
    """Contract of `app.services.normalize.derive_verdict`."""

    def test_three_malicious_engines_yield_a_malicious_verdict(self):
        assert derive_verdict(EngineStats(malicious=3, harmless=60)) is Verdict.MALICIOUS

    def test_many_malicious_engines_yield_a_malicious_verdict(self):
        assert derive_verdict(EngineStats(malicious=62, harmless=8)) is Verdict.MALICIOUS

    def test_two_malicious_engines_yield_a_suspicious_verdict(self):
        assert derive_verdict(EngineStats(malicious=2, harmless=60)) is Verdict.SUSPICIOUS

    def test_a_lone_suspicious_engine_yields_a_suspicious_verdict(self):
        assert derive_verdict(EngineStats(suspicious=1, harmless=60)) is Verdict.SUSPICIOUS

    def test_clean_scan_yields_a_harmless_verdict(self):
        assert derive_verdict(EngineStats(harmless=70, undetected=4)) is Verdict.HARMLESS

    def test_absence_of_any_engine_result_yields_an_unknown_verdict(self):
        assert derive_verdict(EngineStats()) is Verdict.UNKNOWN


class TestEngineStats:
    """Contract of `app.models.EngineStats`."""

    def test_total_counts_every_categorised_engine(self):
        stats = EngineStats(malicious=2, suspicious=1, harmless=3, undetected=4, timeout=1)
        assert stats.total == 11

    def test_flagged_counts_malicious_and_suspicious_engines(self):
        stats = EngineStats(malicious=2, suspicious=1, harmless=3, undetected=4)
        assert stats.flagged == 3


class TestBuildReportForAFile:
    """Contract of `app.services.normalize.build_report` for file indicators."""

    def report(self, attributes):
        return build_report(classify(EICAR_MD5), attributes)

    def test_the_normalised_indicator_is_carried_through(self, file_attributes):
        assert self.report(file_attributes).indicator == EICAR_MD5

    def test_a_heavily_detected_file_is_reported_as_malicious(self, file_attributes):
        assert self.report(file_attributes).verdict is Verdict.MALICIOUS

    def test_detection_ratio_counts_flagged_engines_over_the_total(self, file_attributes):
        assert self.report(file_attributes).detection_ratio == "63/73"

    def test_confirmed_timeouts_are_folded_into_the_timeout_count(self, file_attributes):
        assert self.report(file_attributes).stats.timeout == 2

    def test_community_votes_are_split_by_stance(self, file_attributes):
        assert self.report(file_attributes).community_votes_malicious == 91

    def test_reputation_is_carried_through(self, file_attributes):
        assert self.report(file_attributes).reputation == -14

    def test_first_seen_comes_from_the_first_submission(self, file_attributes):
        assert self.report(file_attributes).first_seen == datetime(
            2006, 1, 2, 8, 9, 19, tzinfo=UTC
        )

    def test_detail_describes_a_file(self, file_attributes):
        assert isinstance(self.report(file_attributes).detail, FileDetail)

    def test_the_suggested_threat_label_is_exposed(self, file_attributes):
        assert self.report(file_attributes).detail.threat_label == "virus.eicar/test"

    def test_threat_categories_are_flattened_to_their_values(self, file_attributes):
        assert self.report(file_attributes).detail.threat_categories == ["virus", "trojan"]

    def test_a_signed_binary_reports_a_valid_signature(self, file_attributes):
        assert self.report(file_attributes).detail.signature_valid is True

    def test_the_signer_is_exposed(self, file_attributes):
        assert self.report(file_attributes).detail.signer == "Example Corp"

    def test_vendors_are_ordered_with_malicious_verdicts_first(self, file_attributes):
        assert self.report(file_attributes).vendors[0].engine == "Kaspersky"

    def test_a_vendor_detection_name_is_preserved(self, file_attributes):
        vendors = {v.engine: v for v in self.report(file_attributes).vendors}
        assert vendors["Kaspersky"].result == "EICAR-Test-File"

    def test_every_engine_result_is_represented(self, file_attributes):
        assert len(self.report(file_attributes).vendors) == 4

    def test_the_source_link_points_at_the_virustotal_file_page(self, file_attributes):
        assert self.report(file_attributes).source_link == (
            f"https://www.virustotal.com/gui/file/{EICAR_MD5}"
        )

    def test_a_fresh_lookup_is_not_marked_as_cached(self, file_attributes):
        assert self.report(file_attributes).cached is False

    def test_a_replayed_lookup_is_marked_as_cached(self, file_attributes):
        report = build_report(classify(EICAR_MD5), file_attributes, cached=True)
        assert report.cached is True


class TestBuildReportForAnIp:
    """Contract of `app.services.normalize.build_report` for IP indicators."""

    def report(self, attributes, abuse=None):
        return build_report(classify("8.8.8.8"), attributes, abuse=abuse)

    def test_a_clean_address_is_reported_as_harmless(self, ip_attributes):
        assert self.report(ip_attributes).verdict is Verdict.HARMLESS

    def test_detail_describes_an_ip(self, ip_attributes):
        assert isinstance(self.report(ip_attributes).detail, IpDetail)

    def test_the_autonomous_system_owner_is_exposed(self, ip_attributes):
        assert self.report(ip_attributes).detail.as_owner == "GOOGLE"

    def test_the_announcing_network_is_exposed(self, ip_attributes):
        assert self.report(ip_attributes).detail.network == "8.8.8.0/24"

    def test_the_regional_registry_is_exposed(self, ip_attributes):
        assert self.report(ip_attributes).detail.registry == "ARIN"

    def test_supplied_abuseipdb_history_is_attached(self, ip_attributes):
        summary = AbuseIpdbSummary(
            confidence_score=87, total_reports=42, distinct_reporters=17
        )
        assert self.report(ip_attributes, abuse=summary).detail.abuseipdb.confidence_score == 87

    def test_the_source_link_points_at_the_virustotal_address_page(self, ip_attributes):
        assert self.report(ip_attributes).source_link == (
            "https://www.virustotal.com/gui/ip-address/8.8.8.8"
        )


class TestBuildReportForADomain:
    """Contract of `app.services.normalize.build_report` for domain indicators."""

    def report(self, attributes):
        return build_report(classify("example.com"), attributes)

    def test_a_single_suspicious_engine_makes_the_domain_suspicious(self, domain_attributes):
        assert self.report(domain_attributes).verdict is Verdict.SUSPICIOUS

    def test_detail_describes_a_domain(self, domain_attributes):
        assert isinstance(self.report(domain_attributes).detail, DomainDetail)

    def test_the_registrar_is_exposed(self, domain_attributes):
        assert self.report(domain_attributes).detail.registrar == "MarkMonitor Inc."

    def test_the_registration_date_is_converted_to_a_datetime(self, domain_attributes):
        assert self.report(domain_attributes).detail.created_at.year == 1997

    def test_dns_records_without_a_value_are_dropped(self, domain_attributes):
        assert len(self.report(domain_attributes).detail.dns_records) == 2

    def test_a_dns_record_keeps_its_type_and_value(self, domain_attributes):
        record = self.report(domain_attributes).detail.dns_records[0]
        assert (record.type, record.value) == ("A", "142.250.185.14")

    def test_numeric_popularity_ranks_are_kept(self, domain_attributes):
        assert self.report(domain_attributes).detail.popularity_ranks == {"Cisco Umbrella": 1}

    def test_vendor_categories_are_exposed(self, domain_attributes):
        assert self.report(domain_attributes).detail.categories["Sophos"] == "search engines"


class TestBuildReportForAUrl:
    """Contract of `app.services.normalize.build_report` for URL indicators."""

    def report(self, attributes):
        return build_report(classify("https://example.com/landing?x=1"), attributes)

    def test_six_malicious_engines_make_the_url_malicious(self, url_attributes):
        assert self.report(url_attributes).verdict is Verdict.MALICIOUS

    def test_detail_describes_a_url(self, url_attributes):
        assert isinstance(self.report(url_attributes).detail, UrlDetail)

    def test_the_page_title_is_exposed(self, url_attributes):
        assert self.report(url_attributes).detail.title == "Example Landing"

    def test_the_last_response_code_is_exposed(self, url_attributes):
        assert self.report(url_attributes).detail.response_code == 200

    def test_the_source_link_addresses_the_url_by_its_base64_identifier(self, url_attributes):
        assert self.report(url_attributes).source_link.startswith(
            "https://www.virustotal.com/gui/url/"
        )

    def test_the_source_link_identifier_carries_no_base64_padding(self, url_attributes):
        assert not self.report(url_attributes).source_link.endswith("=")


class TestBuildBehaviour:
    """Contract of `app.services.normalize.build_behaviour`."""

    def behaviour(self):
        return build_behaviour(BEHAVIOUR_SUMMARY, MITRE_TREES)

    def test_created_processes_are_listed(self):
        assert self.behaviour().processes_created == ["C:\\Windows\\system32\\cmd.exe"]

    def test_dns_lookups_without_a_hostname_are_dropped(self):
        assert len(self.behaviour().dns_lookups) == 1

    def test_a_dns_lookup_keeps_its_resolved_addresses(self):
        assert self.behaviour().dns_lookups[0].resolved_ips == ["1.2.3.4"]

    def test_each_reporting_sandbox_is_represented(self):
        assert [sandbox.sandbox for sandbox in self.behaviour().mitre] == ["Zenbox"]

    def test_a_tactic_keeps_its_attack_identifier(self):
        assert self.behaviour().mitre[0].tactics[0].id == "TA0005"

    def test_an_observed_technique_is_listed_under_its_tactic(self):
        assert self.behaviour().mitre[0].tactics[0].techniques[0].id == "T1027"

    def test_repeated_signature_severities_are_collapsed(self):
        technique = self.behaviour().mitre[0].tactics[0].techniques[0]
        assert technique.severities == ["IMPACT_SEVERITY_HIGH"]

    def test_every_signature_description_is_kept(self):
        technique = self.behaviour().mitre[0].tactics[0].techniques[0]
        assert technique.signatures == ["Packed", "Obfuscated"]

    def test_an_observed_technique_carries_its_attack_mitigations(self):
        technique = self.behaviour().mitre[0].tactics[0].techniques[0]
        assert "M1049" in {mitigation.id for mitigation in technique.mitigations}

    def test_empty_sandbox_payloads_produce_an_empty_report(self):
        assert build_behaviour({}, {}).mitre == []


class TestBuildRelated:
    """Contract of `app.services.normalize.build_related`."""

    CONTACTED_DOMAINS = [
        {
            "id": "clean.example",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}},
        },
        {
            "id": "c2.example",
            "attributes": {"last_analysis_stats": {"malicious": 9, "harmless": 60}},
        },
    ]

    def test_the_most_detected_indicator_is_listed_first(self):
        related = build_related(self.CONTACTED_DOMAINS, "contacted_domains")
        assert related[0].indicator == "c2.example"

    def test_a_related_indicator_carries_its_own_verdict(self):
        related = build_related(self.CONTACTED_DOMAINS, "contacted_domains")
        assert related[0].verdict is Verdict.MALICIOUS

    def test_a_related_indicator_reports_how_many_engines_flagged_it(self):
        related = build_related(self.CONTACTED_DOMAINS, "contacted_domains")
        assert related[0].detections == 9

    def test_a_resolution_to_a_hostname_is_typed_as_a_domain(self):
        objects = [{"id": "x", "attributes": {"host_name": "www.example.com", "date": 1700000000}}]
        assert build_related(objects, "resolutions")[0].ioc_type.value == "domain"

    def test_a_resolution_to_an_address_is_typed_as_an_ip(self):
        objects = [{"id": "x", "attributes": {"ip_address": "1.2.3.4", "date": 1700000000}}]
        assert build_related(objects, "resolutions")[0].ioc_type.value == "ipv4"

    def test_a_resolution_records_when_it_was_observed(self):
        objects = [{"id": "x", "attributes": {"host_name": "a.example", "date": 1700000000}}]
        assert build_related(objects, "resolutions")[0].observed_at == datetime(
            2023, 11, 14, 22, 13, 20, tzinfo=UTC
        )
