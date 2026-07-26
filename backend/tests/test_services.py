import asyncio

import pytest

from app.ioc import classify
from app.models import Report
from app.services.cache import TTLCache
from app.services.export import reports_to_csv
from app.services.history import HistoryStore
from app.services.mitre import covered_techniques, mitigations_for
from app.services.normalize import build_report


def report_for(indicator: str, attributes: dict) -> Report:
    return build_report(classify(indicator), attributes)


class TestMitigationsFor:
    """Contract of `app.services.mitre.mitigations_for`."""

    def test_a_covered_technique_returns_its_mitigations(self):
        assert mitigations_for("T1027")

    def test_a_mitigation_exposes_its_attack_identifier(self):
        assert all(m.id.startswith("M") for m in mitigations_for("T1027"))

    def test_a_mitigation_exposes_its_name_without_the_identifier(self):
        names = {m.name for m in mitigations_for("T1005")}
        assert "Data Loss Prevention" in names

    def test_lookup_is_case_insensitive(self):
        assert mitigations_for("t1027") == mitigations_for("T1027")

    def test_an_uncovered_subtechnique_inherits_its_parent_mitigations(self):
        assert mitigations_for("T1027.999") == mitigations_for("T1027")

    def test_an_unknown_technique_returns_no_mitigations(self):
        assert mitigations_for("T9999") == []


class TestCoveredTechniques:
    """Contract of `app.services.mitre.covered_techniques`."""

    def test_the_bundled_dataset_covers_at_least_one_technique(self):
        assert covered_techniques() > 0


class TestTTLCache:
    """Contract of `app.services.cache.TTLCache`."""

    async def test_a_stored_value_is_returned_on_the_next_read(self):
        cache = TTLCache(ttl_seconds=60)
        cache.set("k", {"v": 1})
        assert cache.get("k") == {"v": 1}

    async def test_an_unknown_key_reads_as_absent(self):
        assert TTLCache(ttl_seconds=60).get("missing") is None

    async def test_an_expired_entry_reads_as_absent(self):
        cache = TTLCache(ttl_seconds=0)
        cache.set("k", "v")
        await asyncio.sleep(0.01)
        assert cache.get("k") is None

    async def test_clearing_discards_stored_entries(self):
        cache = TTLCache(ttl_seconds=60)
        cache.set("k", "v")
        cache.clear()
        assert cache.get("k") is None

    async def test_a_first_fetch_reports_that_it_was_not_cached(self):
        cache = TTLCache(ttl_seconds=60)

        async def fetch():
            return "value"

        _, cached = await cache.get_or_fetch("k", fetch)
        assert cached is False

    async def test_a_repeat_fetch_reports_that_it_was_cached(self):
        cache = TTLCache(ttl_seconds=60)

        async def fetch():
            return "value"

        await cache.get_or_fetch("k", fetch)
        _, cached = await cache.get_or_fetch("k", fetch)
        assert cached is True

    async def test_a_repeat_fetch_returns_the_originally_stored_value(self):
        cache = TTLCache(ttl_seconds=60)
        calls = []

        async def fetch():
            calls.append(1)
            return f"value-{len(calls)}"

        await cache.get_or_fetch("k", fetch)
        value, _ = await cache.get_or_fetch("k", fetch)
        assert value == "value-1"

    async def test_concurrent_requests_for_one_key_share_a_single_fetch(self):
        cache = TTLCache(ttl_seconds=60)
        calls = []

        async def fetch():
            calls.append(1)
            await asyncio.sleep(0.01)
            return "value"

        await asyncio.gather(*(cache.get_or_fetch("k", fetch) for _ in range(5)))
        assert len(calls) == 1


class TestHistoryStore:
    """Contract of `app.services.history.HistoryStore`."""

    def test_a_recorded_report_is_returned_for_its_session(self, ip_attributes):
        store = HistoryStore()
        store.record("session-a", report_for("8.8.8.8", ip_attributes))
        assert [item.indicator for item in store.list("session-a")] == ["8.8.8.8"]

    def test_the_most_recent_lookup_is_listed_first(self, ip_attributes, domain_attributes):
        store = HistoryStore()
        store.record("s", report_for("8.8.8.8", ip_attributes))
        store.record("s", report_for("example.com", domain_attributes))
        assert store.list("s")[0].indicator == "example.com"

    def test_repeating_a_lookup_keeps_one_entry_for_that_indicator(self, ip_attributes):
        store = HistoryStore()
        store.record("s", report_for("8.8.8.8", ip_attributes))
        store.record("s", report_for("8.8.8.8", ip_attributes))
        assert len(store.list("s")) == 1

    def test_one_session_does_not_see_another_session_lookups(self, ip_attributes):
        store = HistoryStore()
        store.record("session-a", report_for("8.8.8.8", ip_attributes))
        assert store.list("session-b") == []

    def test_an_unused_session_starts_empty(self):
        assert HistoryStore().list("fresh") == []

    def test_clearing_reports_how_many_entries_were_removed(self, ip_attributes):
        store = HistoryStore()
        store.record("s", report_for("8.8.8.8", ip_attributes))
        assert store.clear("s") == 1

    def test_clearing_empties_the_session(self, ip_attributes):
        store = HistoryStore()
        store.record("s", report_for("8.8.8.8", ip_attributes))
        store.clear("s")
        assert store.list("s") == []

    def test_a_session_holds_no_more_than_its_configured_maximum(self, ip_attributes):
        store = HistoryStore(max_per_session=2)
        for octet in range(4):
            store.record("s", report_for(f"8.8.8.{octet}", ip_attributes))
        assert len(store.list("s")) == 2


class TestReportsToCsv:
    """Contract of `app.services.export.reports_to_csv`."""

    def header(self) -> list[str]:
        return reports_to_csv([]).splitlines()[0].split(",")

    def test_an_empty_export_still_emits_a_header_row(self):
        assert reports_to_csv([]).strip() != ""

    def test_the_header_names_the_indicator_column_first(self):
        assert self.header()[0] == "indicator"

    def test_one_row_is_emitted_per_indicator(self, ip_attributes, domain_attributes):
        csv_text = reports_to_csv(
            [
                report_for("8.8.8.8", ip_attributes),
                report_for("example.com", domain_attributes),
            ]
        )
        assert len(csv_text.strip().splitlines()) == 3

    def test_a_row_records_the_indicator(self, ip_attributes):
        csv_text = reports_to_csv([report_for("8.8.8.8", ip_attributes)])
        assert csv_text.splitlines()[1].startswith("8.8.8.8,ipv4,harmless")

    def test_a_file_row_summarises_its_type_and_threat_label(self, file_attributes):
        csv_text = reports_to_csv(
            [report_for("44d88612fea8a8f36de82e1278abb02f", file_attributes)]
        )
        assert "virus.eicar/test" in csv_text

    def test_a_file_row_names_the_first_flagging_vendor(self, file_attributes):
        csv_text = reports_to_csv(
            [report_for("44d88612fea8a8f36de82e1278abb02f", file_attributes)]
        )
        assert "Kaspersky: EICAR-Test-File" in csv_text

    def test_an_ip_row_summarises_its_autonomous_system(self, ip_attributes):
        assert "GOOGLE" in reports_to_csv([report_for("8.8.8.8", ip_attributes)])

    def test_a_domain_row_summarises_its_registrar(self, domain_attributes):
        csv_text = reports_to_csv([report_for("example.com", domain_attributes)])
        assert "MarkMonitor Inc." in csv_text

    def test_tags_are_joined_into_a_single_cell(self, file_attributes):
        csv_text = reports_to_csv(
            [report_for("44d88612fea8a8f36de82e1278abb02f", file_attributes)]
        )
        assert '"via-tor, attachment"' in csv_text


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Keep these tests offline by refusing outbound HTTP."""
    import httpx

    async def refuse(*_args, **_kwargs):
        raise AssertionError("These tests must not perform network calls.")

    monkeypatch.setattr(httpx.AsyncClient, "get", refuse)
