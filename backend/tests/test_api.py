import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.dependencies import get_history, get_service
from app.main import app
from app.services.history import HistoryStore
from app.services.intel import IntelService

from .conftest import BEHAVIOUR_SUMMARY, DOMAIN_ATTRIBUTES, FILE_ATTRIBUTES, MITRE_TREES

VT = "https://www.virustotal.com/api/v3"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture
def settings() -> Settings:
    """Settings with a VirusTotal credential and caching enabled."""
    return Settings(VT_API_KEY="test-key", cache_ttl_seconds=300)


@pytest.fixture
def client(settings) -> TestClient:
    """A client whose service and history are isolated to a single test."""
    service = IntelService(settings)
    history = HistoryStore()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_history] = lambda: history
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def vt_object(attributes: dict) -> httpx.Response:
    return httpx.Response(200, json={"data": {"attributes": attributes}})


class TestHealthEndpoint:
    """Contract of `GET /api/health`."""

    def test_a_configured_service_reports_itself_healthy(self, client):
        assert client.get("/api/health").json()["status"] == "ok"

    def test_virustotal_is_reported_as_configured_when_a_key_is_present(self, client):
        providers = {p["name"]: p for p in client.get("/api/health").json()["providers"]}
        assert providers["VirusTotal"]["configured"] is True

    def test_abuseipdb_is_reported_as_unconfigured_without_a_key(self, client):
        providers = {p["name"]: p for p in client.get("/api/health").json()["providers"]}
        assert providers["AbuseIPDB"]["configured"] is False

    def test_a_service_without_a_virustotal_key_reports_itself_degraded(self):
        app.dependency_overrides[get_settings] = lambda: Settings(VT_API_KEY="")
        with TestClient(app) as unconfigured:
            assert unconfigured.get("/api/health").json()["status"] == "degraded"
        app.dependency_overrides.clear()


class TestLookupEndpoint:
    """Contract of `GET /api/lookup`."""

    @respx.mock
    def test_a_known_file_hash_returns_its_report(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        assert client.get("/api/lookup", params={"indicator": EICAR_MD5}).status_code == 200

    @respx.mock
    def test_a_known_file_hash_is_reported_as_malicious(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        body = client.get("/api/lookup", params={"indicator": EICAR_MD5}).json()
        assert body["verdict"] == "malicious"

    @respx.mock
    def test_a_defanged_domain_is_looked_up_in_its_refanged_form(self, client):
        route = respx.get(f"{VT}/domains/example.com").mock(
            return_value=vt_object(DOMAIN_ATTRIBUTES)
        )
        client.get("/api/lookup", params={"indicator": "example[.]com"})
        assert route.called

    @respx.mock
    def test_a_lookup_costs_exactly_one_upstream_request(self, client):
        route = respx.get(f"{VT}/files/{EICAR_MD5}").mock(
            return_value=vt_object(FILE_ATTRIBUTES)
        )
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert route.call_count == 1

    @respx.mock
    def test_a_repeated_lookup_is_served_without_a_second_upstream_request(self, client):
        route = respx.get(f"{VT}/files/{EICAR_MD5}").mock(
            return_value=vt_object(FILE_ATTRIBUTES)
        )
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert route.call_count == 1

    @respx.mock
    def test_a_repeated_lookup_is_flagged_as_cached(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        body = client.get("/api/lookup", params={"indicator": EICAR_MD5}).json()
        assert body["cached"] is True

    @respx.mock
    def test_an_indicator_unknown_to_virustotal_returns_not_found(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=httpx.Response(404, json={}))
        response = client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert response.status_code == 404

    @respx.mock
    def test_an_exhausted_quota_returns_too_many_requests(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=httpx.Response(429, json={}))
        response = client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert response.status_code == 429

    @respx.mock
    def test_an_exhausted_quota_explains_the_free_tier_limit(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=httpx.Response(429, json={}))
        detail = client.get("/api/lookup", params={"indicator": EICAR_MD5}).json()["detail"]
        assert "4 lookups per minute" in detail

    @respx.mock
    def test_a_rejected_credential_names_the_setting_to_fix(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=httpx.Response(401, json={}))
        detail = client.get("/api/lookup", params={"indicator": EICAR_MD5}).json()["detail"]
        assert "VT_API_KEY" in detail

    @respx.mock
    def test_an_unreachable_provider_returns_bad_gateway(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(side_effect=httpx.ConnectError("down"))
        response = client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert response.status_code == 502

    def test_an_unrecognised_indicator_returns_unprocessable_content(self, client):
        response = client.get("/api/lookup", params={"indicator": "hello world"})
        assert response.status_code == 422

    def test_a_missing_virustotal_key_returns_service_unavailable(self):
        unconfigured = Settings(VT_API_KEY="")
        app.dependency_overrides[get_settings] = lambda: unconfigured
        app.dependency_overrides[get_service] = lambda: IntelService(unconfigured)
        with TestClient(app) as test_client:
            response = test_client.get("/api/lookup", params={"indicator": EICAR_MD5})
        app.dependency_overrides.clear()
        assert response.status_code == 503


class TestBehaviourEndpoint:
    """Contract of `GET /api/behaviour`."""

    @respx.mock
    def test_a_file_hash_returns_its_sandbox_behaviour(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}/behaviour_summary").mock(
            return_value=httpx.Response(200, json={"data": BEHAVIOUR_SUMMARY})
        )
        respx.get(f"{VT}/files/{EICAR_MD5}/behaviour_mitre_trees").mock(
            return_value=httpx.Response(200, json={"data": MITRE_TREES})
        )
        response = client.get("/api/behaviour", params={"indicator": EICAR_MD5})
        assert response.json()["processes_created"] == ["C:\\Windows\\system32\\cmd.exe"]

    @respx.mock
    def test_observed_techniques_carry_their_attack_mitigations(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}/behaviour_summary").mock(
            return_value=httpx.Response(200, json={"data": BEHAVIOUR_SUMMARY})
        )
        respx.get(f"{VT}/files/{EICAR_MD5}/behaviour_mitre_trees").mock(
            return_value=httpx.Response(200, json={"data": MITRE_TREES})
        )
        body = client.get("/api/behaviour", params={"indicator": EICAR_MD5}).json()
        technique = body["mitre"][0]["tactics"][0]["techniques"][0]
        assert technique["mitigations"]

    def test_an_ip_address_is_rejected_as_having_no_sandbox_behaviour(self, client):
        response = client.get("/api/behaviour", params={"indicator": "8.8.8.8"})
        assert response.status_code == 400


class TestRelationsEndpoint:
    """Contract of `GET /api/relations`."""

    @respx.mock
    def test_a_file_returns_the_domains_it_contacted(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}/contacted_domains").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "c2.example",
                            "attributes": {"last_analysis_stats": {"malicious": 9}},
                        }
                    ]
                },
            )
        )
        body = client.get("/api/relations", params={"indicator": EICAR_MD5}).json()
        assert body["items"][0]["indicator"] == "c2.example"

    @respx.mock
    def test_a_domain_returns_its_observed_resolutions(self, client):
        respx.get(f"{VT}/domains/example.com/resolutions").mock(
            return_value=httpx.Response(
                200, json={"data": [{"id": "r", "attributes": {"ip_address": "1.2.3.4"}}]}
            )
        )
        body = client.get("/api/relations", params={"indicator": "example.com"}).json()
        assert body["items"][0]["indicator"] == "1.2.3.4"

    def test_a_url_reports_that_it_has_no_relation_to_follow(self, client):
        body = client.get(
            "/api/relations", params={"indicator": "https://example.com/a"}
        ).json()
        assert body["relation"] == "none"


class TestHistoryEndpoint:
    """Contract of `GET /api/history` and its companions."""

    @respx.mock
    def test_a_lookup_is_recorded_in_the_session_history(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert client.get("/api/history").json()[0]["indicator"] == EICAR_MD5

    def test_a_fresh_session_has_an_empty_history(self, client):
        assert client.get("/api/history").json() == []

    @respx.mock
    def test_clearing_reports_how_many_entries_were_removed(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert client.delete("/api/history").json() == {"removed": 1}

    @respx.mock
    def test_a_cleared_history_reads_as_empty(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        client.delete("/api/history")
        assert client.get("/api/history").json() == []

    @respx.mock
    def test_the_export_is_served_as_a_csv_attachment(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        response = client.get("/api/history/export.csv")
        assert response.headers["content-disposition"] == (
            'attachment; filename="ioc-hunter-export.csv"'
        )

    @respx.mock
    def test_the_export_contains_a_row_for_each_looked_up_indicator(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert EICAR_MD5 in client.get("/api/history/export.csv").text

    def test_exporting_an_empty_history_returns_not_found(self, client):
        assert client.get("/api/history/export.csv").status_code == 404


class TestSessionIsolation:
    """Contract of the session cookie that history is keyed by."""

    @respx.mock
    def test_a_first_request_is_issued_a_session_cookie(self, client):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        response = client.get("/api/lookup", params={"indicator": EICAR_MD5})
        assert "ioc_hunter_session" in response.cookies

    @respx.mock
    def test_a_different_session_does_not_see_another_session_history(self, client, settings):
        respx.get(f"{VT}/files/{EICAR_MD5}").mock(return_value=vt_object(FILE_ATTRIBUTES))
        client.get("/api/lookup", params={"indicator": EICAR_MD5})
        with TestClient(app) as other:
            assert other.get("/api/history").json() == []


class TestClassifyEndpoint:
    """Contract of `GET /api/classify`."""

    def test_a_hash_is_reported_with_its_digest_type(self, client):
        body = client.get("/api/classify", params={"indicator": EICAR_MD5}).json()
        assert body["ioc_type"] == "md5"

    def test_a_hash_is_reported_as_belonging_to_the_file_family(self, client):
        body = client.get("/api/classify", params={"indicator": EICAR_MD5}).json()
        assert body["family"] == "file"

    def test_a_defanged_url_is_reported_in_its_refanged_form(self, client):
        body = client.get(
            "/api/classify", params={"indicator": "hxxps://evil[.]com/a"}
        ).json()
        assert body["indicator"] == "https://evil.com/a"

    def test_classification_reaches_no_provider(self, client):
        with respx.mock:
            client.get("/api/classify", params={"indicator": EICAR_MD5})
            assert not respx.calls
