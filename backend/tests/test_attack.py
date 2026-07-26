from fastapi.testclient import TestClient

from app.main import app
from app.services import attack

client = TestClient(app)


class TestTechnique:
    """Contract of `app.services.attack.technique`."""

    def test_a_known_technique_is_returned(self):
        assert attack.technique("T1027") is not None

    def test_a_technique_carries_its_name(self):
        assert attack.technique("T1027").name == "Obfuscated Files or Information"

    def test_lookup_is_case_insensitive(self):
        assert attack.technique("t1027") == attack.technique("T1027")

    def test_a_top_level_technique_reports_no_parent(self):
        assert attack.technique("T1027").parent is None

    def test_a_subtechnique_names_its_parent(self):
        assert attack.technique("T1027.002").parent == "T1027"

    def test_a_subtechnique_is_flagged_as_one(self):
        assert attack.technique("T1027.002").is_subtechnique is True

    def test_a_technique_lists_the_platforms_it_applies_to(self):
        assert "Windows" in attack.technique("T1027").platforms

    def test_a_technique_belongs_to_at_least_one_tactic(self):
        assert attack.technique("T1027").tactics

    def test_a_technique_links_to_its_attack_page(self):
        assert attack.technique("T1027").url.startswith("https://attack.mitre.org/")

    def test_an_unknown_identifier_returns_nothing(self):
        assert attack.technique("T9999") is None


class TestDescriptions:
    """Contract of the prose stored in the bundled catalogue."""

    def test_descriptions_carry_no_markdown_links(self):
        matrix = attack.matrix()
        offenders = [
            entry.id
            for tactic in matrix.tactics
            for entry in tactic.techniques
            if "](http" in (attack.technique(entry.id).description or "")
        ]
        assert offenders == []

    def test_descriptions_carry_no_citation_markers(self):
        matrix = attack.matrix()
        offenders = [
            entry.id
            for tactic in matrix.tactics
            for entry in tactic.techniques
            if "(Citation:" in (attack.technique(entry.id).description or "")
        ]
        assert offenders == []


class TestSubtechniquesOf:
    """Contract of `app.services.attack.subtechniques_of`."""

    def test_a_technique_with_children_lists_them(self):
        assert attack.subtechniques_of("T1027")

    def test_every_child_names_the_requested_parent(self):
        children = attack.subtechniques_of("T1027")
        assert all(child.parent == "T1027" for child in children)

    def test_children_are_returned_in_identifier_order(self):
        ids = [child.id for child in attack.subtechniques_of("T1027")]
        assert ids == sorted(ids)

    def test_a_technique_without_children_returns_an_empty_list(self):
        assert attack.subtechniques_of("T1027.002") == []


class TestMatrix:
    """Contract of `app.services.attack.matrix`."""

    def test_the_matrix_opens_with_reconnaissance(self):
        assert attack.matrix().tactics[0].id == "TA0043"

    def test_every_tactic_column_is_present(self):
        assert len(attack.matrix().tactics) == 15

    def test_the_matrix_holds_only_top_level_techniques(self):
        entries = [entry for tactic in attack.matrix().tactics for entry in tactic.techniques]
        assert all("." not in entry.id for entry in entries)

    def test_a_cell_reports_how_many_subtechniques_it_has(self):
        cells = {
            entry.id: entry
            for tactic in attack.matrix().tactics
            for entry in tactic.techniques
        }
        assert cells["T1027"].subtechnique_count == len(attack.subtechniques_of("T1027"))

    def test_the_available_platforms_are_listed(self):
        assert "Windows" in attack.matrix().platforms

    def test_a_text_filter_narrows_the_technique_count(self):
        assert attack.matrix(query="obfuscat").technique_count < attack.matrix().technique_count

    def test_a_text_filter_matches_a_technique_name(self):
        ids = {
            entry.id
            for tactic in attack.matrix(query="obfuscated files").tactics
            for entry in tactic.techniques
        }
        assert "T1027" in ids

    def test_a_text_filter_matches_a_technique_identifier(self):
        ids = {
            entry.id
            for tactic in attack.matrix(query="T1027").tactics
            for entry in tactic.techniques
        }
        assert "T1027" in ids

    def test_a_subtechnique_match_surfaces_its_parent(self):
        ids = {
            entry.id
            for tactic in attack.matrix(query="software packing").tactics
            for entry in tactic.techniques
        }
        assert "T1027" in ids

    def test_a_platform_filter_keeps_only_techniques_for_that_platform(self):
        entries = [
            entry
            for tactic in attack.matrix(platform="Linux").tactics
            for entry in tactic.techniques
        ]
        assert all("Linux" in entry.platforms for entry in entries)

    def test_an_unmatched_filter_yields_no_techniques(self):
        assert attack.matrix(query="zzzznotatechnique").technique_count == 0


class TestMitigationsFromCatalogue:
    """Contract of `app.services.attack.mitigations_for` against the bundled data."""

    def test_a_technique_with_mitigations_returns_them(self):
        assert mitigation_ids("T1027")

    def test_a_mitigation_carries_an_attack_identifier(self):
        assert all(identifier.startswith("M") for identifier in mitigation_ids("T1027"))

    def test_a_subtechnique_without_its_own_mitigations_inherits_the_parent_set(self):
        assert mitigation_ids("T1027.003") == mitigation_ids("T1027")

    def test_an_unknown_technique_returns_no_mitigations(self):
        assert attack.mitigations_for("T9999") == []


def mitigation_ids(technique_id: str) -> list[str]:
    return [item.id for item in attack.mitigations_for(technique_id)]


class TestMatrixEndpoint:
    """Contract of `GET /api/attack/matrix`."""

    def test_the_matrix_is_served(self):
        assert client.get("/api/attack/matrix").status_code == 200

    def test_the_matrix_reports_how_many_techniques_it_holds(self):
        assert client.get("/api/attack/matrix").json()["technique_count"] > 0

    def test_a_text_filter_is_applied(self):
        body = client.get("/api/attack/matrix", params={"q": "T1027"}).json()
        ids = {t["id"] for tactic in body["tactics"] for t in tactic["techniques"]}
        assert ids == {"T1027"}

    def test_a_platform_filter_is_applied(self):
        body = client.get("/api/attack/matrix", params={"platform": "Linux"}).json()
        entries = [t for tactic in body["tactics"] for t in tactic["techniques"]]
        assert all("Linux" in t["platforms"] for t in entries)


class TestTechniqueEndpoint:
    """Contract of `GET /api/attack/techniques/{id}`."""

    def test_a_known_technique_is_served(self):
        assert client.get("/api/attack/techniques/T1027").status_code == 200

    def test_the_response_names_the_tactics_the_technique_belongs_to(self):
        body = client.get("/api/attack/techniques/T1027").json()
        assert body["tactic_names"]

    def test_the_response_includes_the_subtechniques(self):
        body = client.get("/api/attack/techniques/T1027").json()
        assert len(body["subtechniques"]) > 0

    def test_a_subtechnique_response_includes_its_parent(self):
        body = client.get("/api/attack/techniques/T1027.002").json()
        assert body["parent"]["id"] == "T1027"

    def test_an_unknown_technique_returns_not_found(self):
        assert client.get("/api/attack/techniques/T9999").status_code == 404


class TestCatalogueExport:
    """Contract of `GET /api/attack/export.csv`."""

    def test_the_export_is_served_as_an_attachment(self):
        response = client.get("/api/attack/export.csv")
        assert response.headers["content-disposition"] == (
            'attachment; filename="attack-techniques.csv"'
        )

    def test_the_export_names_the_identifier_column_first(self):
        header = client.get("/api/attack/export.csv").text.splitlines()[0]
        assert header.startswith("id,name,tactics,platforms")

    def test_the_export_holds_one_row_per_technique_and_subtechnique(self):
        rows = client.get("/api/attack/export.csv").text.strip().splitlines()
        assert len(rows) >= attack.catalogue_size()

    def test_the_export_resolves_tactic_identifiers_to_names(self):
        assert "Stealth" in client.get("/api/attack/export.csv").text

    def test_the_export_includes_subtechniques(self):
        assert "T1027.002" in client.get("/api/attack/export.csv").text
