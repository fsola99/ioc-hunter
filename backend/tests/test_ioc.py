import pytest

from app.ioc import IoCType, UnrecognizedIoCError, classify, refang


class TestRefang:
    """Contract of `app.ioc.refang`."""

    def test_bracketed_dot_becomes_a_real_dot(self):
        assert refang("evil[.]com") == "evil.com"

    def test_parenthesised_dot_becomes_a_real_dot(self):
        assert refang("evil(.)com") == "evil.com"

    def test_spelled_out_dot_becomes_a_real_dot(self):
        assert refang("evil[dot]com") == "evil.com"

    def test_neutered_https_scheme_is_restored(self):
        assert refang("hxxps://evil.com/a") == "https://evil.com/a"

    def test_neutered_http_scheme_is_restored(self):
        assert refang("hxxp://evil.com/a") == "http://evil.com/a"

    def test_bracketed_colon_becomes_a_real_colon(self):
        assert refang("http[:]//evil.com") == "http://evil.com"

    def test_surrounding_quotes_are_removed(self):
        assert refang('"evil.com"') == "evil.com"

    def test_already_clean_input_is_returned_unchanged(self):
        assert refang("https://example.com/path") == "https://example.com/path"


class TestClassify:
    """Contract of `app.ioc.classify`."""

    def test_thirty_two_hex_characters_classify_as_md5(self):
        assert classify("44d88612fea8a8f36de82e1278abb02f").type is IoCType.MD5

    def test_forty_hex_characters_classify_as_sha1(self):
        assert classify("3395856ce81f2b7382dee72602f798b642f14140").type is IoCType.SHA1

    def test_sixty_four_hex_characters_classify_as_sha256(self):
        digest = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert classify(digest).type is IoCType.SHA256

    def test_uppercase_hash_is_normalised_to_lowercase(self):
        assert classify("44D88612FEA8A8F36DE82E1278ABB02F").value == (
            "44d88612fea8a8f36de82e1278abb02f"
        )

    def test_dotted_quad_classifies_as_ipv4(self):
        assert classify("8.8.8.8").type is IoCType.IPV4

    def test_compressed_address_classifies_as_ipv6(self):
        assert classify("2001:4860:4860::8888").type is IoCType.IPV6

    def test_hostname_classifies_as_domain(self):
        assert classify("example.com").type is IoCType.DOMAIN

    def test_multi_label_hostname_classifies_as_domain(self):
        assert classify("mail.corp.example.co.uk").type is IoCType.DOMAIN

    def test_www_prefix_is_stripped_from_a_domain(self):
        assert classify("www.example.com").value == "example.com"

    def test_trailing_root_dot_is_stripped_from_a_domain(self):
        assert classify("example.com.").value == "example.com"

    def test_url_with_a_path_classifies_as_url(self):
        assert classify("https://example.com/download.exe").type is IoCType.URL

    def test_url_with_a_query_string_classifies_as_url(self):
        assert classify("https://example.com/?id=1").type is IoCType.URL

    def test_bare_http_root_classifies_as_the_domain_it_names(self):
        assert classify("https://example.com").type is IoCType.DOMAIN

    def test_host_with_a_path_and_no_scheme_classifies_as_url(self):
        assert classify("example.com/payload.bin").type is IoCType.URL

    def test_host_with_a_path_and_no_scheme_gains_an_http_scheme(self):
        assert classify("example.com/payload.bin").value == "http://example.com/payload.bin"

    def test_defanged_domain_classifies_as_domain(self):
        assert classify("evil[.]com").type is IoCType.DOMAIN

    def test_defanged_domain_is_refanged_in_the_query_value(self):
        assert classify("evil[.]com").value == "evil.com"

    def test_defanged_ip_classifies_as_ipv4(self):
        assert classify("192.168.1[.]1").type is IoCType.IPV4

    def test_defanged_url_classifies_as_url(self):
        assert classify("hxxps://evil[.]com/drop.php").type is IoCType.URL

    def test_raw_input_is_preserved_alongside_the_normalised_value(self):
        assert classify("  evil[.]com  ").raw == "evil[.]com"

    def test_surrounding_whitespace_does_not_affect_the_value(self):
        assert classify("  8.8.8.8  ").value == "8.8.8.8"

    def test_empty_input_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("   ")

    def test_free_text_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("this is not an indicator")

    def test_hash_of_the_wrong_length_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("44d88612fea8a8f36de82e1278abb02")

    def test_non_hex_string_of_hash_length_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("z4d88612fea8a8f36de82e1278abb02f")

    def test_single_label_hostname_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("localhost")

    def test_numeric_tld_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("999.999.999.999")

    def test_scheme_without_a_host_is_rejected(self):
        with pytest.raises(UnrecognizedIoCError):
            classify("http://")


class TestIoCTypeFamily:
    """Contract of `app.ioc.IoCType.family`."""

    def test_md5_belongs_to_the_file_family(self):
        assert IoCType.MD5.family == "file"

    def test_sha256_belongs_to_the_file_family(self):
        assert IoCType.SHA256.family == "file"

    def test_ipv6_belongs_to_the_ip_family(self):
        assert IoCType.IPV6.family == "ip"

    def test_domain_belongs_to_the_domain_family(self):
        assert IoCType.DOMAIN.family == "domain"

    def test_url_belongs_to_the_url_family(self):
        assert IoCType.URL.family == "url"
