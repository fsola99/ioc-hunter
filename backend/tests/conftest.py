import pytest

FILE_ATTRIBUTES = {
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "size": 68,
    "type_description": "EICAR virus test files",
    "magic": "EICAR virus test files",
    "names": ["eicar.com", "eicar.txt"],
    "tags": ["via-tor", "attachment"],
    "reputation": -14,
    "total_votes": {"harmless": 3, "malicious": 91},
    "first_submission_date": 1136189359,
    "last_submission_date": 1700000000,
    "last_analysis_date": 1700000500,
    "last_analysis_stats": {
        "malicious": 62,
        "suspicious": 1,
        "harmless": 0,
        "undetected": 8,
        "timeout": 1,
        "confirmed-timeout": 1,
    },
    "last_analysis_results": {
        "Undetected1": {"category": "undetected", "result": None},
        "Kaspersky": {
            "category": "malicious",
            "result": "EICAR-Test-File",
            "engine_version": "22.0",
            "engine_update": "20260101",
        },
        "Avast": {"category": "suspicious", "result": "Heur.Susp"},
        "CleanVendor": {"category": "harmless", "result": None},
    },
    "popular_threat_classification": {
        "suggested_threat_label": "virus.eicar/test",
        "popular_threat_category": [{"value": "virus"}, {"value": "trojan"}],
    },
    "signature_info": {"verified": "Signed", "signers": "Example Corp"},
}

IP_ATTRIBUTES = {
    "asn": 15169,
    "as_owner": "GOOGLE",
    "country": "US",
    "continent": "NA",
    "network": "8.8.8.0/24",
    "regional_internet_registry": "ARIN",
    "jarm": "29d3fd00029d29d00042d43d00041d",
    "reputation": 4,
    "total_votes": {"harmless": 60, "malicious": 4},
    "tags": [],
    "last_modification_date": 1700000000,
    "last_analysis_date": 1700000200,
    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20},
    "last_analysis_results": {},
}

DOMAIN_ATTRIBUTES = {
    "registrar": "MarkMonitor Inc.",
    "creation_date": 874306800,
    "last_update_date": 1600000000,
    "expiration_date": 1900000000,
    "categories": {"Forcepoint": "search engines", "Sophos": "search engines"},
    "last_dns_records": [
        {"type": "A", "value": "142.250.185.14", "ttl": 300},
        {"type": "MX", "value": "smtp.example.com", "ttl": 600},
        {"type": "TXT", "value": "", "ttl": 300},
    ],
    "popularity_ranks": {"Cisco Umbrella": {"rank": 1}, "Broken": {"rank": "n/a"}},
    "reputation": 120,
    "total_votes": {"harmless": 200, "malicious": 2},
    "tags": [],
    "last_modification_date": 1700000000,
    "last_analysis_stats": {"malicious": 0, "suspicious": 1, "harmless": 65, "undetected": 20},
    "last_analysis_results": {},
}

URL_ATTRIBUTES = {
    "last_final_url": "https://example.com/landing",
    "title": "Example Landing",
    "last_http_response_code": 200,
    "last_http_response_content_type": "text/html",
    "categories": {"Sophos": "phishing"},
    "outgoing_links": ["https://example.com/a", "https://example.com/b"],
    "reputation": -3,
    "total_votes": {"harmless": 0, "malicious": 5},
    "tags": ["phishing"],
    "first_submission_date": 1690000000,
    "last_submission_date": 1700000000,
    "last_analysis_stats": {"malicious": 6, "suspicious": 0, "harmless": 60, "undetected": 10},
    "last_analysis_results": {},
}

MITRE_TREES = {
    "Zenbox": {
        "tactics": [
            {
                "id": "TA0005",
                "name": "Defense Evasion",
                "link": "https://attack.mitre.org/tactics/TA0005/",
                "techniques": [
                    {
                        "id": "T1027",
                        "name": "Obfuscated Files or Information",
                        "description": "Packed binary.",
                        "link": "https://attack.mitre.org/techniques/T1027/",
                        "signatures": [
                            {"severity": "IMPACT_SEVERITY_HIGH", "description": "Packed"},
                            {"severity": "IMPACT_SEVERITY_HIGH", "description": "Obfuscated"},
                        ],
                    }
                ],
            }
        ]
    }
}

BEHAVIOUR_SUMMARY = {
    "processes_created": ["C:\\Windows\\system32\\cmd.exe"],
    "services_started": ["WinDefend"],
    "mutexes_created": ["Global\\abc"],
    "files_opened": ["C:\\temp\\a.txt"],
    "registry_keys_opened": ["HKLM\\Software\\Run"],
    "modules_loaded": ["kernel32.dll"],
    "processes_terminated": ["taskmgr.exe"],
    "dns_lookups": [
        {"hostname": "c2.example.com", "resolved_ips": ["1.2.3.4"]},
        {"resolved_ips": ["5.6.7.8"]},
    ],
}


@pytest.fixture
def file_attributes() -> dict:
    """VirusTotal attributes for a file object."""
    return dict(FILE_ATTRIBUTES)


@pytest.fixture
def ip_attributes() -> dict:
    """VirusTotal attributes for an IP address object."""
    return dict(IP_ATTRIBUTES)


@pytest.fixture
def domain_attributes() -> dict:
    """VirusTotal attributes for a domain object."""
    return dict(DOMAIN_ATTRIBUTES)


@pytest.fixture
def url_attributes() -> dict:
    """VirusTotal attributes for a URL object."""
    return dict(URL_ATTRIBUTES)
