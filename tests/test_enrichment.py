"""Unit tests for external enrichment tools (mocked HTTP calls)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


def _mock_httpx_get(response_data: dict, status_code: int = 200):
    mock = MagicMock()
    mock.status_code = status_code
    mock.raise_for_status = MagicMock()
    mock.json.return_value = response_data
    return mock


def _mock_httpx_post(response_data: dict, status_code: int = 200):
    mock = MagicMock()
    mock.status_code = status_code
    mock.raise_for_status = MagicMock()
    mock.json.return_value = response_data
    return mock


class TestLookupIpReputation:
    def test_abuseipdb_returns_abuse_score(self, monkeypatch):
        monkeypatch.setenv("ABUSE_IPDB_KEY", "test-key")
        resp_data = {"data": {
            "abuseConfidenceScore": 85,
            "countryCode": "RU",
            "isp": "Evil Corp",
            "totalReports": 42,
            "isTor": False,
        }}
        with patch("httpx.get", return_value=_mock_httpx_get(resp_data)):
            from tengen.tools.enrichment import lookup_ip_reputation
            result = json.loads(lookup_ip_reputation("1.2.3.4"))
        assert result["abuse_score"] == 85
        assert result["country"] == "RU"
        assert result["source"] == "abuseipdb"

    def test_virustotal_fallback(self, monkeypatch):
        monkeypatch.delenv("ABUSE_IPDB_KEY", raising=False)
        monkeypatch.setenv("VT_API_KEY", "vt-key")
        resp_data = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 5, "harmless": 65, "suspicious": 2, "undetected": 0},
            "country": "CN",
            "as_owner": "Some ISP",
        }}}
        with patch("httpx.get", return_value=_mock_httpx_get(resp_data)):
            from tengen.tools.enrichment import lookup_ip_reputation
            result = json.loads(lookup_ip_reputation("5.6.7.8"))
        assert result["source"] == "virustotal"
        assert result["total_reports"] == 5

    def test_no_api_key_returns_error(self, monkeypatch):
        monkeypatch.delenv("ABUSE_IPDB_KEY", raising=False)
        monkeypatch.delenv("VT_API_KEY", raising=False)
        from tengen.tools.enrichment import lookup_ip_reputation
        result = json.loads(lookup_ip_reputation("1.2.3.4"))
        assert "error" in result

    def test_network_failure_returns_error(self, monkeypatch):
        monkeypatch.setenv("ABUSE_IPDB_KEY", "test-key")
        with patch("httpx.get", side_effect=Exception("connection refused")):
            from tengen.tools.enrichment import lookup_ip_reputation
            result = json.loads(lookup_ip_reputation("1.2.3.4"))
        assert "error" in result


class TestLookupIpGeo:
    def test_returns_geo_data(self):
        resp_data = {
            "city": "Moscow",
            "region": "Moscow",
            "country": "RU",
            "org": "AS12345 Evil Corp",
            "timezone": "Europe/Moscow",
            "loc": "55.7558,37.6173",
        }
        with patch("httpx.get", return_value=_mock_httpx_get(resp_data)):
            from tengen.tools.enrichment import lookup_ip_geo
            result = json.loads(lookup_ip_geo("1.2.3.4"))
        assert result["city"] == "Moscow"
        assert result["country"] == "RU"
        assert result["ip"] == "1.2.3.4"

    def test_network_failure_returns_error(self):
        with patch("httpx.get", side_effect=Exception("timeout")):
            from tengen.tools.enrichment import lookup_ip_geo
            result = json.loads(lookup_ip_geo("1.2.3.4"))
        assert "error" in result


class TestLookupFileHash:
    def test_malicious_hash_detected(self, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "vt-key")
        resp_data = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 32, "suspicious": 3, "harmless": 5, "undetected": 10},
            "names": ["ransomware.exe", "evil.exe"],
            "tags": ["ransomware", "crypto"],
            "type_description": "Win32 EXE",
        }}}
        with patch("httpx.get", return_value=_mock_httpx_get(resp_data)):
            from tengen.tools.enrichment import lookup_file_hash
            result = json.loads(lookup_file_hash("abc123" * 10 + "ab"))
        assert result["malicious"] == 32
        assert "ransomware" in result["tags"]

    def test_no_api_key_returns_error(self, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        from tengen.tools.enrichment import lookup_file_hash
        result = json.loads(lookup_file_hash("abc123"))
        assert "error" in result


class TestLookupUserContext:
    def test_okta_returns_user_info(self, monkeypatch):
        monkeypatch.setenv("OKTA_API_TOKEN", "okta-token")
        monkeypatch.setenv("OKTA_DOMAIN", "example.okta.com")
        resp_data = {
            "id": "user123",
            "status": "ACTIVE",
            "lastLogin": "2024-01-15T10:00:00Z",
            "profile": {
                "email": "alice@example.com",
                "firstName": "Alice",
                "lastName": "Smith",
                "department": "Engineering",
                "title": "SRE",
            },
            "credentials": {"factors": [{"type": "token:software:totp"}]},
        }
        with patch("httpx.get", return_value=_mock_httpx_get(resp_data)):
            from tengen.tools.enrichment import lookup_user_context
            result = json.loads(lookup_user_context("alice@example.com"))
        assert result["source"] == "okta"
        assert result["display_name"] == "Alice Smith"
        assert result["department"] == "Engineering"
        assert result["account_enabled"] is True

    def test_no_provider_configured_returns_error(self, monkeypatch):
        monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
        monkeypatch.delenv("OKTA_DOMAIN", raising=False)
        monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
        from tengen.tools.enrichment import lookup_user_context
        result = json.loads(lookup_user_context("alice@example.com"))
        assert "error" in result
