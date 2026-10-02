"""
Integration tests for the PrivacyFire Proxy API.
Tests the full request pipeline without making real LLM API calls.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from api.proxy import app, scan_text

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_scan_endpoint_with_pii():
    response = client.get("/v1/scan", params={
        "text": "Contact john.smith@example.com or call 07799 123456"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["pii_found"] is True
    assert "john.smith@example.com" not in data["redacted_text"]
    assert data["total_instances"] >= 2


def test_scan_endpoint_no_pii():
    response = client.get("/v1/scan", params={
        "text": "The weather is nice today in the city."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["pii_found"] is False


def test_audit_log_empty():
    response = client.get("/v1/audit")
    assert response.status_code == 200
    data = response.json()
    assert "entries" in data
    assert "total" in data


def test_proxy_request_with_mocked_anthropic():
    with patch("api.proxy.call_anthropic", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "I can help [PERSON_1] with their request."

        response = client.post("/v1/proxy", json={
            "model": "claude-sonnet-4-6",
            "provider": "anthropic",
            "messages": [
                {
                    "role": "user",
                    "content": "My name is John Smith and my email is john@test.com. Help me."
                }
            ]
        })

        assert response.status_code == 200
        data = response.json()

        # PII should have been detected
        assert data["pii_summary"]["redacted"] is True
        assert data["pii_summary"]["total_instances"] >= 1

        # Response should have been processed
        assert "audit_id" in data
        assert data["latency_ms"] > 0

        # Verify LLM was called with redacted content
        call_args = mock_llm.call_args
        redacted_messages = call_args[0][0]
        message_content = redacted_messages[0]["content"]
        assert "John Smith" not in message_content
        assert "john@test.com" not in message_content


def test_proxy_unknown_provider():
    response = client.post("/v1/proxy", json={
        "model": "some-model",
        "provider": "unknown_provider",
        "messages": [{"role": "user", "content": "Hello"}]
    })
    assert response.status_code == 400


def test_audit_summary_after_requests():
    with patch("api.proxy.call_anthropic", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "Response here."

        client.post("/v1/proxy", json={
            "model": "claude-sonnet-4-6",
            "provider": "anthropic",
            "messages": [{"role": "user", "content": "My email is test@example.com"}]
        })

    response = client.get("/v1/audit/summary")
    assert response.status_code == 200
    data = response.json()
    assert data.get("sensitive_data_transmitted_to_llm") is False
