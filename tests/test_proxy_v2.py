"""
Tests for Jnvoy Proxy v2 with intelligence layer wired in.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from api.proxy_v2 import app, semantic_cache

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "2.0.0"
    assert "providers" in data
    assert "cache" in data


def test_scan_endpoint_with_pii():
    response = client.get("/v1/scan", params={
        "text": "Contact john.smith@example.com or call +44 7700 900123"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["pii_found"] is True
    assert data["sensitive_data_transmitted"] is False


def test_scan_endpoint_no_pii():
    response = client.get("/v1/scan", params={"text": "Hello how are you today"})
    assert response.status_code == 200


def test_cache_stats_endpoint():
    response = client.get("/v1/cache/stats")
    assert response.status_code == 200
    data = response.json()
    assert "cache_hits" in data
    assert "cache_misses" in data
    assert "hit_rate_percent" in data


def test_providers_health_endpoint():
    response = client.get("/v1/providers/health")
    assert response.status_code == 200


def test_audit_log_empty():
    response = client.get("/v1/audit")
    assert response.status_code == 200
    assert "entries" in response.json()


def test_proxy_with_mocked_anthropic():
    with patch("api.proxy_v2.call_anthropic", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "Hello [PERSON_1], I can help with that."

        response = client.post("/v1/proxy", json={
            "model": "claude-haiku-4-5-20251001",
            "provider": "anthropic",
            "messages": [{"role": "user", "content": "My name is John Smith. Help me."}]
        })

        assert response.status_code == 200
        data = response.json()
        assert "intelligence" in data
        assert "cache_hit" in data["intelligence"]
        assert "routed_model" in data["intelligence"]
        assert "cost_saved_usd" in data["intelligence"]
        assert data["pii_summary"]["redacted"] is True


def test_semantic_cache_hit():
    """Second identical request should hit cache."""
    semantic_cache.clear()

    with patch("api.proxy_v2.call_anthropic", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "Paris is the capital of France."

        # First request
        client.post("/v1/proxy", json={
            "model": "claude-haiku-4-5-20251001",
            "provider": "anthropic",
            "use_cache": True,
            "messages": [{"role": "user", "content": "What is the capital of France?"}]
        })

        # Second identical request
        response = client.post("/v1/proxy", json={
            "model": "claude-haiku-4-5-20251001",
            "provider": "anthropic",
            "use_cache": True,
            "messages": [{"role": "user", "content": "What is the capital of France?"}]
        })

        assert response.status_code == 200
        data = response.json()
        assert data["intelligence"]["cache_hit"] is True
        # LLM should only have been called once
        assert mock_llm.call_count == 1


def test_cache_disabled():
    """Cache should be bypassed when use_cache is False."""
    semantic_cache.clear()

    with patch("api.proxy_v2.call_anthropic", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "Response here."

        for _ in range(2):
            client.post("/v1/proxy", json={
                "model": "claude-haiku-4-5-20251001",
                "provider": "anthropic",
                "use_cache": False,
                "messages": [{"role": "user", "content": "Same question every time?"}]
            })

        assert mock_llm.call_count == 2


def test_audit_summary_after_requests():
    with patch("api.proxy_v2.call_anthropic", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = "Response."
        client.post("/v1/proxy", json={
            "model": "claude-haiku-4-5-20251001",
            "provider": "anthropic",
            "messages": [{"role": "user", "content": "My email is test@example.com"}]
        })

    response = client.get("/v1/audit/summary")
    assert response.status_code == 200
    data = response.json()
    assert data.get("sensitive_data_transmitted_to_llm") is False
    assert "cache_hit_rate_percent" in data


def test_unknown_provider():
    response = client.post("/v1/proxy", json={
        "model": "some-model",
        "provider": "unknown",
        "messages": [{"role": "user", "content": "Hello"}]
    })
    assert response.status_code == 400


def test_clear_cache():
    response = client.delete("/v1/cache")
    assert response.status_code == 200
