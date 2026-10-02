"""
Tests for the Jnvoy Intelligence Layer.
Tests semantic cache, intelligent router, and outage detector.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import time
import pytest
from core.intelligence import (
    SemanticCache, IntelligentRouter, OutageDetector,
    QueryComplexity, classify_query, RoutingDecision
)


# ─── Query Classification Tests ───────────────────────────────────────────────

def test_classify_simple_query():
    assert classify_query("What is the capital of France?") == QueryComplexity.SIMPLE

def test_classify_simple_short_query():
    assert classify_query("Define AI") == QueryComplexity.SIMPLE

def test_classify_complex_query():
    result = classify_query("Analyse the trade-offs between microservices and monolithic architecture for a fintech startup")
    assert result == QueryComplexity.COMPLEX

def test_classify_critical_legal_query():
    result = classify_query("What are the GDPR compliance requirements for storing customer data?")
    assert result == QueryComplexity.CRITICAL

def test_classify_critical_financial_query():
    result = classify_query("What are the FCA regulatory requirements for this investment strategy?")
    assert result == QueryComplexity.CRITICAL

def test_classify_medium_by_length():
    medium_text = " ".join(["word"] * 30)
    result = classify_query(medium_text)
    assert result in [QueryComplexity.MEDIUM, QueryComplexity.SIMPLE]


# ─── Semantic Cache Tests ──────────────────────────────────────────────────────

def test_cache_exact_match():
    cache = SemanticCache()
    cache.set("What is Python?", "Python is a programming language.", "claude-haiku-4-5", "anthropic", 0.001)
    result = cache.get("What is Python?")
    assert result is not None
    assert result.response_text == "Python is a programming language."

def test_cache_miss():
    cache = SemanticCache()
    result = cache.get("What is Rust?")
    assert result is None

def test_cache_semantic_similarity():
    cache = SemanticCache(similarity_threshold=0.5)
    cache.set("What is the capital of France?", "Paris is the capital.", "claude-haiku-4-5", "anthropic", 0.001)
    result = cache.get("What is France capital city?")
    assert result is not None

def test_cache_no_false_positive():
    cache = SemanticCache(similarity_threshold=0.9)
    cache.set("What is the capital of France?", "Paris.", "claude-haiku-4-5", "anthropic", 0.001)
    result = cache.get("What is the best Python framework for web development?")
    assert result is None

def test_cache_ttl_expiry():
    cache = SemanticCache(ttl_seconds=0)  # Immediate expiry
    cache.set("Test query", "Test response", "claude-haiku-4-5", "anthropic", 0.001)
    time.sleep(0.01)
    result = cache.get("Test query")
    assert result is None

def test_cache_hit_counter():
    cache = SemanticCache()
    cache.set("Hello world", "Hi there", "claude-haiku-4-5", "anthropic", 0.001)
    cache.get("Hello world")
    cache.get("Hello world")
    entry = cache.get("Hello world")
    assert entry.hits >= 2

def test_cache_stats():
    cache = SemanticCache()
    cache.set("Query one", "Response one", "claude-haiku-4-5", "anthropic", 0.001)
    cache.get("Query one")   # Hit
    cache.get("Query two")   # Miss
    stats = cache.stats
    assert stats["cache_hits"] == 1
    assert stats["cache_misses"] == 1
    assert stats["hit_rate_percent"] == 50.0

def test_cache_eviction_at_capacity():
    cache = SemanticCache(max_entries=3)
    for i in range(4):
        cache.set(f"Query {i}", f"Response {i}", "model", "provider", 0.0)
    assert len(cache._cache) <= 3

def test_cache_clear():
    cache = SemanticCache()
    cache.set("Query", "Response", "model", "provider", 0.0)
    cache.clear()
    assert len(cache._cache) == 0
    assert cache.stats["cache_hits"] == 0


# ─── Intelligent Router Tests ──────────────────────────────────────────────────

def test_router_routes_simple_to_cheap_model():
    router = IntelligentRouter()
    decision = router.route("What is 2 + 2?")
    assert decision.complexity == QueryComplexity.SIMPLE
    assert "haiku" in decision.recommended_model or "mini" in decision.recommended_model

def test_router_routes_critical_to_best_model():
    router = IntelligentRouter()
    decision = router.route("What are the legal implications of this GDPR compliance issue?")
    assert decision.complexity == QueryComplexity.CRITICAL
    assert "opus" in decision.recommended_model or "gpt-4o" in decision.recommended_model

def test_router_prefer_local():
    router = IntelligentRouter(prefer_local=True)
    decision = router.route("Summarise this document")
    assert decision.use_local is True

def test_router_cost_analysis_shows_savings():
    router = IntelligentRouter()
    queries = [
        "What is Python?",                                    # Simple
        "What is Python?",                                    # Simple
        "What is Python?",                                    # Simple
        "Analyse the architecture trade-offs for this system",  # Complex
    ]
    analysis = router.cost_analysis(queries, baseline_model="gpt-4o")
    assert analysis["savings_percent"] > 0
    assert analysis["baseline_cost_usd"] > analysis["routed_cost_usd"]
    assert "saves" in analysis["message"]

def test_router_batch_route():
    router = IntelligentRouter()
    queries = ["What is AI?", "Analyse this complex legal document thoroughly"]
    decisions = router.batch_route(queries)
    assert len(decisions) == 2
    assert decisions[0].complexity != decisions[1].complexity

def test_router_force_complexity():
    router = IntelligentRouter()
    decision = router.route("simple question", force_complexity=QueryComplexity.CRITICAL)
    assert decision.complexity == QueryComplexity.CRITICAL


# ─── Outage Detector Tests ────────────────────────────────────────────────────

def test_outage_detector_healthy_by_default():
    detector = OutageDetector()
    assert detector.is_healthy("anthropic") is True

def test_outage_detector_marks_unhealthy_after_failures():
    detector = OutageDetector()
    detector.record_failure("anthropic", "Connection timeout")
    assert detector.is_healthy("anthropic") is True  # Not yet
    detector.record_failure("anthropic", "Connection timeout")
    assert detector.is_healthy("anthropic") is False  # Now unhealthy

def test_outage_detector_recovers_on_success():
    detector = OutageDetector()
    detector.record_failure("openai", "API error")
    detector.record_failure("openai", "API error")
    assert detector.is_healthy("openai") is False
    detector.record_success("openai", 150.0)
    assert detector.is_healthy("openai") is True

def test_outage_detector_tracks_latency():
    detector = OutageDetector()
    detector.record_success("anthropic", 200.0)
    detector.record_success("anthropic", 300.0)
    dashboard = detector.get_dashboard()
    assert dashboard["anthropic"]["avg_latency_ms"] > 0

def test_outage_detector_get_healthy_providers():
    detector = OutageDetector()
    detector.record_success("anthropic", 150.0)
    detector.record_success("openai", 200.0)
    detector.record_failure("google", "error")
    detector.record_failure("google", "error")
    healthy = detector.get_healthy_providers()
    assert "anthropic" in healthy
    assert "openai" in healthy
    assert "google" not in healthy

def test_outage_detector_dashboard():
    detector = OutageDetector()
    detector.record_success("anthropic", 150.0)
    dashboard = detector.get_dashboard()
    assert "anthropic" in dashboard
    assert "healthy" in dashboard["anthropic"]
    assert "avg_latency_ms" in dashboard["anthropic"]
