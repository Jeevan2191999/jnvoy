"""
Tests for Jnvoy PDF compliance report generator.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import os
import pytest
import tempfile

from core.report import generate_compliance_report


SAMPLE_SUMMARY = {
    "tenant_id": "test_tenant",
    "period_start": "2026-09-01T00:00:00+00:00",
    "period_end": "2026-10-01T00:00:00+00:00",
    "total_api_calls": 1250,
    "total_pii_instances_detected_and_redacted": 847,
    "pii_types_breakdown": {
        "EMAIL_ADDRESS": 312,
        "PERSON": 289,
        "PHONE_NUMBER": 156,
        "UK_POSTCODE": 54,
        "NI_NUMBER": 36,
    },
    "cache_hit_rate_percent": 34.2,
    "average_latency_ms": 1823.5,
    "sensitive_data_transmitted_to_llm": False,
    "compliance_statement": "Zero sensitive data was transmitted to any LLM API during this period.",
    "generated_at": "2026-10-06T10:00:00+00:00"
}


def test_report_generates_pdf():
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    try:
        result = generate_compliance_report(
            summary=SAMPLE_SUMMARY,
            output_path=path,
            company_name="Acme Financial Ltd",
            tenant_id="test_tenant"
        )
        assert os.path.exists(result)
        assert os.path.getsize(result) > 5000
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_report_with_zero_pii():
    summary = SAMPLE_SUMMARY.copy()
    summary["total_pii_instances_detected_and_redacted"] = 0
    summary["pii_types_breakdown"] = {}

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    try:
        result = generate_compliance_report(
            summary=summary,
            output_path=path,
            company_name="Clean Company Ltd"
        )
        assert os.path.exists(result)
        assert os.path.getsize(result) > 5000
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_report_with_transmission_detected():
    summary = SAMPLE_SUMMARY.copy()
    summary["sensitive_data_transmitted_to_llm"] = True

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    try:
        result = generate_compliance_report(
            summary=summary,
            output_path=path,
            company_name="Warning Company Ltd"
        )
        assert os.path.exists(result)
        assert os.path.getsize(result) > 5000
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_report_returns_path():
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    try:
        result = generate_compliance_report(
            summary=SAMPLE_SUMMARY,
            output_path=path
        )
        assert result == path
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_report_custom_company_name():
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name

    try:
        result = generate_compliance_report(
            summary=SAMPLE_SUMMARY,
            output_path=path,
            company_name="Nexus Black Ltd"
        )
        assert os.path.exists(result)
    finally:
        if os.path.exists(path):
            os.unlink(path)
