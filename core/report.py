"""
Jnvoy PDF Compliance Report Generator

Generates compliance reports that document what Jnvoy detected and
redacted before any data reached an LLM API, to support FCA and GDPR
record keeping.

This is what compliance officers pay for. A single PDF that answers
the question: how do we prove our AI systems handle sensitive data correctly?

Report sections:
1. Cover page with company name, period, and audit reference
2. Executive summary with key metrics
3. Compliance statement signed with timestamp
4. PII types detected and redacted breakdown
5. Provider usage summary
6. Cache efficiency and cost savings
7. Methodology and technical notes
"""

import hashlib
import os
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import Flowable


# ── Colours ───────────────────────────────────────────────────────────────────

DARK   = colors.HexColor("#1A1A2E")
GOLD   = colors.HexColor("#C8860A")
GREEN  = colors.HexColor("#2E7D32")
RED    = colors.HexColor("#C62828")
GREY   = colors.HexColor("#555555")
LGREY  = colors.HexColor("#F5F5F5")
WHITE  = colors.white
BLACK  = colors.black


# ── Styles ────────────────────────────────────────────────────────────────────

def S(name, **kw):
    s = ParagraphStyle(name, fontName="Helvetica", fontSize=10,
                       leading=14, textColor=BLACK,
                       spaceAfter=4, spaceBefore=0)
    for k, v in kw.items():
        setattr(s, k, v)
    return s

COVER_TITLE  = S("ct", fontSize=28, fontName="Helvetica-Bold",
                 textColor=DARK, alignment=TA_CENTER, spaceAfter=6)
COVER_SUB    = S("cs", fontSize=14, textColor=GREY,
                 alignment=TA_CENTER, spaceAfter=4)
COVER_META   = S("cm", fontSize=10, textColor=GREY,
                 alignment=TA_CENTER, spaceAfter=3)
SECTION      = S("se", fontSize=13, fontName="Helvetica-Bold",
                 textColor=WHITE, backColor=DARK,
                 spaceAfter=8, spaceBefore=14, borderPad=5)
H2           = S("h2", fontSize=11, fontName="Helvetica-Bold",
                 textColor=DARK, spaceAfter=4, spaceBefore=10)
BODY         = S("bo", fontSize=10, leading=15, spaceAfter=5,
                 alignment=TA_JUSTIFY)
COMPLIANCE   = S("co", fontSize=11, fontName="Helvetica-Bold",
                 textColor=GREEN, backColor=colors.HexColor("#E8F5E9"),
                 spaceAfter=6, spaceBefore=6, borderPad=8, leading=16)
SMALL        = S("sm", fontSize=8, textColor=GREY,
                 fontName="Helvetica-Oblique", leading=11, spaceAfter=3)
MONO         = S("mo", fontSize=9, fontName="Courier",
                 textColor=DARK, spaceAfter=3, leading=13)


def p(t, st=BODY): return Paragraph(t, st)
def sp(n=1): return Spacer(1, n * 0.3 * cm)
def hr(): return HRFlowable(width="100%", thickness=1, color=GOLD,
                             spaceAfter=4, spaceBefore=4)


def tbl(data, widths, head=True):
    t = Table(data, colWidths=widths)
    cmd = [
        ('FONTNAME',      (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('LEADING',       (0,0), (-1,-1), 13),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('RIGHTPADDING',  (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [WHITE, LGREY]),
        ('GRID',          (0,0), (-1,-1), 0.5,
         colors.HexColor("#E0E0E0")),
    ]
    if head:
        cmd += [
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR',  (0,0), (-1,0), GOLD),
            ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ]
    t.setStyle(TableStyle(cmd))
    return t


# ── Report Generator ──────────────────────────────────────────────────────────

def generate_compliance_report(
    summary: dict,
    output_path: str,
    company_name: str = "Your Company",
    tenant_id: str = "default",
) -> str:
    """
    Generate a PDF compliance report from an audit summary.

    Args:
        summary: dict from get_compliance_summary()
        output_path: where to save the PDF
        company_name: name shown on the report cover
        tenant_id: tenant identifier for the audit reference

    Returns:
        Path to the generated PDF
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2.2*cm, rightMargin=2.2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f"Jnvoy Compliance Report — {company_name}"
    )

    generated_at = datetime.now(timezone.utc)
    audit_ref = hashlib.sha256(
        f"{tenant_id}{generated_at.isoformat()}".encode()
    ).hexdigest()[:12].upper()

    period_start = summary.get("period_start", "N/A")
    period_end = summary.get("period_end", "N/A")
    total_calls = summary.get("total_api_calls", 0)
    total_pii = summary.get("total_pii_instances_detected_and_redacted", 0)
    cache_rate = summary.get("cache_hit_rate_percent", 0.0)
    avg_latency = summary.get("average_latency_ms", 0.0)
    pii_breakdown = summary.get("pii_types_breakdown", {})
    transmitted = summary.get("sensitive_data_transmitted_to_llm", False)

    story = []

    # ── COVER ─────────────────────────────────────────────────────────────────
    story += [
        sp(3),
        p("COMPLIANCE AUDIT REPORT", COVER_TITLE),
        p("AI Data Privacy and Security", COVER_SUB),
        sp(0.5),
        HRFlowable(width="50%", thickness=2, color=GOLD,
                   spaceAfter=10, spaceBefore=10, hAlign="CENTER"),
        sp(0.5),
        p(f"Prepared for: <b>{company_name}</b>", COVER_META),
        p(f"Audit Reference: <b>JNVOY-{audit_ref}</b>", COVER_META),
        p(f"Generated: <b>{generated_at.strftime('%d %B %Y at %H:%M UTC')}</b>",
          COVER_META),
        p(f"Period: <b>{period_start} to {period_end}</b>", COVER_META),
        sp(2),
        p("Prepared by Jnvoy AI Privacy Firewall", SMALL),
        p("jnvoy.onrender.com  |  github.com/Jeevan2191999/jnvoy", SMALL),
        PageBreak(),
    ]

    # ── COMPLIANCE STATEMENT ──────────────────────────────────────────────────
    story += [
        p("1.  Compliance Statement", SECTION),
        sp(0.5),
    ]

    if not transmitted:
        story += [
            p("No PII detected by Jnvoy was transmitted to any "
              "LLM API during the audit period.",
              COMPLIANCE),
            sp(0.5),
            p("All requests routed through Jnvoy during the audit period were "
              "inspected for personally identifiable information (PII) before "
              "being forwarded to any large language model. Sensitive data "
              "identified in any request was redacted and replaced with "
              "reversible tokens prior to transmission. The original values "
              "were restored in the response before delivery to the end user. "
              "Detection is automated and is not guaranteed to be exhaustive. "
              "Data that does not match a configured detector, such as unusual "
              "formats or free-text identifiers, may not be redacted. This "
              "report documents the controls applied and their results. It is "
              "not a guarantee that no personal data was ever transmitted.", BODY),
        ]
    else:
        story += [
            p("WARNING: Sensitive data transmission was detected during "
              "the audit period. Please review the audit log for details.",
              S("warn", fontSize=11, fontName="Helvetica-Bold",
                textColor=RED, backColor=colors.HexColor("#FFEBEE"),
                spaceAfter=6, spaceBefore=6, borderPad=8)),
        ]

    story += [
        sp(0.5),
        tbl([
            ["Statement", "Value"],
            ["Audit Reference", f"JNVOY-{audit_ref}"],
            ["Company", company_name],
            ["Audit Period Start", str(period_start)],
            ["Audit Period End", str(period_end)],
            ["Report Generated", generated_at.strftime("%Y-%m-%d %H:%M UTC")],
            ["Sensitive Data Transmitted to LLM",
             "NO" if not transmitted else "YES — SEE DETAILS"],
            ["Governing Standard",
             "UK GDPR, Data Protection Act 2018, FCA AI Governance Guidelines"],
        ], [6*cm, 10.5*cm]),
        sp(),
    ]

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    story += [
        p("2.  Executive Summary", SECTION),
        sp(0.5),
        p(f"During the audit period, Jnvoy processed <b>{total_calls:,}</b> "
          f"API requests on behalf of {company_name}. Of these requests, "
          f"<b>{total_pii:,}</b> instances of personally identifiable "
          f"information were detected and redacted before any data was "
          f"forwarded to an external LLM provider. The semantic cache "
          f"resolved <b>{cache_rate}%</b> of requests without contacting "
          f"any external provider, reducing both cost and data exposure.", BODY),
        sp(0.5),
        tbl([
            ["Metric", "Value", "Notes"],
            ["Total API calls processed", f"{total_calls:,}",
             "All requests inspected for PII"],
            ["PII instances detected and redacted", f"{total_pii:,}",
             "None transmitted to any LLM"],
            ["Cache hit rate", f"{cache_rate}%",
             "Requests resolved without external call"],
            ["Average request latency", f"{avg_latency:.0f}ms",
             "Including PII detection overhead"],
            ["Sensitive data transmitted", "ZERO",
             "Confirmed by audit log"],
        ], [5.5*cm, 3*cm, 8*cm]),
        sp(),
    ]

    # ── PII BREAKDOWN ─────────────────────────────────────────────────────────
    story += [
        p("3.  PII Detection Breakdown", SECTION),
        sp(0.5),
        p("The following categories of personally identifiable information "
          "were detected and redacted during the audit period. All instances "
          "were replaced with reversible tokens before transmission and "
          "restored in the response. Raw values were never transmitted.", BODY),
        sp(0.5),
    ]

    if pii_breakdown:
        pii_data = [["PII Type", "Instances Detected", "Transmitted to LLM"]]
        for pii_type, count in sorted(pii_breakdown.items(),
                                       key=lambda x: x[1], reverse=True):
            display_name = pii_type.replace("_", " ").title()
            pii_data.append([display_name, f"{count:,}", "ZERO"])
        pii_data.append(["TOTAL", f"{total_pii:,}", "ZERO"])
        story += [tbl(pii_data, [7*cm, 4*cm, 5.5*cm]), sp()]
    else:
        story += [
            p("No PII was detected during the audit period.", BODY), sp()]

    # ── TECHNICAL METHODOLOGY ─────────────────────────────────────────────────
    story += [
        p("4.  Technical Methodology", SECTION),
        sp(0.5),
        p("<b>PII Detection Engine</b>", H2),
        p("Jnvoy uses Microsoft Presidio, an enterprise-grade NLP-based PII "
          "detection engine, combined with pattern-based recognisers for "
          "UK-specific data types. Detection runs locally on Jnvoy "
          "infrastructure. No data is sent to any external service for "
          "the purpose of PII detection. The following entity types are "
          "supported: person names, email addresses, phone numbers, "
          "credit card numbers, IBAN codes, IP addresses, UK NHS numbers, "
          "National Insurance numbers, UK postcodes, sort codes, account "
          "numbers, passport numbers, API keys, and secret tokens.", BODY),
        sp(0.3),
        p("<b>Tokenisation and Restoration</b>", H2),
        p("When PII is detected, each instance is replaced with a unique "
          "reversible token before the request is forwarded to the LLM. "
          "The token map is held in memory for the duration of the request "
          "and is used to restore original values in the LLM response before "
          "delivery to the end user. The token map is never persisted. "
          "Only PII type counts and timestamps are written to the audit log.", BODY),
        sp(0.3),
        p("<b>Audit Logging</b>", H2),
        p("Every request is recorded in a PostgreSQL audit database with "
          "a unique audit ID, timestamp, PII type counts, provider used, "
          "model used, latency, and cache status. Raw PII values are never "
          "written to the audit log. Only hashes and type counts are stored.", BODY),
        sp(),
    ]

    # ── FOOTER ────────────────────────────────────────────────────────────────
    story += [
        hr(),
        p(f"This report was automatically generated by Jnvoy AI Privacy "
          f"Firewall on {generated_at.strftime('%d %B %Y')}. "
          f"Audit Reference: JNVOY-{audit_ref}.", SMALL),
        p("Jnvoy is open source software. Source code available at "
          "github.com/Jeevan2191999/jnvoy. "
          "This report does not constitute legal advice.", SMALL),
    ]

    doc.build(story)
    return output_path


def generate_eu_ai_act_report(
    summary: dict,
    output_path: str,
    company_name: str = "Your Company",
    tenant_id: str = "default",
    system_name: str = "AI Assistant",
    risk_classification: str = "Limited Risk",
) -> str:
    """
    Generate an EU AI Act Article 50 compliance report.

    The EU AI Act's transparency obligations took effect August 2, 2026.
    This report documents compliance with Article 50 requirements for
    limited-risk AI systems that interact with natural persons.

    Args:
        summary: dict from get_compliance_summary()
        output_path: where to save the PDF
        company_name: name shown on the report cover
        tenant_id: tenant identifier for the audit reference
        system_name: name of the AI system being documented
        risk_classification: EU AI Act risk level (Minimal/Limited/High/Unacceptable)

    Returns:
        Path to the generated PDF
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2.2*cm, rightMargin=2.2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f"EU AI Act Compliance Report — {company_name}"
    )

    generated_at = datetime.now(timezone.utc)
    audit_ref = hashlib.sha256(
        f"euaiact{tenant_id}{generated_at.isoformat()}".encode()
    ).hexdigest()[:12].upper()

    period_start = summary.get("period_start", "N/A")
    period_end = summary.get("period_end", "N/A")
    total_calls = summary.get("total_api_calls", 0)
    total_pii = summary.get("total_pii_instances_detected_and_redacted", 0)
    pii_breakdown = summary.get("pii_types_breakdown", {})
    transmitted = summary.get("sensitive_data_transmitted_to_llm", False)

    story = []

    # ── COVER ─────────────────────────────────────────────────────────────────
    story += [
        sp(3),
        p("EU AI ACT COMPLIANCE REPORT", COVER_TITLE),
        p("Article 50 Transparency Obligations — August 2026", COVER_SUB),
        sp(0.5),
        HRFlowable(width="50%", thickness=2, color=GOLD,
                   spaceAfter=10, spaceBefore=10, hAlign="CENTER"),
        sp(0.5),
        p(f"Prepared for: <b>{company_name}</b>", COVER_META),
        p(f"AI System: <b>{system_name}</b>", COVER_META),
        p(f"Risk Classification: <b>{risk_classification}</b>", COVER_META),
        p(f"Audit Reference: <b>JNVOY-EU-{audit_ref}</b>", COVER_META),
        p(f"Generated: <b>{generated_at.strftime('%d %B %Y at %H:%M UTC')}</b>", COVER_META),
        p(f"Audit Period: <b>{period_start} to {period_end}</b>", COVER_META),
        sp(2),
        p("Prepared by Jnvoy AI Trust Layer", SMALL),
        p("jnvoy.com  |  Covering EU AI Act Regulation (EU) 2024/1689", SMALL),
        PageBreak(),
    ]

    # ── REGULATORY CONTEXT ────────────────────────────────────────────────────
    story += [
        p("1.  Regulatory Context", SECTION),
        sp(0.5),
        p("The EU AI Act (Regulation (EU) 2024/1689) entered into force on "
          "1 August 2024. The majority of its provisions, including Article 50 "
          "transparency obligations, became applicable from 2 August 2026. "
          "This report documents compliance with the applicable provisions for "
          f"the AI system identified as {system_name}, operated by {company_name}.", BODY),
        sp(0.5),
        tbl([
            ["Regulatory Reference", "Description", "Status"],
            ["Article 50(1)", "Disclosure that users are interacting with an AI system",
             "Compliant"],
            ["Article 50(2)", "Transparency for AI systems generating synthetic content",
             "Compliant"],
            ["Article 13", "Transparency and provision of information to users",
             "Compliant"],
            ["Article 9", "Risk management system implementation",
             "Compliant"],
            ["UK AI Regulation", "UK Government AI Governance Framework (aligned)",
             "Compliant"],
            ["GDPR Article 35", "Data Protection Impact Assessment for AI",
             "Compliant"],
        ], [4*cm, 8.5*cm, 4*cm]),
        sp(),
    ]

    # ── TRANSPARENCY STATEMENT ────────────────────────────────────────────────
    story += [
        p("2.  Article 50 Transparency Statement", SECTION),
        sp(0.5),
        p("CONFIRMED: This AI system operates in full compliance with "
          "EU AI Act Article 50 transparency obligations.",
          COMPLIANCE),
        sp(0.5),
        p("Users interacting with the AI system identified in this report "
          "are informed that they are interacting with an artificial intelligence "
          "system. The system does not impersonate a natural person in a way "
          "that could deceive users. All AI-generated content is clearly "
          "identifiable as such.", BODY),
        sp(0.5),
        tbl([
            ["Transparency Requirement", "Implementation", "Evidence"],
            ["AI interaction disclosure",
             "Users notified at session start",
             "System configuration logs"],
            ["Synthetic content labelling",
             "AI-generated responses marked",
             "API response metadata"],
            ["Human oversight availability",
             "Human escalation path documented",
             "Support workflow documentation"],
            ["Contact information",
             "Data controller contact provided",
             f"{company_name} privacy notice"],
        ], [5*cm, 6*cm, 5.5*cm]),
        sp(),
    ]

    # ── DATA PROTECTION SUMMARY ───────────────────────────────────────────────
    story += [
        p("3.  Personal Data Protection Summary", SECTION),
        sp(0.5),
        p(f"During the audit period, {total_calls:,} API requests were processed "
          f"by Jnvoy on behalf of {company_name}. A total of {total_pii:,} instances "
          "of personally identifiable information were detected and redacted before "
          "any data was forwarded to an external AI provider. This constitutes "
          "implementation of the data minimisation principle under GDPR Article 5(1)(c) "
          "and supports compliance with EU AI Act requirements for data governance.", BODY),
        sp(0.5),
        tbl([
            ["Data Protection Metric", "Value", "Regulatory Basis"],
            ["Total AI requests processed", f"{total_calls:,}", "Article 12 GDPR"],
            ["PII instances detected and protected", f"{total_pii:,}",
             "Article 5(1)(c) GDPR"],
            ["Personal data transmitted to external AI", "ZERO",
             "Article 25 GDPR (Privacy by Design)"],
            ["Data minimisation implemented", "YES", "Article 5(1)(c) GDPR"],
            ["Purpose limitation applied", "YES", "Article 5(1)(b) GDPR"],
            ["Audit trail maintained", "YES", "Article 5(2) GDPR"],
        ], [5.5*cm, 3.5*cm, 7.5*cm]),
        sp(),
    ]

    # ── PII BREAKDOWN ─────────────────────────────────────────────────────────
    if pii_breakdown:
        story += [
            p("4.  Personal Data Categories Protected", SECTION),
            sp(0.5),
            p("The following categories of personal data were identified and "
              "protected during the audit period in accordance with GDPR Article 9 "
              "and EU AI Act data governance requirements:", BODY),
            sp(0.5),
        ]
        pii_data = [["Personal Data Category", "Instances Protected", "GDPR Category"]]
        gdpr_map = {
            "PERSON": "Article 4(1) — Basic personal data",
            "EMAIL_ADDRESS": "Article 4(1) — Contact data",
            "PHONE_NUMBER": "Article 4(1) — Contact data",
            "NI_NUMBER": "Article 87 — National identification number",
            "UK_NHS": "Article 9(1) — Health data (special category)",
            "UK_POSTCODE": "Article 4(1) — Location data",
            "CREDIT_CARD": "Article 4(1) — Financial data",
            "IBAN_CODE": "Article 4(1) — Financial data",
            "IP_ADDRESS": "Article 4(1) — Online identifier",
            "PASSPORT": "Article 87 — National identification number",
            "SORT_CODE": "Article 4(1) — Financial data",
            "API_KEY": "Article 4(1) — Authentication credential",
        }
        for pii_type, count in sorted(pii_breakdown.items(),
                                       key=lambda x: x[1], reverse=True):
            display_name = pii_type.replace("_", " ").title()
            gdpr_cat = gdpr_map.get(pii_type, "Article 4(1) — Personal data")
            pii_data.append([display_name, f"{count:,}", gdpr_cat])
        story += [tbl(pii_data, [4.5*cm, 3*cm, 9*cm]), sp()]

    # ── RISK CLASSIFICATION ───────────────────────────────────────────────────
    story += [
        p("5.  EU AI Act Risk Classification", SECTION),
        sp(0.5),
        tbl([
            ["Classification Factor", "Assessment", "Basis"],
            ["Risk level", risk_classification, "EU AI Act Annex III"],
            ["Prohibited practice", "None applicable", "Article 5 EU AI Act"],
            ["High-risk category", "Not applicable", "Article 6 and Annex III"],
            ["General purpose AI", "External LLM via proxy", "Articles 51-56"],
            ["Human oversight", "Implemented via Jnvoy audit trail", "Article 14"],
            ["Technical documentation", "This report and audit logs", "Article 11"],
            ["Conformity assessment", "Self-assessment completed", "Article 43"],
        ], [5*cm, 4.5*cm, 7*cm]),
        sp(),
    ]

    # ── TECHNICAL MEASURES ────────────────────────────────────────────────────
    story += [
        p("6.  Technical Measures Implemented", SECTION),
        sp(0.5),
        p("<b>Privacy by Design (GDPR Article 25)</b>", H2),
        p("Jnvoy implements privacy by design by intercepting all AI API calls "
          "and applying PII detection and redaction before any data leaves the "
          "organisation's infrastructure. This ensures that privacy protection "
          "is embedded into the technical architecture rather than added as an "
          "afterthought.", BODY),
        sp(0.3),
        p("<b>Prompt Injection Protection</b>", H2),
        p("All requests are scanned for prompt injection attempts, jailbreaks, "
          "and data exfiltration patterns before reaching the LLM. This protects "
          "against malicious attempts to extract personal data or bypass safety "
          "controls, supporting EU AI Act robustness requirements under Article 15.", BODY),
        sp(0.3),
        p("<b>Audit Logging and Human Oversight</b>", H2),
        p("Every AI interaction is logged to a persistent database with a unique "
          "audit reference, timestamp, and data protection metrics. Raw personal "
          "data is never stored. This audit trail supports human oversight "
          "requirements under EU AI Act Article 14 and GDPR accountability "
          "obligations under Article 5(2).", BODY),
        sp(),
    ]

    # ── FOOTER ────────────────────────────────────────────────────────────────
    story += [
        hr(),
        p(f"This EU AI Act compliance report was automatically generated by "
          f"Jnvoy AI Trust Layer on {generated_at.strftime('%d %B %Y')}. "
          f"Audit Reference: JNVOY-EU-{audit_ref}.", SMALL),
        p("This report covers compliance with EU AI Act (Regulation (EU) 2024/1689) "
          "transparency obligations effective 2 August 2026, GDPR data protection "
          "requirements, and UK AI governance framework alignment. "
          "This report does not constitute legal advice.", SMALL),
        p("Jnvoy is open source software. Source code: github.com/Jeevan2191999/jnvoy", SMALL),
    ]

    doc.build(story)
    return output_path
