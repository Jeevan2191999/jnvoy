# Claims ledger

Every claim on the public pages, what proves it, and what it does not prove. A test
(`tests/test_claims_ledger.py`) fails if a claim's wording leaves the page, if the evidence
does not exist, or if a feature on the homepage has no row here. When you change the site,
change this file in the same commit.

Status words:

- **met**: a test or a document in this repository proves it.
- **partly**: true as worded, but the Limit column says what is not yet proven.
- **promise**: a commitment to customers, not a feature. It is honoured per customer.

Evidence is a file, a `file::test_name`, or an outside source with the date it was checked.
Several pieces of evidence are separated by `;`.

| Claim | Page | Phrase on the page | Evidence | Status | Limit |
|---|---|---|---|---|---|
| 50 identifier types | index.html | `50 identifier types` | tests/test_regions.py::test_every_pack_has_a_recogniser_and_a_test; tests/test_homepage_regions.py::test_every_hero_example_is_really_redacted_to_the_token_shown | partly | Tested against published sample numbers. Accuracy on real customer data is not measured. |
| Over 1,000 automated tests | index.html | `1,000+` | tests | met | 1,011 tests collected on 3 November 2026 with PostgreSQL available. |
| Original values held in memory for the request only | index.html | `held in memory for the request only and never stored` | tests/test_privacy_page.py::test_privacy_page_states_the_key_facts; tests/test_audit_export.py::test_nothing_in_an_event_could_hold_text_or_keys | met | Applies to the audit log, cache and logs. The model provider you choose still receives the redacted text. |
| Microsoft Presidio detection | index.html | `Microsoft Presidio detection` | tests/test_detector.py | met | Detection finds patterns and names, not meaning. |
| Exact-match cache | index.html | `Exact-match cache` | tests/test_intelligence.py::test_cache_exact_match; tests/test_output_scan.py::test_the_cache_never_holds_a_secret_in_redact_mode | met | |
| Intelligent routing, off by default | index.html | `Off by default, so your request always uses the model you named` | tests/test_routing_and_claims.py::test_routing_is_off_unless_asked_for; tests/test_routing_and_claims.py::test_the_callers_model_is_kept_when_routing_is_off | met | |
| Persistent audit logs | index.html | `Persistent audit logs` | tests/test_audit_export.py::test_date_filters_pick_the_right_entries; tests/test_audit_export.py::test_nothing_in_an_event_could_hold_text_or_keys | met | Counts by type. Never original text. |
| Compliance report PDF | index.html | `Compliance report PDF` | tests/test_report.py::test_report_generates_pdf; tests/test_routing_and_claims.py::test_reports_do_not_assert_compliance_or_zero_transmission | met | The report states what was detected. It does not state that a customer is compliant. |
| API keys and rate limits | index.html | `API keys and rate limits` | tests/test_auth.py::test_rate_limit_per_key_and_recovery; tests/test_tenant_isolation.py::test_a_customer_key_cannot_use_admin_routes | met | |
| Provider health monitoring | index.html | `Provider health monitoring` | tests/test_intelligence.py::test_outage_detector_marks_unhealthy_after_failures; tests/test_intelligence.py::test_outage_detector_dashboard | met | |
| Docker stack | index.html | `Docker stack` | tests/test_docker_compose.py::test_compose_passes_the_api_keys_and_fails_clearly_without_them; .github/workflows/tests.yml | met | The CI job builds the image and starts it. |
| Redacts people, not vocabulary | index.html | `Redacts people, not vocabulary` | tests/test_entity_filter.py::test_default_leaves_generic_text_alone; tests/test_entity_filter.py::test_person_is_still_redacted_by_default | met | Company names are not hidden by default. |
| Optional second-pass review | index.html | `Optional second-pass review` | tests/test_judged_detector.py::test_without_judge_matches_primary_detector_exactly; tests/test_judged_detector.py::test_judge_cannot_weaken_primary_redaction | met | Off on the hosted service. |
| Prompt injection blocking | index.html | `Prompt injection blocking` | tests/test_injection.py::test_real_attacks_are_still_caught; tests/test_injection.py::test_ordinary_requests_are_not_blocked | partly | Pattern based. No detection rate has been published yet. |
| Reply scanning with an audit trail | index.html | `Reply scanning, with an audit trail of what was found` | tests/test_output_scan.py::test_proxy_response_carries_the_scan_summary; tests/test_output_scan.py::test_pipeline_flags_by_default_and_keeps_the_reply | met | |
| Reversible tokens | index.html | `Reversible tokens` | tests/test_conversation_tokens.py | met | |
| Coverage by region | index.html | `Coverage by region` | tests/test_homepage_regions.py::test_coverage_section_names_every_country_with_a_pack | met | |
| Accuracy on real customer data is not measured | index.html | `have not yet measured accuracy on real customer data` | tests/test_accuracy_page.py::test_the_page_states_its_limits_and_makes_no_overclaim | met | This is a stated limit. |
| Source-available under BSL 1.1 | index.html | `source-available under BSL 1.1` | LICENSE; tests/test_routing_and_claims.py::test_readme_matches_what_is_built | met | Not open source. Each version becomes Apache 2.0 four years after release. |
| No SOC 2 or ISO 27001 certification yet | index.html | `no SOC 2 or ISO 27001 certification yet` | tests/test_security_page.py::test_security_page_is_honest_about_gaps | met | This is a stated limit. |
| Shadow AI breach figures | index.html | `one in five organisations had a breach linked to unsanctioned` | https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls (IBM Cost of a Data Breach Report 2025, checked 2026-11-03) | met | The 65% and 53% figures are IBM's. |
| Samsung restricted staff use of generative AI | index.html | `In 2023 Samsung restricted staff use of generative AI` | https://www.techradar.com/news/samsung-bans-chatgpt-use-after-employee-leak (TechRadar, 2 May 2023, checked 2026-11-03) | met | Reported by Bloomberg. Samsung's memo is not public, so the page says "reports". |
| ChatGPT data flaw fixed 20 February 2026 | index.html | `OpenAI fixed it on 20 February 2026` | https://blog.checkpoint.com/research/when-ai-trust-breaks-the-chatgpt-data-leakage-flaw-that-redefined-ai-vendor-security-trust/ (Check Point Research, checked 2026-11-03) | met | Check Point found no sign it was used in the wild. |
| Proprietary code and trade secrets are not caught | index.html | `proprietary source code, trade secrets and other business-confidential text are not caught` | tests/test_entity_filter.py::test_default_leaves_generic_text_alone | met | This is a stated limit. |
| Service level agreed with you | index.html | `Service level agreed with you` | none | promise | No service level template exists yet. Write one before the first paying customer. |
| Dedicated Slack channel | index.html | `Dedicated Slack channel` | none | promise | Honoured per Enterprise customer. |
| Custom recognisers, built with you | index.html | `Custom recognisers, built with you` | tests/test_custom_rules.py::test_a_custom_pattern_is_redacted_under_its_own_type_and_restored | promise | Customers can add their own patterns today. Recognisers built for them are a service. |
