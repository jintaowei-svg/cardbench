from scripts.consolidate_paper_results import attack_domain_variant, summarize_asr


def test_attack_domain_variant_parses_carddiff_id():
    assert attack_domain_variant("CARDDIFF_C2_HEALTHCARE_T050_V003") == (
        "C2",
        "healthcare",
        "003",
    )


def test_summarize_asr_counts_failures_and_errors():
    rows = [
        {"case_id": "CARDDIFF_A1_TRAVEL_T001_V001", "success": True, "errors": []},
        {"case_id": "CARDDIFF_A1_TRAVEL_T002_V001", "success": False, "errors": ["timeout"]},
    ]
    summary = summarize_asr(rows)
    assert summary["trials"] == 2
    assert summary["successes"] == 1
    assert summary["asr"] == 0.5
    assert summary["error_records"] == 1
    assert summary["by_attack"]["A1"]["trials"] == 2
