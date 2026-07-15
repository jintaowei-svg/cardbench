from scripts.consolidate_paper_results import (
    OFFICIAL_A2A_MODELS,
    attack_domain_variant,
    row_case_id,
    summarize_asr,
)


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


def test_transfer_rows_use_source_case_id():
    row = {"source_case_id": "CARDDIFF_A3_TRAVEL_T001_V002"}
    assert row_case_id(row) == "CARDDIFF_A3_TRAVEL_T001_V002"


def test_official_cross_model_matrix_has_eight_complete_models():
    assert len(OFFICIAL_A2A_MODELS) == 8
    assert "claude-haiku-4.5" not in OFFICIAL_A2A_MODELS
    assert "claude-sonnet-5" in OFFICIAL_A2A_MODELS
