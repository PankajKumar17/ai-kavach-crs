"""Tests for the metrics module."""

import json

from ai_kavach.metrics import BugResolutionRecord, generate_run_summary


def test_generate_run_summary_math(tmp_path):
    """Test that the arithmetic in the summary generator is strictly correct."""

    records = [
        # Bug 1: Resolved via LLM, 1000 tokens, 10 seconds
        BugResolutionRecord(
            bug_id="bug1",
            resolved=True,
            resolution_path="llm",
            llm_tokens_used=1000,
            wall_clock_time_s=10.0,
            peak_memory_mb=100.0
        ),
        # Bug 2: Resolved via template, 0 tokens, 1 second
        BugResolutionRecord(
            bug_id="bug2",
            resolved=True,
            resolution_path="template",
            llm_tokens_used=0,
            wall_clock_time_s=1.0,
            peak_memory_mb=120.0
        ),
        # Bug 3: Failed resolution (LLM timeout), 500 tokens, 60 seconds
        BugResolutionRecord(
            bug_id="bug3",
            resolved=False,
            resolution_path="llm",
            llm_tokens_used=500,
            wall_clock_time_s=60.0,
            peak_memory_mb=150.0
        ),
        # Bug 4: Resolved via cache, 0 tokens, 0.5 seconds
        BugResolutionRecord(
            bug_id="bug4",
            resolved=True,
            resolution_path="cache",
            llm_tokens_used=0,
            wall_clock_time_s=0.5,
            peak_memory_mb=90.0
        )
    ]

    # Hand-calculated expectations:
    # Total processed = 4
    # Total resolved = 3
    # Total tokens = 1500
    # Total time = 71.5
    # Peak memory = 150.0

    # Tokens per verified patch (only resolved matter):
    # LLM (1000) + Template (0) + Cache (0) = 1000 / 3 = 333.333...

    # Time per verified patch (only resolved matter):
    # LLM (10.0) + Template (1.0) + Cache (0.5) = 11.5 / 3 = 3.833...

    # % resolved without LLM:
    # Template + Cache = 2 out of 3 resolved = 66.666...%

    summary = generate_run_summary(records, "test_run_1", tmp_path)

    assert summary.total_bugs_processed == 4
    assert summary.total_bugs_resolved == 3
    assert summary.total_tokens_used == 1500
    assert summary.total_time_s == 71.5
    assert summary.peak_memory_mb == 150.0

    assert abs(summary.tokens_per_verified_patch - 333.33) < 0.1
    assert abs(summary.average_time_per_verified_patch_s - 3.83) < 0.1
    assert abs(summary.percent_resolved_without_llm - 66.66) < 0.1

    # Check JSON output
    json_path = tmp_path / "test_run_1" / "summary.json"
    assert json_path.exists()

    data = json.loads(json_path.read_text())
    assert data["total_bugs_resolved"] == 3
    assert data["total_tokens_used"] == 1500


def test_generate_run_summary_empty(tmp_path):
    """Test handling of empty records / no bugs resolved to avoid divide-by-zero."""
    summary = generate_run_summary([], "empty_run", tmp_path)
    assert summary.total_bugs_processed == 0
    assert summary.total_bugs_resolved == 0
    assert summary.tokens_per_verified_patch == 0.0
    assert summary.average_time_per_verified_patch_s == 0.0
    assert summary.percent_resolved_without_llm == 0.0
