"""Tests for the LLM patch generation module."""

from pathlib import Path

import pytest

from ai_kavach.patch_gen.llm_patch import (
    PatchGenerationError,
    generate_patch_candidates,
    regenerate_with_feedback,
)
from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport
from ai_kavach.triage import TriagedBug


@pytest.fixture
def dummy_bug():
    return TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["vuln_func"],
        file_path=Path("vuln.c"),
        line_number=42,
        severity=10,
        hash_signature="hash",
        original_crashes=[]
    )


@pytest.fixture
def dummy_root_cause():
    return RootCauseReport(
        root_cause_summary="Buffer overflow in strcpy",
        cwe_class="CWE-121",
        fix_location="crash_site",
        vulnerable_functions=["vuln_func"]
    )


def test_generate_patch_candidates_success(mocker, dummy_bug, dummy_root_cause):
    """Test generating n patch candidates from mocked distinct responses."""
    mock_client = mocker.MagicMock()

    valid_diff = "--- a/vuln.c\n+++ b/vuln.c\n@@ -1,5 +1,5 @@\n-strcpy(dest, src);\n+strncpy(dest, src, n);"

    # Setup mock response
    mock_client.create_message.return_value = {
        "content": [{"type": "text", "text": valid_diff}],
        "stop_reason": "end_turn",
    }
    mocker.patch("ai_kavach.patch_gen.llm_patch.create_client", return_value=mock_client)

    patches = generate_patch_candidates(dummy_bug, dummy_root_cause, "code context", n=2)

    assert len(patches) == 2
    for patch in patches:
        assert isinstance(patch, Patch)
        assert patch.diff_content == valid_diff

    # Assert API was called twice with different temperatures
    assert mock_client.create_message.call_count == 2
    calls = mock_client.create_message.call_args_list
    assert calls[0].kwargs["temperature"] != calls[1].kwargs["temperature"]


def test_generate_patch_malformed_retry(mocker, dummy_bug, dummy_root_cause):
    """Test that a malformed response triggers exactly one retry."""
    mock_client = mocker.MagicMock()

    # First call returns malformed, second returns valid diff
    mock_client.create_message.side_effect = [
        {
            "content": [{"type": "text", "text": "Here is the fix: just add a bounds check!"}],
            "stop_reason": "end_turn",
        },
        {
            "content": [{"type": "text", "text": "--- a/vuln.c\n+++ b/vuln.c\n@@ -1 +1 @@\n-bad\n+good"}],
            "stop_reason": "end_turn",
        }
    ]
    mocker.patch("ai_kavach.patch_gen.llm_patch.create_client", return_value=mock_client)

    patches = generate_patch_candidates(dummy_bug, dummy_root_cause, "context", n=1)

    assert len(patches) == 1
    assert "good" in patches[0].diff_content

    # The client should have been called twice (1 initial + 1 retry)
    assert mock_client.create_message.call_count == 2

    # The retry should include the strict instruction
    retry_call_args = mock_client.create_message.call_args_list[1]
    assert "CRITICAL:" in retry_call_args.kwargs["messages"][0]["content"]


def test_generate_patch_accepts_repo_relative_diff_against_absolute_path(mocker):
    """
    Web-mode regression: bug.file_path is an ABSOLUTE path (orchestrator's
    _finding_to_triaged_bug resolves it), while the LLM correctly emits
    repo-relative diff headers (--- a/app/main.py). The validator must
    accept the suffix match, not reject every valid patch.
    """
    mock_client = mocker.MagicMock()

    valid_diff = "--- a/app/main.py\n+++ b/app/main.py\n@@ -10,3 +10,3 @@\n-pickle.loads(data)\n+json.loads(data)"

    mock_client.create_message.return_value = {
        "content": [{"type": "text", "text": valid_diff}],
        "stop_reason": "end_turn",
    }
    mocker.patch("ai_kavach.patch_gen.llm_patch.create_client", return_value=mock_client)

    abs_bug = TriagedBug(
        crash_type="Automatic Memory Pinning/Pickles",
        top_frames=["loads"],
        file_path=Path("C:/tmp/targets/a727fd74/source/app/main.py"),
        line_number=12,
        severity=9,
        hash_signature="h2",
        original_crashes=[],
    )
    rc = RootCauseReport(
        root_cause_summary="Insecure deserialization",
        cwe_class="CWE-502",
        fix_location="crash_site",
        vulnerable_functions=["loads"],
    )

    patches = generate_patch_candidates(abs_bug, rc, "context", n=1)

    assert len(patches) == 1
    assert patches[0].diff_content == valid_diff


def test_validate_diff_still_rejects_wrong_file():
    """A diff pointing at a genuinely different file must still be rejected."""
    import pytest

    from ai_kavach.patch_gen.llm_patch import parse_diff

    with pytest.raises(ValueError, match="Diff targets"):
        parse_diff(
            "--- a/other/unrelated.c\n+++ b/other/unrelated.c\n@@ -1 +1 @@\n-bad\n+good",
            str(Path("C:/tmp/targets/x/source/main.c")),
        )


def test_generate_patch_double_malformed(mocker, dummy_bug, dummy_root_cause):
    """Test that two malformed responses raise an error."""
    mock_client = mocker.MagicMock()

    # Always return malformed
    mock_client.create_message.return_value = {
        "content": [{"type": "text", "text": "Not a diff at all"}],
        "stop_reason": "end_turn",
    }
    mocker.patch("ai_kavach.patch_gen.llm_patch.create_client", return_value=mock_client)

    with pytest.raises(PatchGenerationError) as exc_info:
        generate_patch_candidates(dummy_bug, dummy_root_cause, "context", n=1)

    assert "Failed to generate any valid patch" in str(exc_info.value)
    # 1 initial + 1 retry = 2 calls
    assert mock_client.create_message.call_count == 2


def test_regenerate_with_feedback(mocker, dummy_bug, dummy_root_cause):
    """Test that regenerate_with_feedback includes the prior patch and failure reason."""
    mock_client = mocker.MagicMock()

    valid_diff = "--- a/vuln.c\n+++ b/vuln.c\n@@ -1 +1 @@\n-bad\n+good"
    mock_client.create_message.return_value = {
        "content": [{"type": "text", "text": valid_diff}],
        "stop_reason": "end_turn",
    }
    mocker.patch("ai_kavach.patch_gen.llm_patch.create_client", return_value=mock_client)

    failed_patch = Patch(
        file_path=Path("vuln.c"),
        diff_content="--- a/vuln.c\n+++ b/vuln.c\n@@ -1 +1 @@\n-bad\n+still_bad",
    )
    failure_reason = "Compilation failed: implicit declaration of function 'still_bad'"

    new_patch = regenerate_with_feedback(dummy_bug, dummy_root_cause, failed_patch, failure_reason)

    assert new_patch.diff_content == valid_diff

    # Assert on prompt contents
    call_args = mock_client.create_message.call_args
    prompt_content = call_args.kwargs["messages"][0]["content"]
    assert "still_bad" in prompt_content
    assert failure_reason in prompt_content
