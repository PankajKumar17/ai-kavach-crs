"""Tests for the LLM patch generation module."""

from pathlib import Path
from unittest.mock import MagicMock

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
    mock_client = mocker.patch("ai_kavach.patch_gen.llm_patch.Anthropic")
    
    valid_diff = "--- a/vuln.c\n+++ b/vuln.c\n@@ -1,5 +1,5 @@\n-strcpy(dest, src);\n+strncpy(dest, src, n);"
    
    # Setup mock response
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=valid_diff)]
    mock_client.return_value.messages.create.return_value = mock_response
    
    patches = generate_patch_candidates(dummy_bug, dummy_root_cause, "code context", n=2)
    
    assert len(patches) == 2
    for patch in patches:
        assert isinstance(patch, Patch)
        assert patch.diff_content == valid_diff
        
    # Assert API was called twice with different temperatures
    assert mock_client.return_value.messages.create.call_count == 2
    calls = mock_client.return_value.messages.create.call_args_list
    assert calls[0].kwargs["temperature"] != calls[1].kwargs["temperature"]


def test_generate_patch_malformed_retry(mocker, dummy_bug, dummy_root_cause):
    """Test that a malformed response triggers exactly one retry."""
    mock_client = mocker.patch("ai_kavach.patch_gen.llm_patch.Anthropic")
    
    malformed_response = MagicMock()
    malformed_response.content = [MagicMock(text="Here is the fix: just add a bounds check!")]
    
    valid_diff_response = MagicMock()
    valid_diff_response.content = [MagicMock(text="--- a/vuln.c\n+++ b/vuln.c\n@@ -1 +1 @@\n-bad\n+good")]
    
    # First call returns malformed, second returns valid diff
    mock_client.return_value.messages.create.side_effect = [malformed_response, valid_diff_response]
    
    patches = generate_patch_candidates(dummy_bug, dummy_root_cause, "context", n=1)
    
    assert len(patches) == 1
    assert "good" in patches[0].diff_content
    
    # The client should have been called twice (1 initial + 1 retry)
    assert mock_client.return_value.messages.create.call_count == 2
    
    # The retry should include the strict instruction
    retry_call_args = mock_client.return_value.messages.create.call_args_list[1]
    assert "CRITICAL:" in retry_call_args.kwargs["messages"][0]["content"]


def test_generate_patch_double_malformed(mocker, dummy_bug, dummy_root_cause):
    """Test that two malformed responses raise an error."""
    mock_client = mocker.patch("ai_kavach.patch_gen.llm_patch.Anthropic")
    
    malformed_response = MagicMock()
    malformed_response.content = [MagicMock(text="Not a diff at all")]
    
    # Always return malformed
    mock_client.return_value.messages.create.return_value = malformed_response
    
    with pytest.raises(PatchGenerationError) as exc_info:
        generate_patch_candidates(dummy_bug, dummy_root_cause, "context", n=1)
        
    assert "Failed to generate any valid patch" in str(exc_info.value)
    # 1 initial + 1 retry = 2 calls
    assert mock_client.return_value.messages.create.call_count == 2


def test_regenerate_with_feedback(mocker, dummy_bug, dummy_root_cause):
    """Test that regenerate_with_feedback includes the prior patch and failure reason."""
    mock_client = mocker.patch("ai_kavach.patch_gen.llm_patch.Anthropic")
    
    valid_diff = "--- a/vuln.c\n+++ b/vuln.c\n@@ -1 +1 @@\n-bad\n+good"
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=valid_diff)]
    mock_client.return_value.messages.create.return_value = mock_response
    
    failed_patch = Patch(file_path=Path("vuln.c"), diff_content="--- a/vuln.c\n+++ b/vuln.c\n@@ -1 +1 @@\n-bad\n+still_bad")
    failure_reason = "Compilation failed: implicit declaration of function 'still_bad'"
    
    new_patch = regenerate_with_feedback(dummy_bug, dummy_root_cause, failed_patch, failure_reason)
    
    assert new_patch.diff_content == valid_diff
    
    # Assert on prompt contents
    call_args = mock_client.return_value.messages.create.call_args
    prompt_content = call_args.kwargs["messages"][0]["content"]
    assert "still_bad" in prompt_content
    assert failure_reason in prompt_content
