"""Tests for the RCA module."""

import os
from unittest.mock import MagicMock

import pytest
from anthropic import APIConnectionError

from ai_kavach.rca import RCAError, analyze_root_cause
from ai_kavach.triage import TriagedBug


@pytest.fixture
def dummy_bug():
    return TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["vuln_func", "main"],
        file_path="vuln.c",
        line_number=42,
        severity=10,
        hash_signature="hash",
        original_crashes=[]
    )


def test_analyze_root_cause_success(mocker, dummy_bug):
    """Test successful parsing of a mocked LLM response."""
    mock_client = mocker.patch("ai_kavach.rca.Anthropic")
    
    # Setup mock response
    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(text='{"root_cause_summary": "Buffer overflow in vuln_func", "cwe_class": "CWE-121", "fix_location": "crash_site", "vulnerable_functions": ["vuln_func"]}')
    ]
    mock_client.return_value.messages.create.return_value = mock_response
    
    report = analyze_root_cause(dummy_bug, "void vuln_func(char* buf) { strcpy(...) }", max_retries=1)
    
    assert report.cwe_class == "CWE-121"
    assert report.fix_location == "crash_site"
    assert "vuln_func" in report.vulnerable_functions
    
    # Assert context scoping (the code context was passed in the prompt)
    call_args = mock_client.return_value.messages.create.call_args
    assert "void vuln_func(char* buf)" in call_args.kwargs["messages"][0]["content"]


def test_analyze_root_cause_retries(mocker, dummy_bug):
    """Test that the function retries on transient errors and eventually raises RCAError."""
    # We mock time.sleep to avoid actually waiting during tests
    mocker.patch("time.sleep")
    mock_client = mocker.patch("ai_kavach.rca.Anthropic")
    
    # Make the API raise an error every time
    mock_client.return_value.messages.create.side_effect = APIConnectionError(
        message="Connection failed",
        request=MagicMock()
    )
    
    with pytest.raises(RCAError) as exc_info:
        analyze_root_cause(dummy_bug, "code context", max_retries=3)
        
    assert "RCA failed after 3 attempts" in str(exc_info.value)
    
    # Assert the API was called 3 times
    assert mock_client.return_value.messages.create.call_count == 3


@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="needs a real API key")
def test_analyze_root_cause_live(dummy_bug):
    """Live integration test hitting the real Anthropic API."""
    code_context = """
    #include <string.h>
    void vuln_func(char* input) {
        char buf[16];
        strcpy(buf, input); // overflow here
    }
    """
    
    report = analyze_root_cause(dummy_bug, code_context)
    
    assert report is not None
    assert "buffer" in report.root_cause_summary.lower() or "overflow" in report.root_cause_summary.lower()
    assert report.fix_location in ["crash_site", "earlier_in_chain"]
