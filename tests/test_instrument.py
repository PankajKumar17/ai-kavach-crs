"""Tests for the instrument module."""

import subprocess
from pathlib import Path

import pytest

from ai_kavach.instrument import BuildError, build_target

TARGETS_DIR = Path(__file__).parent.parent / "targets"
SAMPLE_VULN_DIR = TARGETS_DIR / "sample_vuln"


def test_build_target_success():
    """Test that building a valid target succeeds and returns a valid path."""
    bin_path = build_target(SAMPLE_VULN_DIR)
    assert bin_path.exists()
    assert bin_path.is_file()


def test_build_target_crashes_under_asan():
    """Test that the compiled binary actually crashes under ASan when given an oversized argument."""
    bin_path = build_target(SAMPLE_VULN_DIR)
    
    # Run the binary with an oversized argument (more than 16 bytes)
    # Our mock clang generates a .bat file that exits 1 and prints buffer-overflow
    cmd = [str(bin_path), "A" * 32]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    assert result.returncode != 0
    assert "buffer-overflow" in result.stderr


def test_build_target_missing_dir():
    """Test that building a non-existent directory raises BuildError."""
    missing_dir = TARGETS_DIR / "does_not_exist"
    with pytest.raises(BuildError) as exc_info:
        build_target(missing_dir)
        
    assert "does not exist" in str(exc_info.value)
    assert str(missing_dir) in str(exc_info.value)
