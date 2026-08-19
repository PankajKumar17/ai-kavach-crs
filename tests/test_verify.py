"""Tests for the patch verification module."""

import shutil
from pathlib import Path

import pytest

from ai_kavach.fuzzing import CrashArtifact
from ai_kavach.patch_gen.models import Patch
from ai_kavach.patch_gen.templates import try_template_fix
from ai_kavach.triage import TriagedBug
from ai_kavach.verify import verify_patch

TARGETS_DIR = Path(__file__).parent.parent / "targets"
SAMPLE_VULN_DIR = TARGETS_DIR / "sample_vuln"


@pytest.fixture
def fresh_sample_vuln(tmp_path):
    """Provide a fresh copy of the vulnerable target for each test."""
    dest = tmp_path / "sample_vuln"
    shutil.copytree(SAMPLE_VULN_DIR, dest)
    # Copy the build script too so build_target works if we don't mock it
    shutil.copy(SAMPLE_VULN_DIR.parent / "build_target.ps1", dest.parent / "build_target.ps1")
    return dest


@pytest.fixture
def dummy_bug(fresh_sample_vuln):
    # Create a dummy crash input that triggers the overflow
    crash_file = fresh_sample_vuln / "crash.txt"
    crash_file.write_text("A" * 32)
    
    crash = CrashArtifact(
        input_path=crash_file,
        exit_signal=11,
        stderr="buffer-overflow"
    )
    
    return TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["main"],
        file_path=str(fresh_sample_vuln / "vuln.c"),
        line_number=7,
        severity=10,
        hash_signature="hash",
        original_crashes=[crash]
    )


def test_verify_patch_happy_path(fresh_sample_vuln, dummy_bug, mocker):
    """Test that applying a real working patch passes all checks."""
    # We will use try_template_fix to generate a real patch
    vuln_c = fresh_sample_vuln / "vuln.c"
    source = vuln_c.read_text()
    
    # Adjust bug to point to the correct file path
    dummy_bug.file_path = vuln_c
    
    patch = try_template_fix(dummy_bug, source)
    assert patch is not None
    
    # Mock fuzzing to be fast and return no crashes (as the fix should prevent them)
    mocker.patch("ai_kavach.verify.run_fuzz_campaign", return_value=[])
    
    # Since patch command might not be installed on Windows CI trivially, 
    # and git apply requires a repo, we'll mock `apply_patch` to just write the patched content directly
    def mock_apply(p, backup=True):
        backup_path = p.file_path.with_suffix(".bak")
        shutil.copy(p.file_path, backup_path)
        
        # Manually apply our simple template patch
        # diff format is rough, so we just use python string replace for the test
        # Actually try_template_fix returns a diff. We can just replace the whole file for this test
        patched_src = source.replace("strcpy(buffer, argv[1]);", "if (strlen(argv[1]) < sizeof(buffer)) { strcpy(buffer, argv[1]); } else { }")
        p.file_path.write_text(patched_src)
        return backup_path
        
    mocker.patch("ai_kavach.verify.apply_patch", side_effect=mock_apply)
    
    result = verify_patch(patch, dummy_bug, fresh_sample_vuln)
    
    assert result.verified is True
    assert result.failed_stage is None


def test_verify_patch_negative_case(fresh_sample_vuln, dummy_bug, mocker):
    """Test that a bad patch which suppresses the symptom but doesn't fix the bug is caught."""
    vuln_c = fresh_sample_vuln / "vuln.c"
    
    # Construct a bad patch that just prints a message but leaves the overflow
    bad_patch = Patch(
        file_path=vuln_c,
        diff_content="fake diff",
        is_template_based=False
    )
    
    def mock_apply(p, backup=True):
        backup_path = p.file_path.with_suffix(".bak")
        shutil.copy(p.file_path, backup_path)
        # The bad patch does nothing to fix the vulnerability
        return backup_path
        
    mocker.patch("ai_kavach.verify.apply_patch", side_effect=mock_apply)
    
    # Replay will run the compiled binary on the A*32 file. It should still crash!
    # Because our mock compile on Windows writes a script that crashes if arg > 16
    # Let's mock subprocess.run in replay to explicitly return a crash if needed, 
    # but the real binary will actually crash.
    
    result = verify_patch(bad_patch, dummy_bug, fresh_sample_vuln)
    
    assert result.verified is False
    assert result.failed_stage == "replay"
    assert "Crash still occurs" in result.failure_reason


def test_verify_patch_build_failure(fresh_sample_vuln, dummy_bug, mocker):
    """Test that a patch which fails to compile is caught immediately."""
    vuln_c = fresh_sample_vuln / "vuln.c"
    
    bad_patch = Patch(
        file_path=vuln_c,
        diff_content="fake diff",
        is_template_based=False
    )
    
    def mock_apply(p, backup=True):
        backup_path = p.file_path.with_suffix(".bak")
        shutil.copy(p.file_path, backup_path)
        return backup_path
        
    mocker.patch("ai_kavach.verify.apply_patch", side_effect=mock_apply)
    mocker.patch("ai_kavach.verify.build_target", side_effect=__import__('ai_kavach.instrument').instrument.BuildError("Build failed"))
    
    result = verify_patch(bad_patch, dummy_bug, fresh_sample_vuln)
    
    assert result.verified is False
    assert result.failed_stage == "build"
    assert "Build failed" in result.failure_reason
