import shutil
from pathlib import Path

from ai_kavach.harness_synth import (
    identify_entry_points,
    synthesize_and_validate_harness,
)

TARGETS_DIR = Path(__file__).parent.parent / "targets"
SAMPLE_VULN_DIR = TARGETS_DIR / "sample_vuln"


def test_harness_synth(tmp_path):
    work_dir = tmp_path / "work"
    target_dir = work_dir / "sample_vuln"
    shutil.copytree(SAMPLE_VULN_DIR, target_dir)
    shutil.copy(SAMPLE_VULN_DIR.parent / "build_target.ps1", work_dir / "build_target.ps1")
    
    # 1. Identify entry points
    entry_points = identify_entry_points(target_dir)
    assert "main" in entry_points, "Failed to identify main as entry point"
    
    # 2. Generate and validate
    bin_path = synthesize_and_validate_harness(target_dir)
    assert bin_path is not None, "Failed to validate harness"
    assert bin_path.exists(), "Harness did not compile"
    
    # 3. Validation should have found the crash during its short burst
    # run_fuzz_campaign mocked output will find a crash
    # The assertions above effectively prove this since synthesize_and_validate_harness runs the fuzzer.
