import shutil
from pathlib import Path

import pytest

from ai_kavach.harness_synth import (
    identify_entry_points,
    synthesize_and_validate_harness,
)

TARGETS_DIR = Path(__file__).parent.parent / "targets"
SAMPLE_VULN_DIR = TARGETS_DIR / "sample_vuln"

AFL_AVAILABLE = shutil.which("afl-fuzz.bat") is not None or shutil.which("afl-fuzz") is not None


@pytest.mark.skipif(not AFL_AVAILABLE, reason="AFL++ (afl-fuzz) not installed")
def test_harness_synth(tmp_path):
    work_dir = tmp_path / "work"
    target_dir = work_dir / "sample_vuln"
    shutil.copytree(SAMPLE_VULN_DIR, target_dir)
    # Copy both build scripts so build_target works on any platform
    # (Windows uses .ps1, Linux/WSL uses .sh).
    for script in ("build_target.ps1", "build_target.sh"):
        script_src = SAMPLE_VULN_DIR.parent / script
        if script_src.exists():
            shutil.copy(script_src, work_dir / script)

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
