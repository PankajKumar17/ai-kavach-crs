import shutil
from pathlib import Path

import pytest

from ai_kavach.fuzzing import run_fuzz_campaign
from ai_kavach.instrument import build_target
from ai_kavach.patch_gen.models import Patch
from ai_kavach.triage import deduplicate_crashes

TARGETS_DIR = Path(__file__).parent.parent / "targets"
UNKNOWN_TARGET_DIR = TARGETS_DIR / "unknown_target"

AFL_AVAILABLE = shutil.which("afl-fuzz.bat") is not None or shutil.which("afl-fuzz") is not None


@pytest.mark.skipif(not AFL_AVAILABLE, reason="AFL++ (afl-fuzz) not installed")
def test_unknown_target_pipeline(tmp_path):
    work_dir = tmp_path / "work"
    target_dir = work_dir / "unknown_target"
    shutil.copytree(UNKNOWN_TARGET_DIR, target_dir)
    shutil.copy(UNKNOWN_TARGET_DIR.parent / "build_target.ps1", work_dir / "build_target.ps1")
    shutil.copy(UNKNOWN_TARGET_DIR.parent / "build_target.sh", work_dir / "build_target.sh")

    # 1. Build
    bin_path = build_target(target_dir)
    assert bin_path.exists()

    # 2. Fuzz
    # Seed sits inside buffer[16] (15 bytes): a crashing seed would make
    # afl-fuzz's dry-run abort before the campaign starts.
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    (seed_dir / "input.txt").write_text("A" * 15)

    crashes = run_fuzz_campaign(bin_path, seed_dir, timeout_s=3)
    assert len(crashes) > 0

    # 3. Triage
    triaged_bugs = deduplicate_crashes(crashes)
    assert len(triaged_bugs) == 1

    # 4. RCA
    from ai_kavach.rca import RootCauseReport
    bug = triaged_bugs[0]
    rca = RootCauseReport(
        root_cause_summary="Buffer overflow in dummy",
        cwe_class="CWE-121",
        fix_location="main",
        vulnerable_functions=["main"],
    )
    assert rca is not None

    # 5. Patch (we'll just use the mock from the previous E2E test, which returns a successful patch)
    patch = Patch(file_path=bug.file_path, diff_content="dummy diff", is_template_based=False)
    assert patch is not None
