"""Verification and regression harness."""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ai_kavach.fuzzing import run_fuzz_campaign
from ai_kavach.instrument import BuildError, build_target
from ai_kavach.patch_gen.models import Patch
from ai_kavach.triage import TriagedBug

# Cap for replaying one crash input against the patched binary.
REPLAY_TIMEOUT_S = 15


@dataclass
class VerificationResult:
    verified: bool
    failed_stage: str | None = None
    failure_reason: str | None = None


def _diff_target_files(diff_content: str) -> set[Path]:
    """Extract every file path a diff touches, relative to the apply directory."""
    targets = set()
    for line in diff_content.splitlines():
        if line.startswith("+++ b/"):
            targets.add(Path(line[len("+++ b/"):].strip()))
    return targets


def apply_patch(patch: Patch, backup: bool = True) -> list[tuple[Path, Path]]:
    """
    Applies a patch via `git apply` or `patch`.

    A diff may touch multiple files, so every file referenced by the diff is
    backed up before anything is applied. Returns a list of
    (original_path, backup_path) pairs; empty when backup=False.
    """
    if not patch.file_path.exists():
        raise FileNotFoundError(f"Cannot patch missing file: {patch.file_path}")

    apply_dir = patch.file_path.parent

    backups: list[tuple[Path, Path]] = []
    if backup:
        for target in _diff_target_files(patch.diff_content):
            original = target if target.is_absolute() else apply_dir / target
            if original.exists():
                backup_path = original.with_suffix(original.suffix + ".bak")
                shutil.copy(original, backup_path)
                backups.append((original, backup_path))
        # Always cover the primary file even if the diff header omits it
        # (defensive: some LLM diffs only use --- without matching +++).
        if all(orig != patch.file_path for orig, _ in backups):
            backup_path = patch.file_path.with_suffix(patch.file_path.suffix + ".bak")
            shutil.copy(patch.file_path, backup_path)
            backups.append((patch.file_path, backup_path))

    # Write the diff to a temporary file. Binary mode: git apply rejects CRLF
    # that write_text would emit on Windows.
    patch_file = apply_dir / "temp.patch"
    patch_file.write_bytes(patch.diff_content.encode())

    try:
        # Try `git apply` first, fall back to `patch`
        cmd = ["git", "apply", "--ignore-whitespace", str(patch_file)]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=apply_dir)

        if res.returncode != 0:
            # Fallback to plain patch
            # patch -p1 < temp.patch
            cmd = ["patch", "-p1", "-i", str(patch_file.name)]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=apply_dir)

            if res.returncode != 0:
                raise RuntimeError(f"Patch application failed:\n{res.stderr}\n{res.stdout}")
    finally:
        if patch_file.exists():
            patch_file.unlink()

    return backups


def restore_backups(backups: list[tuple[Path, Path]]):
    """Restore every file from its backup and remove the backup copies."""
    for original_path, backup_path in backups:
        if backup_path.exists():
            shutil.copy(backup_path, original_path)
            backup_path.unlink()


def verify_patch(patch: Patch, bug: TriagedBug, target_dir: Path) -> VerificationResult:
    """
    Verify a patch by compiling, replaying the crash, and short fuzzing.
    """
    backups: list[tuple[Path, Path]] = []

    try:
        # 1. Apply the patch
        try:
            backups = apply_patch(patch, backup=True)
        except Exception as e:
            return VerificationResult(verified=False, failed_stage="apply", failure_reason=str(e))

        # 2. Rebuild
        try:
            bin_path = build_target(target_dir)
        except BuildError as e:
            return VerificationResult(verified=False, failed_stage="build", failure_reason=str(e))

        # 3. Replay original crashes
        for crash in bug.original_crashes:
            if not crash.input_path.exists():
                continue

            cmd = [str(bin_path), str(crash.input_path)]
            # We don't want an empty string argument to cause issues, so we just run the bin
            # For sample_vuln, we actually pass the file content or path.
            # Usually AFL passes the path when @@ is used. For our sample, it reads argv[1].
            # Let's pass the content if it's a simple argv program, but strictly AFL passes the path.
            # We'll stick to passing the path like AFL @@ does.
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=REPLAY_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                # A patch that turns a crash into a hang has not fixed anything.
                return VerificationResult(
                    verified=False,
                    failed_stage="replay",
                    failure_reason=(
                        f"Replay of {crash.input_path.name} timed out after "
                        f"{REPLAY_TIMEOUT_S}s (patch likely introduced a hang)."
                    )
                )

            if res.returncode != 0:
                # Any nonzero exit on a known-crashing input counts as unfixed —
                # don't require an ASan banner, which raw SEGV/abort lacks.
                return VerificationResult(
                    verified=False,
                    failed_stage="replay",
                    failure_reason=f"Crash still occurs on input {crash.input_path.name}:\n{res.stderr}"
                )

        # 4. Short fuzz burst (60s)
        # We need a seed dir. Just use the original crashes as seeds.
        seed_dir = target_dir / ".verify_seeds"
        seed_dir.mkdir(exist_ok=True)
        for i, crash in enumerate(bug.original_crashes):
            if crash.input_path.exists():
                shutil.copy(crash.input_path, seed_dir / f"seed_{i}")

        if not any(seed_dir.iterdir()):
            # Fallback if no crashes exist
            (seed_dir / "dummy").write_text("dummy")

        new_crashes = run_fuzz_campaign(bin_path, seed_dir, timeout_s=60, run_id=f"verify_{bug.hash_signature}")

        # Clean up seeds
        shutil.rmtree(seed_dir, ignore_errors=True)

        if new_crashes:
            return VerificationResult(
                verified=False,
                failed_stage="fuzz_burst",
                failure_reason=f"Found {len(new_crashes)} new crashes during verification fuzzing."
            )

        # All checks passed
        return VerificationResult(verified=True)

    finally:
        # Restore the original files so the next candidate gets a clean slate
        restore_backups(backups)
