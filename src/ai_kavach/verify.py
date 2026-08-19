"""Verification and regression harness."""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ai_kavach.fuzzing import run_fuzz_campaign
from ai_kavach.instrument import BuildError, build_target
from ai_kavach.patch_gen.models import Patch
from ai_kavach.triage import TriagedBug


@dataclass
class VerificationResult:
    verified: bool
    failed_stage: str | None = None
    failure_reason: str | None = None


def apply_patch(patch: Patch, backup: bool = True) -> Path | None:
    """
    Applies a patch via `git apply` or `patch`.
    Returns the path to the backup file if created.
    """
    if not patch.file_path.exists():
        raise FileNotFoundError(f"Cannot patch missing file: {patch.file_path}")

    backup_path = None
    if backup:
        backup_path = patch.file_path.with_suffix(patch.file_path.suffix + ".bak")
        shutil.copy(patch.file_path, backup_path)
        
    # Write the diff to a temporary file
    patch_file = patch.file_path.parent / "temp.patch"
    patch_file.write_text(patch.diff_content)
    
    try:
        # Try `git apply` first, fall back to `patch`
        cmd = ["git", "apply", "--ignore-whitespace", str(patch_file)]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=patch.file_path.parent)
        
        if res.returncode != 0:
            # Fallback to plain patch
            # patch -p1 < temp.patch
            cmd = ["patch", "-p1", "-i", str(patch_file.name)]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=patch.file_path.parent)
            
            if res.returncode != 0:
                raise RuntimeError(f"Patch application failed:\n{res.stderr}\n{res.stdout}")
    finally:
        if patch_file.exists():
            patch_file.unlink()
            
    return backup_path


def restore_backup(original_path: Path, backup_path: Path):
    """Restore a file from its backup."""
    if backup_path and backup_path.exists():
        shutil.copy(backup_path, original_path)
        backup_path.unlink()


def verify_patch(patch: Patch, bug: TriagedBug, target_dir: Path) -> VerificationResult:
    """
    Verify a patch by compiling, replaying the crash, and short fuzzing.
    """
    backup_path = None
    
    try:
        # 1. Apply the patch
        try:
            backup_path = apply_patch(patch, backup=True)
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
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            if res.returncode != 0 and ("AddressSanitizer" in res.stderr or "buffer-overflow" in res.stderr or "SEGV" in res.stderr):
                # The patch failed to fix the crash
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
        # Restore the original file so the next candidate gets a clean slate
        restore_backup(patch.file_path, backup_path)
