"""Fuzzing layer wrapping AFL++."""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# Cap on replaying a single crash input; a hanging input must not wedge the run.
REPLAY_TIMEOUT_S = 10


@dataclass
class CrashArtifact:
    input_path: Path
    exit_signal: int
    stderr: str


def run_fuzz_campaign(
    target_binary: Path, seed_dir: Path, timeout_s: int, run_id: str = "default_run"
) -> list[CrashArtifact]:
    """
    Run an AFL++ fuzzing campaign.

    Args:
        target_binary: Path to the target binary.
        seed_dir: Path to the seed corpus directory.
        timeout_s: Fuzzing campaign duration in seconds.
        run_id: Unique identifier for the run.

    Returns:
        List of CrashArtifact objects found during fuzzing.
    """
    out_dir = Path("runs") / run_id / "afl_out"

    crashes_dest_dir = Path("runs") / run_id / "crashes"
    crashes_dest_dir.mkdir(parents=True, exist_ok=True)

    # Start from a clean slate. Stale AFL++ state in out_dir makes afl-fuzz
    # refuse to start, and leftover crash files would leak into this run's
    # results — a re-used run_id must never report a previous run's crashes.
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for stale_file in crashes_dest_dir.iterdir():
        if stale_file.is_file():
            stale_file.unlink()

    afl_crashes_dir = out_dir / "default" / "crashes"
    afl_crashes_dir.mkdir(parents=True, exist_ok=True)

    executable = "afl-fuzz.bat" if os.name == "nt" else "afl-fuzz"
    resolved = shutil.which(executable)
    if resolved is None:
        raise RuntimeError(
            f"{executable} is not installed or not on PATH. "
            "Install AFL++ (or place afl-fuzz on PATH) to run fuzz campaigns."
        )
    cmd = [
        resolved,
        "-i", str(seed_dir),
        "-o", str(out_dir),
        "-m", "none",
        # Generous per-exec timeout. AFL++'s auto-calibrated default (~20ms)
        # is too tight for sanitizer builds under WSL, where every exec would
        # be misread as a hang and no crashes ever get saved.
        "-t", "5000",
        "--",
        str(target_binary),
        "@@"
    ]

    # Environment fixes so afl-fuzz starts outside a tuned Linux box:
    # - ASan-instrumented binaries reserve large shadow memory, which the
    #   default memory limit rejects; -m none lifts it.
    # - WSL/docker core_pattern is a pipe (systemd-coredump), which AFL++
    #   treats as "crashes may be lost" and aborts on. We collect crashes by
    #   exit code, so we can accept that risk.
    # - CPU frequency scaling makes AFL++'s calibration noisy; skip the check.
    env = os.environ.copy()
    env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
    env.setdefault("AFL_SKIP_CPUFREQ", "1")

    # Start the fuzzer
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    try:
        # Wait for the specified timeout
        process.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        pass
    finally:
        # Terminate cleanly
        if process.poll() is None:
            if os.name == "nt":
                # On Windows, SIGTERM is not well supported by Popen.terminate() for batch scripts,
                # but we'll try our best. taskkill is more reliable for tree kill.
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True)
            else:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()

    # Collect crashes
    crashes = []
    afl_crashes_dir = out_dir / "default" / "crashes"

    # Give the file system a moment to sync in case the process just died
    time.sleep(0.5)

    if afl_crashes_dir.exists():
        for crash_file in afl_crashes_dir.iterdir():
            if crash_file.is_file() and not crash_file.name.startswith("README"):
                dest_path = crashes_dest_dir / crash_file.name
                shutil.copy(crash_file, dest_path)

                # Replay the crash to get exit_signal and stderr.
                try:
                    res = subprocess.run(
                        [str(target_binary), str(dest_path)],
                        capture_output=True, text=True, timeout=REPLAY_TIMEOUT_S
                    )
                    exit_signal, stderr = res.returncode, res.stderr
                except subprocess.TimeoutExpired:
                    # A crash that now hangs is still a finding worth recording.
                    exit_signal, stderr = -1, "REPLAY TIMEOUT: input caused a hang"

                crashes.append(CrashArtifact(
                    input_path=dest_path,
                    exit_signal=exit_signal,
                    stderr=stderr
                ))

    return crashes
