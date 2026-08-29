"""Triage and deduplication module."""

import hashlib
import re
from dataclasses import dataclass

from ai_kavach.fuzzing import CrashArtifact


@dataclass
class TriagedBug:
    crash_type: str
    top_frames: list[str]
    file_path: str
    line_number: int
    severity: int
    hash_signature: str
    original_crashes: list[CrashArtifact]
    # Raw sanitizer output of the first crash in this dedup group — surfaced
    # to the dashboard trace as evidence ("show the ASan trace" demo beat).
    asan_trace: str = ""


def parse_asan_trace(stderr: str) -> tuple[str | None, list[str], str | None, int | None]:
    """Parse ASan stderr to extract crash type, top 3 frames, and crash site (file:line)."""
    crash_type = None
    top_frames = []
    file_path = None
    line_number = None

    # E.g., ERROR: AddressSanitizer: heap-buffer-overflow on address...
    type_match = re.search(r"ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer): ([\w-]+)", stderr)
    if type_match:
        crash_type = type_match.group(1)

    # E.g., #0 0x12345 in func_name /path/to/file.c:42:5
    # Support Windows paths (e.g. C:\path) and Unix paths
    frame_pattern = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+([\w_]+)\s+(.*?):(\d+)")

    for line in stderr.splitlines():
        match = frame_pattern.search(line)
        if match:
            frame_idx = int(match.group(1))
            func_name = match.group(2)
            frame_file = match.group(3)
            frame_line = int(match.group(4))

            # Keep only the top 3 frames (usually #0, #1, #2)
            if len(top_frames) < 3:
                # Normalize frame (strip memory addresses, keep func name and approx file)
                # Just keep func name for deduplication to be robust against minor code shifts
                top_frames.append(func_name)

            # The first frame (#0) is usually the crash site
            if file_path is None and frame_idx == 0:
                file_path = frame_file
                line_number = frame_line

        # Some ASan traces might look slightly different, let's also try catching simpler ones
        elif len(top_frames) < 3 and " in " in line and line.strip().startswith("#"):
            parts = line.split(" in ")
            if len(parts) >= 2:
                func_part = parts[1].split()[0]
                top_frames.append(func_part)

    # If we couldn't parse the file/line from the frame, just set it to unknown
    if not file_path:
        file_path = "unknown"
        line_number = 0

    if not crash_type:
        # Fallback if no ASan header was found
        if "buffer-overflow" in stderr:
            crash_type = "buffer-overflow"
        else:
            crash_type = "unknown-crash"

    return crash_type, top_frames, file_path, line_number


def calculate_severity(crash_type: str) -> int:
    """Estimate severity based on crash type (higher is worse)."""
    memory_corruption_types = [
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
        "use-after-free",
        "use-after-scope",
        "double-free",
        "invalid-free"
    ]

    if any(mc in crash_type.lower() for mc in memory_corruption_types):
        return 10
    elif "null-dereference" in crash_type.lower() or "segv" in crash_type.lower():
        return 7
    elif "assertion" in crash_type.lower():
        return 3
    else:
        return 5


def deduplicate_crashes(crashes: list[CrashArtifact]) -> list[TriagedBug]:
    """
    Deduplicate crashes based on the top 3 stack frames.

    Returns a list of TriagedBug objects, ranked by severity (highest first).
    """
    deduped = {}

    for crash in crashes:
        crash_type, top_frames, file_path, line_number = parse_asan_trace(crash.stderr)

        # Create a hash signature from the normalized top 3 frames and crash type
        signature_str = f"{crash_type}:" + ",".join(top_frames)
        hash_signature = hashlib.sha256(signature_str.encode()).hexdigest()[:16]

        severity = calculate_severity(crash_type)

        if hash_signature not in deduped:
            deduped[hash_signature] = TriagedBug(
                crash_type=crash_type,
                top_frames=top_frames,
                file_path=file_path,
                line_number=line_number,
                severity=severity,
                hash_signature=hash_signature,
                original_crashes=[crash],
                asan_trace=crash.stderr or "",
            )
        else:
            deduped[hash_signature].original_crashes.append(crash)

    # Sort by severity descending
    return sorted(list(deduped.values()), key=lambda b: b.severity, reverse=True)
