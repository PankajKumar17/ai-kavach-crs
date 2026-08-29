"""Tests for the triage module."""

from pathlib import Path

from ai_kavach.fuzzing import CrashArtifact
from ai_kavach.triage import deduplicate_crashes, parse_asan_trace


def test_parse_real_asan_dump():
    """Test parsing a real-looking heap-buffer-overflow ASan dump."""
    asan_output = """
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018
READ of size 4 at 0x602000000018 thread T0
    #0 0x4011d6 in vulnerable_read /path/to/project/src/vuln.c:42:15
    #1 0x4012e5 in process_data /path/to/project/src/main.c:100:5
    #2 0x40156a in main /path/to/project/src/main.c:150:12
"""
    crash_type, top_frames, file_path, line_number = parse_asan_trace(asan_output)

    assert crash_type == "heap-buffer-overflow"
    assert len(top_frames) == 3
    assert top_frames[0] == "vulnerable_read"
    assert top_frames[1] == "process_data"
    assert top_frames[2] == "main"
    assert file_path == "/path/to/project/src/vuln.c"
    assert line_number == 42


def test_deduplicate_identical_stack_frames_different_addresses():
    """Test deduplicating crashes with same stack frames but different addresses."""
    crash1 = CrashArtifact(
        input_path=Path("input1.txt"),
        exit_signal=11,
        stderr="""
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x400010 in foo vuln.c:10
    #1 0x400020 in bar main.c:20
"""
    )

    crash2 = CrashArtifact(
        input_path=Path("input2.txt"),
        exit_signal=11,
        stderr="""
==2==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x500010 in foo vuln.c:10
    #1 0x500020 in bar main.c:20
"""
    )

    bugs = deduplicate_crashes([crash1, crash2])

    # Should dedupe to 1 bug
    assert len(bugs) == 1
    assert len(bugs[0].original_crashes) == 2
    assert bugs[0].crash_type == "heap-buffer-overflow"
    assert bugs[0].top_frames == ["foo", "bar"]


def test_no_deduplicate_different_root_cause():
    """Test that crashes with genuinely different stack traces do NOT dedupe."""
    crash1 = CrashArtifact(
        input_path=Path("input1.txt"),
        exit_signal=11,
        stderr="""
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x400010 in foo vuln.c:10
"""
    )

    crash2 = CrashArtifact(
        input_path=Path("input2.txt"),
        exit_signal=11,
        stderr="""
==2==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x500010 in baz other.c:30
"""
    )

    bugs = deduplicate_crashes([crash1, crash2])

    # Should remain 2 bugs
    assert len(bugs) == 2


def test_severity_ranking():
    """Test that a memory-corruption bug ranks higher severity than an assertion failure."""
    crash1 = CrashArtifact(
        input_path=Path("input1.txt"),
        exit_signal=6,
        stderr="""
==1==ERROR: AddressSanitizer: assertion-failure
    #0 0x400010 in assert_func assert.c:10
"""
    )

    crash2 = CrashArtifact(
        input_path=Path("input2.txt"),
        exit_signal=11,
        stderr="""
==2==ERROR: AddressSanitizer: stack-buffer-overflow
    #0 0x500010 in overflow_func vuln.c:30
"""
    )

    bugs = deduplicate_crashes([crash1, crash2])

    # Should remain 2 bugs, but the buffer overflow should be first
    assert len(bugs) == 2
    assert bugs[0].crash_type == "stack-buffer-overflow"
    assert bugs[0].severity > bugs[1].severity
    assert bugs[1].crash_type == "assertion-failure"
