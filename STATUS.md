# AI Kavach Cyber Reasoning System - Final Status

## Overview
AI Kavach is an autonomous vulnerability discovery and patching pipeline built for the Indian Army Terrier Cyber Quest 2026. This repository successfully demonstrates an end-to-end "Golden Path" for triaging, RCA, patch generation, and verification using a mock LLM-driven workflow and automated fuzzing.

## Current Test & Lint Status (as of 2026-08-24)

### WSL2 Ubuntu 24.04 (real AFL++ + real clang — primary environment) — **49 passed, 3 skipped, 0 failed**
- The full suite, including every AFL++-gated test, passes under WSL with a Linux-native venv (`.venv-wsl`, Python 3.12). The step-17 golden-path end-to-end proof (`test_end_to_end_pipeline`) runs for real: afl-fuzz discovers the crash, triage parses the ASan trace, the template patcher generates a bounds-check fix, and the verification harness proves it holds.
- Skips (environment-gated, not failures):
- AFL++ integration fixes that made this possible:
  - `targets/build_target.sh` now prefers `afl-clang-fast`, so binaries carry the coverage instrumentation afl-fuzz requires ("No instrumentation detected" abort).
  - `fuzzing.py` runs afl-fuzz with `-m none -t 5000` and sets `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` / `AFL_SKIP_CPUFREQ=1`. The fixed `-t` matters: AFL++'s auto-calibrated timeout (~20 ms) is far too tight for sanitizer builds under WSL and every exec would be misread as a hang. `-t 1000` was also too tight for ASan+UBSan builds.
  - `targets/sample_vuln/vuln.c` and `targets/unknown_target/vuln.c` now read their input from a file (`@@` style) so afl-fuzz can drive them; they fall back to treating argv[1] as a literal string for direct invocation.
  - Fuzz campaigns start from a clean slate: stale `afl_out` state is removed and leftover crash files are purged, so a re-used run_id can never report a previous run's crashes.
  - Test seeds sit just *inside* the overflow threshold (15 bytes vs `buffer[16]`) — a seed that already crashes makes afl-fuzz's dry-run abort with "We need at least one valid input seed that does not crash!".

### Windows (native `.venv`) — **47 passed, 5 skipped, 0 failed**
- Same suite on Windows with the mocked clang/fuzzer shims in `.venv/Scripts`; all AFL++-gated tests skip there by design (no native afl-fuzz).

### Semgrep
Semgrep **is** installed on Windows and its tests run for real there: `test_static_analysis.py` passes 3/3, including a live Semgrep scan that finds the known `strcpy` buffer-copy bug in `sample_vuln`.

## What Works (100% Golden Path)
1. **Target Build Instrumentation**: Clang/ASan flags are dynamically injected for instrumented builds.
2. **Automated Fuzzing**: A mock (and extensible) fuzzer loop discovers crashes using standard inputs.
3. **Static Analysis (Semgrep)**: Identifies reachable dangerous functions (e.g. `strcpy`). Verified live against `sample_vuln`.
4. **Triage**: ASan trace parsing, deduplication, and severity scoring correctly identifies the heap buffer overflow.
5. **Root Cause Analysis (RCA)**: An LLM (Claude via Anthropic API) determines the buggy lines.
6. **Patch Generation**:
   - Uses **Hybrid Repair** to first attempt template-based fixes (fast, deterministic).
   - Falls back to **LLM Patch Generation** for complex logic bugs.
   - Includes a **Signature-based Instant-Fix Cache** to skip costly generation for known bug signatures.
7. **Verification**:
   - A verification harness proves the patch stops the crash.
   - The **LLM-as-judge Patch Critic** evaluates the patch for behavioral correctness and symptom-masking.
8. **Watchdog Layer**: Circuit breakers and exponential backoff ensure the pipeline gracefully handles flaky tests or stalled fuzzer runs.
9. **Harness Synthesis Agent**: Identifies fuzzable entry points and synthesizes simple harnesses.
10. **Claude Agent SDK Orchestration**: Uses scoped tool permissions and `@tool` decorators for subagents (`triage-agent`, `rca-agent`, `patch-agent`).
11. **Dashboard & Metrics**: A FastAPI web dashboard visualizes MTTD/MTTR and success rates.

## Known Limitations (Prototype vs. Real CRS)
- **AFL++ needs WSL/Linux**: The fuzzer backend shells out to `afl-fuzz`, which does not run natively on Windows. Run the full suite (including the step-17 end-to-end proof) inside WSL: `wsl -d Ubuntu -- bash -c 'cd /mnt/c/.../ai-kavach-crs && ./.venv-wsl/bin/python -m pytest'`. On Windows the same suite passes with mocked fuzzing; the AFL-gated tests skip there by design.
- **Symbolic Execution**: This prototype lacks true symbolic execution (e.g. angr/KLEE) for path discovery, relying purely on static analysis (Semgrep) and fuzzing.
- **Fuzzer Backend Integration**: While the code calls a subprocess, a true production CRS would integrate deeply with libFuzzer/AFL++ via shared memory, rather than shelling out.
- **Target Complexity**: The current `sample_vuln` is a simple `argc`/`argv` parsing C program. Complex targets like web servers or deeply nested state machines would require more advanced harness synthesis and snapshot fuzzing.
- **Model Context Limitations**: For a massive codebase, RAG (Retrieval-Augmented Generation) or repository-level context management would be required.

## How to Run

### Install Dependencies
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest pytest-asyncio pytest-cov pytest-mock httpx semgrep
pip install claude-agent-sdk
```

### Run Tests
```bash
pytest -v
```

### Run Pipeline (End-to-End)
```bash
python -m ai_kavach.cli run targets/sample_vuln
```

### Run Dashboard
```bash
python -m ai_kavach.cli dashboard
# Visit http://localhost:8000
```
