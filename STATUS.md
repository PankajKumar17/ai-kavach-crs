# AI Kavach Cyber Reasoning System - Final Status

## Overview
AI Kavach is an autonomous vulnerability discovery and patching pipeline built for the Indian Army Terrier Cyber Quest 2026. This repository successfully demonstrates an end-to-end "Golden Path" for triaging, RCA, patch generation, and verification using a mock LLM-driven workflow and automated fuzzing.

## What Works (100% Golden Path)
1. **Target Build Instrumentation**: Clang/ASan flags are dynamically injected for instrumented builds.
2. **Automated Fuzzing**: A mock (and extensible) fuzzer loop discovers crashes using standard inputs.
3. **Static Analysis (Semgrep)**: Identifies reachable dangerous functions (e.g. `strcpy`).
4. **Triage**: ASan trace parsing, deduplication, and severity scoring correctly identifies the heap buffer overflow.
5. **Root Cause Analysis (RCA)**: An LLM (Anthropic Claude 3.5 Sonnet) determines the buggy lines.
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
- **Symbolic Execution**: This prototype lacks true symbolic execution (e.g. angr/KLEE) for path discovery, relying purely on static analysis (Semgrep) and fuzzing.
- **Fuzzer Backend**: While the code calls a subprocess, a true production CRS would integrate deeply with libFuzzer/AFL++ via shared memory, rather than shelling out.
- **Environment**: Due to the local Windows environment for development, Linux-specific utilities (`clang`, `afl-fuzz`) were mocked using batch scripts.
- **Target Complexity**: The current `sample_vuln` is a simple `argc`/`argv` parsing C program. Complex targets like web servers or deeply nested state machines would require more advanced harness synthesis and snapshot fuzzing.
- **Model Context Limitations**: We use `claude-3-5-sonnet-20241022`. For a massive codebase, RAG (Retrieval-Augmented Generation) or repository-level context management would be required.

## How to Run

### Install Dependencies
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest pytest-asyncio pytest-cov pytest-mock httpx
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
