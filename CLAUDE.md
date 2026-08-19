# AI Kavach Cyber Reasoning System

## Project Description
A cyber-reasoning system for the AI Kavach hackathon (Indian Army Terrier Cyber Quest 2026) that autonomously finds a vulnerability in a target codebase, generates a patch with an LLM, and proves the fix holds via a regression harness.

## Planned Modules
- `fuzzing/`
- `static_analysis/`
- `triage/`
- `rca/`
- `patch_gen/`
- `verify/`
- `orchestrator/`
- `dashboard/`

## Design Priorities (In Order)
1. Reliability over technique coverage
2. Resource efficiency (minimize LLM calls)
3. Lightweight single-machine footprint

## IMPORTANT RULES & SCOPE
**No model training or fine-tuning is required or in scope anywhere in this project.** All reasoning uses the Claude API/Agent SDK as-is via prompting. Do not propose, scaffold, or start building a training pipeline, dataset collection process, or model-weight customization at any point — if a step seems to need better model behavior, the fix is a better prompt or better retrieved context, not training.

## Definition of Done
A module is complete only when:
(a) Every public function has type hints and a docstring.
(b) It has pytest tests covering the happy path AND at least one failure/edge case.
(c) `pytest -v` passes with zero failures.
(d) `ruff check .` passes clean.

**State clearly:** never report a step as finished without having actually run the tests and shown the passing output.
