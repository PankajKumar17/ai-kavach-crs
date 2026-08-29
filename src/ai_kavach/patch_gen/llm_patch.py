"""LLM-based patch generation."""

import logging
from pathlib import Path

from ai_kavach.llm_client import (
    APIConnectionError,
    APIStatusError,
    LLMError,
    RateLimitError,
    create_client,
)
from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport
from ai_kavach.triage import TriagedBug

logger = logging.getLogger(__name__)


class PatchGenerationError(Exception):
    """Exception raised when LLM patch generation fails."""


def parse_diff(response_text: str, target_file: str) -> str:
    """
    Extract and validate a unified diff from an LLM response.

    The diff must reference target_file; diffs for other files are rejected
    so a plausible-looking patch for the wrong file can't reach git apply.
    """
    normalized_target = Path(target_file).as_posix()

    if "--- a/" in response_text and "+++ b/" in response_text and "@@" in response_text:
        # Extract just the diff block if there is surrounding markdown text
        lines = response_text.splitlines()
        diff_lines = []
        in_diff = False

        for line in lines:
            if line.startswith("--- a/"):
                in_diff = True

            if in_diff:
                if line.startswith("```"):
                    break
                diff_lines.append(line)

        if diff_lines:
            diff_text = "\n".join(diff_lines)
            _validate_diff_targets(diff_text, normalized_target)
            return diff_text

    raise ValueError("Response does not appear to be a unified diff.")


def _validate_diff_targets(diff_text: str, normalized_target: str) -> None:
    """
    Reject diffs whose --- a/ paths don't match the bug's file.

    The LLM typically emits repo-relative headers (--- a/app/main.py) while
    target_file may be an absolute path, so accept an exact match, a
    path-suffix match, or at minimum the same basename. A diff pointing at a
    genuinely different file is still rejected.
    """
    target = Path(normalized_target)
    for line in diff_text.splitlines():
        if line.startswith("--- a/"):
            diff_path = Path(line[len("--- a/"):].strip())
            matches = (
                diff_path == target
                # absolute bug path vs repo-relative diff header (either direction)
                or str(target).replace("\\", "/").endswith(diff_path.as_posix())
                or diff_path.as_posix().endswith(str(target).replace("\\", "/"))
                # last resort: same file name, different directory depth
                or diff_path.name == target.name
            )
            if not matches:
                raise ValueError(
                    f"Diff targets '{diff_path.as_posix()}' but expected '{normalized_target}'."
                )


def _response_text(response: dict) -> str:
    """Extract text from an API response, rejecting truncated replies."""
    if response["stop_reason"] in ("max_tokens", "length"):
        raise ValueError("Response truncated at max_tokens; diff would be incomplete.")
    return "".join(block["text"] for block in response["content"] if block["type"] == "text")


def _call_claude_for_patch(
    bug: TriagedBug,
    root_cause: RootCauseReport,
    code_context: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.5
) -> Patch:
    client = create_client()

    # First attempt
    try:
        response = client.create_message(
            messages=[{"role": "user", "content": user_prompt}],
            max_tokens=1500,
            temperature=temperature,
            system=system_prompt,
        )
        diff_text = parse_diff(_response_text(response), str(bug.file_path))
        return Patch(file_path=bug.file_path, diff_content=diff_text, is_template_based=False)
    except ValueError:
        # Failed to parse as diff. Retry once with a stricter instruction.
        retry_user_prompt = user_prompt + (
            "\n\nCRITICAL: Your previous response was not a valid unified diff. "
            "You MUST return ONLY a unified diff starting with `--- a/` and `+++ b/`. "
            "Do not include any explanations or markdown blocks around the diff."
        )

        try:
            retry_response = client.create_message(
                messages=[{"role": "user", "content": retry_user_prompt}],
                max_tokens=1500,
                temperature=temperature,
                system=system_prompt,
            )
            diff_text = parse_diff(_response_text(retry_response), str(bug.file_path))
            return Patch(file_path=bug.file_path, diff_content=diff_text, is_template_based=False)
        except ValueError as err:
            raise PatchGenerationError("LLM failed to produce a valid diff after retry.") from err
    except (LLMError, APIConnectionError, APIStatusError, RateLimitError) as e:
        raise PatchGenerationError(f"API Error: {e}") from e


def generate_patch_candidates(
    bug: TriagedBug, root_cause: RootCauseReport, code_context: str, n: int = 3
) -> list[Patch]:
    """
    Generate multiple distinct patch candidates for a bug.
    """
    system_prompt = (
        "You are an expert C/C++ security researcher fixing vulnerabilities. "
        "Generate a minimal patch to fix the provided bug. "
        "You MUST return ONLY a valid unified diff format. "
        "Do not provide explanations, only the raw diff text."
    )

    user_prompt = (
        f"Crash Type: {bug.crash_type}\n"
        f"Root Cause: {root_cause.root_cause_summary}\n"
        f"Fix Location: {root_cause.fix_location}\n"
        f"File: {bug.file_path}\n\n"
        f"Code Context:\n{code_context}\n\n"
        "Please provide a unified diff fixing the issue."
    )

    patches = []
    # Use increasing temperatures to get distinct patches
    temperatures = [0.2, 0.5, 0.8]

    for i in range(min(n, len(temperatures))):
        try:
            patch = _call_claude_for_patch(
                bug, root_cause, code_context, system_prompt, user_prompt,
                temperature=temperatures[i],
            )
            patches.append(patch)
        except PatchGenerationError as e:
            logger.warning("Patch candidate %d failed: %s", i + 1, e)
            continue

    if not patches:
        raise PatchGenerationError("Failed to generate any valid patch candidates.")

    return patches


def regenerate_with_feedback(
    bug: TriagedBug, root_cause: RootCauseReport, failed_patch: Patch, failure_reason: str
) -> Patch:
    """
    Regenerate a patch incorporating feedback from a previous failure.
    """
    system_prompt = (
        "You are an expert C/C++ security researcher fixing vulnerabilities. "
        "You MUST return ONLY a valid unified diff format."
    )

    user_prompt = (
        f"We tried to apply your previous patch for {bug.crash_type} in {bug.file_path}, but it failed.\n"
        f"Root Cause: {root_cause.root_cause_summary}\n\n"
        f"Failed Patch:\n{failed_patch.diff_content}\n\n"
        f"Failure Reason: {failure_reason}\n\n"
        "Please provide a NEW unified diff fixing the issue AND addressing the failure reason."
    )

    # We only need the code context if we need to remind the LLM, but we'll stick to a simpler prompt
    # to avoid blowing up the context, or we can pass it if we have it.

    return _call_claude_for_patch(bug, root_cause, "", system_prompt, user_prompt, temperature=0.7)
