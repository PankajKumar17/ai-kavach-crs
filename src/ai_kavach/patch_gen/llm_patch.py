"""LLM-based patch generation."""

import os

from anthropic import Anthropic, APIConnectionError, APIError, RateLimitError

from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport
from ai_kavach.triage import TriagedBug


class PatchGenerationError(Exception):
    """Exception raised when LLM patch generation fails."""


def parse_diff(response_text: str, target_file: str) -> str:
    """
    Very basic check to ensure the response looks like a unified diff.
    """
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
            return "\n".join(diff_lines)
            
    # If we couldn't cleanly extract, maybe it's just raw diff text.
    # Check if it has diff markers.
    if "@@" in response_text:
        return response_text
        
    raise ValueError("Response does not appear to be a unified diff.")


def _call_claude_for_patch(
    bug: TriagedBug, 
    root_cause: RootCauseReport, 
    code_context: str, 
    system_prompt: str, 
    user_prompt: str,
    temperature: float = 0.5
) -> Patch:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "dummy_test_key")
    client = Anthropic(api_key=api_key)

    # First attempt
    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1500,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        diff_text = parse_diff(response.content[0].text, str(bug.file_path))
        return Patch(file_path=bug.file_path, diff_content=diff_text, is_template_based=False)
    except ValueError:
        # Failed to parse as diff. Retry once with a stricter instruction.
        retry_user_prompt = user_prompt + "\n\nCRITICAL: Your previous response was not a valid unified diff. You MUST return ONLY a unified diff starting with `--- a/` and `+++ b/`. Do not include any explanations or markdown blocks around the diff."
        
        try:
            retry_response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1500,
                temperature=temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": retry_user_prompt}]
            )
            diff_text = parse_diff(retry_response.content[0].text, str(bug.file_path))
            return Patch(file_path=bug.file_path, diff_content=diff_text, is_template_based=False)
        except ValueError:
            raise PatchGenerationError("LLM failed to produce a valid diff after retry.")
    except (APIError, APIConnectionError, RateLimitError) as e:
        raise PatchGenerationError(f"API Error: {e}")


def generate_patch_candidates(bug: TriagedBug, root_cause: RootCauseReport, code_context: str, n: int = 3) -> list[Patch]:
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
            patch = _call_claude_for_patch(bug, root_cause, code_context, system_prompt, user_prompt, temperature=temperatures[i])
            patches.append(patch)
        except PatchGenerationError:
            continue
            
    if not patches:
        raise PatchGenerationError("Failed to generate any valid patch candidates.")
        
    return patches


def regenerate_with_feedback(bug: TriagedBug, root_cause: RootCauseReport, failed_patch: Patch, failure_reason: str) -> Patch:
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
