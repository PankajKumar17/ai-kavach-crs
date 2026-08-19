"""Root Cause Analysis module using LLM."""

import json
import os
import time
from dataclasses import dataclass

from anthropic import Anthropic, APIConnectionError, APIError, RateLimitError

from ai_kavach.triage import TriagedBug


class RCAError(Exception):
    """Exception raised when RCA fails after retries."""


@dataclass
class RootCauseReport:
    root_cause_summary: str
    cwe_class: str
    fix_location: str  # "crash_site" or "earlier_in_chain"
    vulnerable_functions: list[str]


def analyze_root_cause(bug: TriagedBug, code_context: str, max_retries: int = 3) -> RootCauseReport:
    """
    Analyze the root cause of a crash using an LLM.
    
    Args:
        bug: The triaged bug.
        code_context: The code snippet for the relevant function plus one call-graph level.
        max_retries: Maximum number of retries for the API call.
        
    Returns:
        A RootCauseReport containing the analysis.
        
    Raises:
        RCAError: If the analysis fails after max_retries.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    # For testing without a key, allow a dummy key if running tests. But fail fast in production.
    if not api_key:
        # Check if we are running in pytest
        if "PYTEST_CURRENT_TEST" not in os.environ:
            raise RuntimeError("ANTHROPIC_API_KEY is not set.")
        api_key = "dummy_test_key"
            
    client = Anthropic(api_key=api_key)

    system_prompt = (
        "You are an expert security researcher. Analyze the following crash and code context. "
        "Identify the actual root cause (not just the crash site), name the CWE class (e.g. CWE-121), "
        "and flag whether the fix belongs at the crash site or earlier in the call chain. "
        "Return your analysis strictly in JSON format with keys: "
        "'root_cause_summary', 'cwe_class', 'fix_location' (either 'crash_site' or 'earlier_in_chain'), "
        "and 'vulnerable_functions' (list of function names)."
    )

    user_prompt = (
        f"Crash Type: {bug.crash_type}\n"
        f"Stack Trace Top Frames: {bug.top_frames}\n"
        f"Crash Location: {bug.file_path}:{bug.line_number}\n\n"
        f"Code Context:\n{code_context}"
    )

    attempt = 0
    while attempt < max_retries:
        try:
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            # Extract JSON from response
            text = response.content[0].text
            # Very simple JSON extraction, assuming the model returns purely JSON
            json_str = text[text.find("{"):text.rfind("}")+1]
            
            parsed = json.loads(json_str)
            return RootCauseReport(
                root_cause_summary=parsed.get("root_cause_summary", "Unknown"),
                cwe_class=parsed.get("cwe_class", "Unknown"),
                fix_location=parsed.get("fix_location", "crash_site"),
                vulnerable_functions=parsed.get("vulnerable_functions", [])
            )
            
        except (APIError, APIConnectionError, RateLimitError, json.JSONDecodeError) as e:
            attempt += 1
            if attempt >= max_retries:
                raise RCAError(f"RCA failed after {max_retries} attempts. Last error: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff
