"""Root Cause Analysis module using LLM."""

import json
import time
from dataclasses import dataclass

from ai_kavach.llm_client import (
    APIConnectionError,
    APIStatusError,
    LLMError,
    RateLimitError,
    create_client,
)
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
    client = create_client()

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
    # Total wall-clock ceiling for the whole retry loop. max_retries bounds
    # attempts, but with per-call timeouts of LLM_CALL_TIMEOUT_S each, a
    # bad-luck stall on every attempt could otherwise run ~30 min. The
    # template patch tier covers resolution when RCA gives up here.
    budget_s = float(__import__("os").environ.get("RCA_TIME_BUDGET_S", "240"))
    deadline = time.monotonic() + budget_s
    while attempt < max_retries and time.monotonic() < deadline:
        try:
            response = client.create_message(
                messages=[{"role": "user", "content": user_prompt}],
                max_tokens=1000,
                system=system_prompt,
            )

            # A truncated JSON payload will never parse; retrying the identical
            # prompt at the same budget would fail the same way.
            if response["stop_reason"] in ("max_tokens", "length"):
                raise RCAError("RCA response truncated (max_tokens). Increase the token budget.")

            # Extract text from normalized response
            text = "".join(block["text"] for block in response["content"] if block["type"] == "text")
            if not text.strip():
                raise ValueError("Empty RCA response text.")
            # Very simple JSON extraction, assuming the model returns purely JSON
            json_str = text[text.find("{"):text.rfind("}")+1]

            parsed = json.loads(json_str)
            return RootCauseReport(
                root_cause_summary=parsed.get("root_cause_summary", "Unknown"),
                cwe_class=parsed.get("cwe_class", "Unknown"),
                fix_location=parsed.get("fix_location", "crash_site"),
                vulnerable_functions=parsed.get("vulnerable_functions", [])
            )

        except RCAError:
            raise  # Non-retryable: truncation needs a bigger budget, not another try.
        except (RateLimitError, APIConnectionError, TimeoutError) as e:
            attempt += 1
            if attempt >= max_retries:
                raise RCAError(f"RCA failed after {max_retries} attempts. Last error: {e}") from e
            time.sleep(2 ** attempt)  # Exponential backoff
        except LLMError as e:
            # Generic LLM client failure that is NOT one of the retryable
            # subclasses above — create_message already exhausted every model
            # (or hit its turn budget). Retrying the identical turn cannot
            # succeed faster than the budget just burned; fail fast.
            raise RCAError(f"RCA failed: {e}") from e
        except APIStatusError as e:
            # Only transient server-side errors are worth retrying; 4xx won't succeed.
            if e.status_code >= 500:
                attempt += 1
                if attempt >= max_retries:
                    raise RCAError(f"RCA failed after {max_retries} attempts. Last error: {e}") from e
                time.sleep(2 ** attempt)
            raise RCAError(f"RCA API request rejected (HTTP {e.status_code}): {e}") from e
        except (json.JSONDecodeError, ValueError) as e:
            attempt += 1
            if attempt >= max_retries:
                raise RCAError(f"RCA failed after {max_retries} attempts. Last error: {e}") from e
            time.sleep(2 ** attempt)  # Exponential backoff

    # Loop exited by budget exhaustion rather than max_retries.
    raise RCAError(
        f"RCA gave up after {attempt} attempt(s) within the "
        f"{budget_s:.0f}s wall-clock budget."
    )
