"""LLM-as-judge patch critic."""


from ai_kavach.llm_client import create_client
from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport


class CriticUnavailableError(Exception):
    """Raised when the critic cannot render a verdict (API failure, empty reply)."""


def evaluate_patch_with_critic(patch: Patch, rca: RootCauseReport, clean_input: str, clean_output: str) -> str | None:
    """
    Evaluate a proposed patch to ensure it actually fixes the root cause
    rather than just suppressing symptoms.

    Returns None if approved, or a string describing the concern if flagged.

    Raises:
        CriticUnavailableError: If the critic API call fails or returns no text.
            Callers must treat this as "not approved" — the critic fails closed.
    """
    prompt = f"""
You are an expert C/C++ security reviewer. Evaluate this patch.

Root Cause Report:
{rca.root_cause_summary}

Proposed Patch:
{patch.diff_content}

Clean Input: {clean_input}
Expected Clean Output: {clean_output}

Does this patch correctly address the underlying root cause? Or does it merely
suppress the crash symptom (e.g., catching a signal without fixing the overflow)?
Could this patch break legitimate behavior for the clean input?

If the patch is good and fixes the root cause, reply with exactly: APPROVE
If you have concerns, reply with CONCERN: followed by a brief explanation.
"""

    client = create_client()

    try:
        response = client.create_message(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.0,
        )

        reply = "".join(
            block["text"] for block in response["content"]
            if block["type"] == "text"
        ).strip()

    except Exception as e:
        # Fail closed: an unreachable critic must never count as an approval.
        raise CriticUnavailableError(f"Critic API call failed: {e}") from e

    if not reply:
        raise CriticUnavailableError("Critic returned an empty reply.")

    if reply.startswith("APPROVE"):
        return None
    elif reply.startswith("CONCERN:"):
        return reply[8:].strip()
    else:
        # Unrecognized verdict — treat it as a concern, never as approval.
        return reply
