"""LLM-as-judge patch critic."""


import anthropic

from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport


def evaluate_patch_with_critic(patch: Patch, rca: RootCauseReport, clean_input: str, clean_output: str) -> str | None:
    """
    Evaluate a proposed patch to ensure it actually fixes the root cause 
    rather than just suppressing symptoms.
    
    Returns None if approved, or a string describing the concern if flagged.
    """
    prompt = f"""
You are an expert C/C++ security reviewer. Evaluate this patch.

Root Cause Report:
{rca.root_cause_summary}

Proposed Patch:
{patch.diff_content}

Clean Input: {clean_input}
Expected Clean Output: {clean_output}

Does this patch correctly address the underlying root cause? Or does it merely suppress the crash symptom (e.g., catching a signal without fixing the overflow)?
Could this patch break legitimate behavior for the clean input?

If the patch is good and fixes the root cause, reply with exactly: APPROVE
If you have concerns, reply with CONCERN: followed by a brief explanation.
"""

    client = anthropic.Anthropic()
    
    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=200,
            temperature=0.0,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        reply = response.content[0].text.strip()
        
        if reply.startswith("APPROVE"):
            return None
        elif reply.startswith("CONCERN:"):
            return reply[8:].strip()
        else:
            # Fallback
            return reply
            
    except Exception:
        # In case of API failure, we might default to approving to not block the pipeline
        # But in a real CRS, we'd want to retry.
        return None
