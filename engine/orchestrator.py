import os
import re
import subprocess
import sys
import time

TARGET_FILE = os.path.join(os.path.dirname(__file__), "target_app", "vulnerable.py")
TEST_FILE = os.path.join(os.path.dirname(__file__), "target_app", "test_vulnerable.py")

def log(msg, step="SYS"):
    """Format logs similarly to the dashboard's subagent trace log."""
    ts = time.strftime("[%H:%M:%S]")
    print(f"{ts} {msg}")

def run_test_harness():
    """Runs the regression test and returns True if it passes, False otherwise."""
    log("Running regression test harness...")
    try:
        result = subprocess.run([sys.executable, TEST_FILE], capture_output=True, text=True, timeout=10)

        # Log the output for the user to see
        for line in result.stdout.splitlines():
            log(f"  > {line}")

        if result.returncode == 0:
            log("Regression tests passed. Vulnerability resolved.", "PASS")
            return True
        else:
            log(f"Test failed with return code {result.returncode}", "FAIL")
            return False
    except subprocess.TimeoutExpired:
        log("Test timed out.", "FAIL")
        return False

def analyze_code():
    """Simulates a static analysis tool finding a bug."""
    log("Starting Static Analysis on target_app/vulnerable.py...")
    time.sleep(2)
    with open(TARGET_FILE) as f:
        code = f.read()

    if "f\"SELECT * FROM users WHERE username = '{username}'\"" in code:
        log("VULNERABILITY FOUND: SQL Injection detected at get_user_data().")
        log("  -> Using f-strings to format SQL queries allows arbitrary SQL execution.")
        return True, code

    log("No vulnerabilities detected by Static Analysis.")
    return False, code

def _extract_code_block(text):
    """Pull a fenced ```python block out of an LLM reply; None if absent."""
    match = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # No fences: accept the whole reply only if it looks like Python source.
    if "def get_user_data" in text:
        return text.strip()
    return None


def _patch_with_claude(code):
    """
    Ask Claude to fix the vulnerability. Returns patched source, or None on
    any failure (API error, refusal, unparseable/truncated reply).
    """
    import anthropic

    from ai_kavach.config import CLAUDE_MODEL

    client = anthropic.Anthropic()  # Reads ANTHROPIC_API_KEY from env.

    system_prompt = (
        "You are a security engineer fixing a SQL injection vulnerability. "
        "Rewrite the given Python function so user input is passed via sqlite3 "
        "parameterized queries (?) instead of being formatted into the query string. "
        "Keep the function signature and behavior otherwise identical. "
        "Respond with ONLY a single fenced python code block containing the fixed file."
    )
    user_prompt = f"Vulnerable file:\n```python\n{code}\n```\n\nReturn the fixed file."

    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=2000,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    # A truncated reply would produce broken source; treat it as failure so
    # the caller can fall back instead of applying half a file.
    if response.stop_reason == "max_tokens":
        log("Claude reply truncated at max_tokens.", "WARN")
        return None

    text = "".join(
        b.text for b in response.content
        if getattr(b, "type", "text") == "text" and hasattr(b, "text")
    )
    return _extract_code_block(text)


def call_llm_for_patch(code):
    """
    Calls an LLM to generate a patch.
    If no ANTHROPIC_API_KEY is set — or the real call fails for any reason —
    falls back to a deterministic mock LLM so the demo always completes.
    """
    log("Sending vulnerable code and context to LLM for reasoning...")
    time.sleep(3) # Simulate network delay

    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if api_key:
        model_name = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
        log(f"Claude API key found ({api_key[:7]}...). Calling {model_name}...")
        try:
            patched = _patch_with_claude(code)
        except Exception as e:
            log(f"Claude API call failed: {e}", "WARN")
            patched = None

        if patched:
            # Sanity gate: never apply a "fix" that still formats input into SQL.
            if re.search(r"(f[\"']SELECT|%\s*username|\+\s*username)", patched):
                log("Claude's patch still interpolates input into SQL; rejecting.", "WARN")
            else:
                log("Received valid patch from Claude.", "PASS")
                return patched
        elif patched is not None:
            log("Could not extract usable code from Claude's reply.", "WARN")
        log("Falling back to deterministic mock LLM.", "SYS")
    else:
        log("No ANTHROPIC_API_KEY in environment. Using Local Deterministic Mock LLM for demo purposes.")

    # MOCK LLM REASONING (fallback path)
    log("LLM Reasoner: The code directly concatenates user input into the SQL query.")
    log("LLM Reasoner: This can be exploited by passing `' OR '1'='1`.")
    log("LLM Reasoner: The fix is to use parameterized queries (`?`) provided by sqlite3.")
    time.sleep(2)

    # Regex, not str.replace: the exact-match version silently stopped
    # matching when whitespace changed, turning the patch into a no-op.
    patched_code, n = re.subn(
        r"query = f\"SELECT \* FROM users WHERE username = '\{username\}'\"\s*\n\s*try:\n\s*cursor\.execute\(query\)",
        'query = "SELECT * FROM users WHERE username = ?"\n\n    try:\n        cursor.execute(query, (username,))',
        code,
    )
    if n == 0:
        log("Mock LLM could not locate the vulnerable query to patch.", "FAIL")
        return code
    return patched_code

def apply_patch(patched_code):
    """Applies the LLM generated patch back to the file."""
    log("Applying generated patch to target_app/vulnerable.py...")
    with open(TARGET_FILE, "w") as f:
        f.write(patched_code)
    log("Patch applied successfully.")

def run_autonomous_loop():
    """Main orchestrator loop."""
    log("--- STARTING AI KAVACH AUTONOMOUS REASONING LOOP ---")

    # 1. Baseline Test (Should fail if vulnerable)
    log("Phase 1: Baseline Verification")
    is_secure = run_test_harness()
    if is_secure:
        log("Target is already secure. Nothing to do.")
        return

    # 2. Analysis
    log("\nPhase 2: Discovery and Analysis")
    has_bug, original_code = analyze_code()

    if not has_bug:
        log("Failed to locate the vulnerability in code.")
        return

    # 3. LLM Reasoning and Patching
    log("\nPhase 3: AI Reasoning & Patch Generation")
    patched_code = call_llm_for_patch(original_code)

    # 4. Apply Patch
    log("\nPhase 4: Patch Application")
    apply_patch(patched_code)

    # 5. Verify Patch (Regression Test)
    log("\nPhase 5: Patch Verification")
    time.sleep(1) # Wait for file system flush
    is_fixed = run_test_harness()

    if is_fixed:
        log("FINAL: Vulnerability fixed successfully! [PASS]")
    else:
        log("FINAL: Patch failed to resolve the vulnerability. [FAIL]")

        # Rollback (optional but good practice)
        log("Rolling back to original code...")
        with open(TARGET_FILE, "w") as f:
            f.write(original_code)

if __name__ == "__main__":
    run_autonomous_loop()
