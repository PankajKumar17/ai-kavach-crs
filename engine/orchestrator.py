import os
import sys
import time
import subprocess
import json

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
    with open(TARGET_FILE, "r") as f:
        code = f.read()
    
    if "f\"SELECT * FROM users WHERE username = '{username}'\"" in code:
        log("VULNERABILITY FOUND: SQL Injection detected at get_user_data().")
        log("  -> Using f-strings to format SQL queries allows arbitrary SQL execution.")
        return True, code
    
    log("No vulnerabilities detected by Static Analysis.")
    return False, code

def call_llm_for_patch(code):
    """
    Calls an LLM to generate a patch.
    If no API key is provided, falls back to a deterministic mock LLM for reliable demoing.
    """
    log("Sending vulnerable code and context to LLM for reasoning...")
    time.sleep(3) # Simulate network delay
    
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("GEMINI_API_KEY")
    
    if not api_key:
        log("No LLM API Key found in environment. Using Local Deterministic Mock LLM for demo purposes.")
        # MOCK LLM REASONING
        log("LLM Reasoner: The code directly concatenates user input into the SQL query.")
        log("LLM Reasoner: This can be exploited by passing `' OR '1'='1`.")
        log("LLM Reasoner: The fix is to use parameterized queries (`?`) provided by sqlite3.")
        time.sleep(2)
        
        patched_code = code.replace(
            "query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    \n    try:\n        cursor.execute(query)",
            "query = \"SELECT * FROM users WHERE username = ?\"\n    \n    try:\n        cursor.execute(query, (username,))"
        )
        return patched_code
    else:
        # Here you would actually call the OpenAI or Gemini SDK.
        # For this prototype, we'll just log that we would call it.
        log(f"Calling real LLM API with key starting with {api_key[:4]}...")
        # ... (Actual LLM SDK Call) ...
        return code # Placeholder

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
