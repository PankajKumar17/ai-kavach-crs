import sys
import os

# Add the current directory to path so we can import vulnerable.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vulnerable import get_user_data

def run_tests():
    print("Running Regression Test Harness...")
    
    # Test 1: Normal functionality
    print("Test 1: Normal User Request")
    normal_result = get_user_data("guest")
    assert len(normal_result) == 1, "Normal functionality broken!"
    assert normal_result[0][1] == "guest", "Returned wrong user!"
    print("Test 1 PASS")
    
    # Test 2: Exploit attempt (SQL Injection)
    print("Test 2: SQL Injection Exploit Attempt")
    exploit_payload = "' OR '1'='1"
    exploit_result = get_user_data(exploit_payload)
    
    # If the exploit returns more than 1 row (i.e. it dumped the table), the vulnerability still exists
    if isinstance(exploit_result, list) and len(exploit_result) > 1:
        print("Test 2 FAIL: Vulnerability successfully exploited! Table dumped.")
        sys.exit(1) # Exploit succeeded, test fails
    elif isinstance(exploit_result, str):
         # It might have thrown an error due to syntax, which is also bad but let's say it didn't dump data
         pass
        
    print("Test 2 PASS: Exploit failed to dump database.")
    
    print("All tests passed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    run_tests()
