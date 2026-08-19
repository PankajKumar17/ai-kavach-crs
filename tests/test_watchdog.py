import time

import pytest

from ai_kavach.watchdog import MaxRetriesExceeded, watchdog


@watchdog(timeout_s=1.0, max_retries=2)
def slow_function(run_id="test"):
    time.sleep(2.0)
    return True


@watchdog(timeout_s=5.0, max_retries=3)
def failing_function(run_id="test"):
    raise ValueError("I always fail")


class FlakyService:
    def __init__(self):
        self.attempts = 0

    @watchdog(timeout_s=5.0, max_retries=3)
    def flaky_function(self, run_id="test"):
        self.attempts += 1
        if self.attempts < 3:
            raise RuntimeError("Transient error")
        return "Success!"


def test_watchdog_timeout(tmp_path):
    start = time.time()
    
    with pytest.raises(MaxRetriesExceeded) as exc:
        slow_function(run_id="timeout_test", output_dir=tmp_path)
        
    duration = time.time() - start
    
    # Should timeout at 1s, plus some small overhead
    assert duration < 1.5, f"Timeout failed, took {duration}s"
    assert "timed out" in str(exc.value)
    
    # Check incidents
    incidents_file = tmp_path / "timeout_test" / "incidents.jsonl"
    assert incidents_file.exists()
    lines = incidents_file.read_text().splitlines()
    assert len(lines) > 0
    assert "timed out" in lines[0]


def test_watchdog_max_retries(tmp_path):
    with pytest.raises(MaxRetriesExceeded) as exc:
        failing_function(run_id="retry_test", output_dir=tmp_path)
        
    incidents_file = tmp_path / "retry_test" / "incidents.jsonl"
    assert incidents_file.exists()
    lines = incidents_file.read_text().splitlines()
    
    # Attempt 1, Attempt 2, Attempt 3, Final failure
    assert len(lines) == 4
    assert "Attempt 1 failed" in lines[0]
    assert "Attempt 3 failed" in lines[2]


def test_watchdog_flaky_success(tmp_path):
    service = FlakyService()
    
    result = service.flaky_function(run_id="flaky_test", output_dir=tmp_path)
    assert result == "Success!"
    assert service.attempts == 3
    
    incidents_file = tmp_path / "flaky_test" / "incidents.jsonl"
    assert incidents_file.exists()
    lines = incidents_file.read_text().splitlines()
    
    # Attempt 1 and 2 failed, but 3 succeeded, so final failure wasn't logged
    assert len(lines) == 2
    assert "Attempt 1 failed" in lines[0]
    assert "Attempt 2 failed" in lines[1]
