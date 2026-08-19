"""Watchdog and circuit-breaker layer."""

import json
import logging
import threading
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TimeoutException(Exception):
    pass


class MaxRetriesExceeded(Exception):
    pass


def log_incident(run_id: str, stage: str, error_msg: str, output_dir: Path = Path("runs")):
    """Log an incident to the run's incidents.jsonl file."""
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    incidents_file = run_dir / "incidents.jsonl"
    
    incident = {
        "timestamp": time.time(),
        "stage": stage,
        "error": error_msg
    }
    
    with open(incidents_file, "a") as f:
        f.write(json.dumps(incident) + "\n")


def run_with_timeout(func, args, kwargs, timeout_s):
    """Run a function with a timeout using a thread."""
    result = []
    exc = []

    def wrapper():
        try:
            result.append(func(*args, **kwargs))
        except Exception as e:
            exc.append(e)

    thread = threading.Thread(target=wrapper)
    thread.daemon = True
    thread.start()
    thread.join(timeout_s)

    if thread.is_alive():
        # In Python, we can't cleanly kill a thread easily.
        # But we can at least return and let it die when it finishes or blocks.
        raise TimeoutException(f"Function {func.__name__} timed out after {timeout_s} seconds.")
    
    if exc:
        raise exc[0]
        
    if not result and not exc:
        # Edge case if thread dies before appending
        raise Exception("Function terminated unexpectedly.")
        
    return result[0]


def watchdog(timeout_s: float, max_retries: int = 3, run_id_kwarg: str = "run_id"):
    """
    Decorator to enforce timeout and retries on a pipeline stage.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            run_id = kwargs.get(run_id_kwarg, "default_run")
            output_dir = kwargs.pop("output_dir", Path("runs"))
            
            attempt = 0
            last_exception = None
            
            while attempt < max_retries:
                attempt += 1
                try:
                    # Execute with timeout
                    return run_with_timeout(func, args, kwargs, timeout_s)
                except TimeoutException as e:
                    last_exception = e
                    log_incident(run_id, func.__name__, str(e), output_dir)
                    break # Don't retry on hard timeout
                except Exception as e:
                    last_exception = e
                    log_incident(run_id, func.__name__, f"Attempt {attempt} failed: {e}", output_dir)
                    if attempt < max_retries:
                        time.sleep(2 ** attempt) # Exponential backoff
            
            log_incident(run_id, func.__name__, "Max retries exceeded or fatal error", output_dir)
            raise MaxRetriesExceeded(f"Stage {func.__name__} failed after {attempt} attempts: {last_exception}")
        return wrapper
    return decorator
