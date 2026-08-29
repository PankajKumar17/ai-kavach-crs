"""Watchdog and circuit-breaker layer."""

import atexit
import json
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from functools import wraps
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Bounded shared executor: repeated timeouts reuse pooled threads instead of
# spawning a fresh fire-and-forget thread per call.
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="watchdog")

# Futures that outlived their caller's patience. They keep running (Python
# cannot kill a thread) but are tracked so they can be drained on shutdown.
_ORPHANED_FUTURES: set[Future] = set()
_ORPHANS_LOCK = threading.Lock()


def _reap_orphans(shutdown_timeout_s: float = 10.0):
    """Best-effort wait for orphaned work at interpreter shutdown."""
    with _ORPHANS_LOCK:
        orphans = list(_ORPHANED_FUTURES)
        _ORPHANED_FUTURES.clear()
    for fut in orphans:
        try:
            fut.result(timeout=shutdown_timeout_s)
        except Exception:
            pass  # Best effort: the work's outcome no longer matters.


atexit.register(_reap_orphans)


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
    """
    Run a function with a timeout on the shared watchdog executor.

    On timeout the future is tracked as orphaned (the underlying work cannot
    be killed in Python) and drained at interpreter shutdown by _reap_orphans,
    so abandoned work never accumulates unbounded or dies silently mid-write.
    """
    future = _EXECUTOR.submit(func, *args, **kwargs)
    try:
        return future.result(timeout=timeout_s)
    except TimeoutError:
        with _ORPHANS_LOCK:
            _ORPHANED_FUTURES.add(future)
        raise TimeoutException(
            f"Function {func.__name__} timed out after {timeout_s} seconds."
        ) from None


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
