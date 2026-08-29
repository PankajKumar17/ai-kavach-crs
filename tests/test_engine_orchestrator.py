"""Tests for the engine's demo orchestrator (engine/orchestrator.py)."""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ENGINE_DIR = Path(__file__).resolve().parent.parent / "engine"


def _load_engine_module():
    """Import engine/orchestrator.py (not a package) by file path."""
    spec = importlib.util.spec_from_file_location(
        "engine_orchestrator", ENGINE_DIR / "orchestrator.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["engine_orchestrator"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def eng():
    return _load_engine_module()


class FakeResponse:
    def __init__(self, text, stop_reason="end_turn"):
        self.stop_reason = stop_reason
        self.content = [types.SimpleNamespace(type="text", text=text)]


VULN = '''
def get_user_data(username):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        return cursor.fetchall()
    finally:
        conn.close()
'''

FIXED_MARKER = "cursor.execute(query, (username,))"


def _run_with(eng, monkeypatch, client):
    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", lambda: client)
    return eng.call_llm_for_patch(VULN)


@pytest.fixture
def fake_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-dummy")


class FakeClient:
    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error
        self.messages = self

    def create(self, **kwargs):
        if self._error:
            raise self._error
        return self._response


def test_fenced_reply_used_directly(eng, monkeypatch, fake_key):
    fixed_code = VULN.replace('cursor.execute(query)', 'cursor.execute(query, (username,))')
    reply = f"Here is the fix:\n```python{fixed_code}```\nDone."
    result = _run_with(eng, monkeypatch, FakeClient(FakeResponse(reply)))
    assert FIXED_MARKER in result


def test_unfenced_python_accepted(eng, monkeypatch, fake_key):
    fixed = VULN.replace("cursor.execute(query)", "cursor.execute(query, (username,))")
    result = _run_with(eng, monkeypatch, FakeClient(FakeResponse(fixed)))
    assert FIXED_MARKER in result


def test_interpolating_patch_rejected(eng, monkeypatch, fake_key):
    # A "fix" that still formats input into SQL must be rejected -> mock fallback.
    bad = VULN  # unchanged vulnerable code as the "patch"
    result = _run_with(eng, monkeypatch, FakeClient(FakeResponse(f"```python\n{bad}\n```")))
    assert FIXED_MARKER in result and "'{" not in result


def test_truncated_reply_falls_back(eng, monkeypatch, fake_key):
    result = _run_with(eng, monkeypatch, FakeClient(FakeResponse("partial...", stop_reason="max_tokens")))
    assert FIXED_MARKER in result and "'{" not in result


def test_api_error_falls_back(eng, monkeypatch, fake_key):
    import anthropic
    import httpx

    err = anthropic.APIConnectionError(request=httpx.Request("POST", "https://x"))
    result = _run_with(eng, monkeypatch, FakeClient(error=err))
    assert FIXED_MARKER in result and "'{" not in result


def test_refusal_falls_back(eng, monkeypatch, fake_key):
    result = _run_with(eng, monkeypatch, FakeClient(FakeResponse("I cannot help with that.")))
    assert FIXED_MARKER in result and "'{" not in result


def test_no_key_uses_mock(eng, monkeypatch):
    """Without a key the deterministic mock path patches without any API call."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = eng.call_llm_for_patch(VULN)
    assert FIXED_MARKER in result and "'{" not in result
