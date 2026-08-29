"""Tests for LLM call timeout behavior and total-time budget enforcement."""
import os
import shutil
from pathlib import Path
from unittest import mock

import pytest

from ai_kavach.llm_client import LLMError
from ai_kavach.rca import RCAError


def _make_bug():
    """Minimal TriagedBug for RCA tests."""
    from ai_kavach.triage import TriagedBug

    return TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["main"],
        file_path="vuln.c",
        line_number=5,
        severity=10,
        hash_signature="deadbeef",
        original_crashes=[],
    )


def test_openrouter_call_respects_timeout(monkeypatch):
    """The 120s cap must actually be passed to the OpenRouter call."""
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy_test_key")
    from ai_kavach.llm_client import LLMClient

    client = LLMClient()
    assert client.provider == "openrouter"

    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            raise TimeoutError("simulated stall")

    fake_client = mock.MagicMock()
    fake_client.chat.completions = FakeCompletions()
    client.client = fake_client
    client._call_fn = client._call_openrouter

    with pytest.raises(TimeoutError):
        client._call_openrouter([{"role": "user", "content": "hi"}], 100, 0.0, None)

    assert captured.get("timeout") == float(os.environ.get("LLM_CALL_TIMEOUT_S", "120"))


def test_rca_total_budget_ceiling(monkeypatch):
    """
    analyze_root_cause must give up after max_retries even when every call
    times out — no unbounded retry storm.
    """
    from ai_kavach import rca as rca_mod

    calls = {"n": 0}

    class FakeClient:
        def create_message(self, *a, **k):
            calls["n"] += 1
            raise TimeoutError("stall")

    monkeypatch.setattr(rca_mod, "create_client", lambda: FakeClient())
    monkeypatch.setattr(rca_mod.time, "sleep", lambda s: None)  # skip backoff waits

    bug = _make_bug()
    with pytest.raises(RCAError):
        rca_mod.analyze_root_cause(bug, "int main(){return 0;}", max_retries=3)

    # Exactly max_retries attempts — bounded, not a loop
    assert calls["n"] == 3


def test_rca_wall_clock_budget(monkeypatch):
    """
    Even when attempts are individually fast to *start*, the whole RCA loop
    must respect RCA_TIME_BUDGET_S: a tiny budget cuts the retry loop short
    (fewer than max_retries calls) and raises instead of hanging.
    """
    import time as _time

    from ai_kavach import rca as rca_mod

    calls = {"n": 0}

    class SlowStartClient:
        def create_message(self, *a, **k):
            calls["n"] += 1
            # Burn real wall-clock WITHOUT touching time.sleep (the test
            # patches the shared time module's sleep to skip backoff).
            start = _time.monotonic()
            while _time.monotonic() - start < 0.3:
                pass
            raise TimeoutError("stall")

    monkeypatch.setattr(rca_mod, "create_client", lambda: SlowStartClient())
    monkeypatch.setenv("RCA_TIME_BUDGET_S", "1.0")  # budget < max_retries × per-attempt cost
    monkeypatch.setattr(rca_mod.time, "sleep", lambda s: None)  # skip backoff waits

    bug = _make_bug()
    with pytest.raises(RCAError):
        rca_mod.analyze_root_cause(bug, "int main(){return 0;}", max_retries=10)

    # Budget cut the loop well short of max_retries
    assert calls["n"] < 10


def test_turn_budget_stops_fallback_chain(monkeypatch):
    """
    One create_message turn (primary + fallbacks) must not exceed
    LLM_CALL_BUDGET_S: once the budget is burned by earlier models, later
    fallbacks are skipped without another full LLM_CALL_TIMEOUT_S wait.
    """
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy_test_key")
    monkeypatch.setenv("LLM_CALL_BUDGET_S", "2")
    monkeypatch.setenv("LLM_CALL_TIMEOUT_S", "120")  # per-call cap >> turn budget

    from ai_kavach.llm_client import LLMClient

    client = LLMClient()
    assert len(client.fallback_models) == 4

    started = {"n": 0}

    class StallCompletions:
        def create(self, **kwargs):
            started["n"] += 1
            # Each model attempt "stalls" ~0.8s of real time before failing;
            # with a 2s turn budget the chain must be cut before all 5 run.
            import time as _time

            start = _time.monotonic()
            while _time.monotonic() - start < 0.8:
                pass
            raise TimeoutError("simulated stall")

    fake = mock.MagicMock()
    fake.chat.completions = StallCompletions()
    client.client = fake

    with pytest.raises(LLMError):
        client.create_message([{"role": "user", "content": "hi"}], max_tokens=100)

    # Primary + at most the fallbacks that fit in ~2s of real stalls; the
    # chain must be cut far short of all 5 models.
    assert started["n"] < 5


def test_pipeline_falls_to_template_when_llm_stalls(tmp_path, monkeypatch):
    """
    C pipeline: LLM constructor fails (post-cap exhaustion) → template tier
    still patches and the run completes.

    Only the OS-dependent seams (build, fuzz, verify-rebuild) are mocked —
    those need clang/AFL++ and are covered by the WSL proof run. Everything
    under test here (orchestrator flow, triage→RCA→template→status wiring,
    try_template_fix itself) runs for real.
    """
    from ai_kavach import orchestrator as orch
    from ai_kavach.triage import TriagedBug
    from ai_kavach.verify import VerificationResult

    tgt = tmp_path / "tgt"
    tgt.mkdir()
    project_root = Path(__file__).parent.parent
    shutil.copy(project_root / "targets" / "sample_vuln" / "vuln.c", tgt / "vuln.c")

    # Seam 1: instrumented build (needs clang). Emit a fake binary.
    fake_bin = tgt / "target_bin"
    fake_bin.write_bytes(b"\x7fELF-mock")

    import ai_kavach.instrument as instrument_mod

    monkeypatch.setattr(instrument_mod, "build_target", lambda src, **k: fake_bin)

    # Seam 2: fuzz campaign (needs afl-fuzz). One crashing input.
    import ai_kavach.fuzzing as fuzzing_mod

    monkeypatch.setattr(fuzzing_mod, "run_fuzz_campaign", lambda *a, **k: [tmp_path / "crash1"])

    # Seam 3: triage. Real dedup needs ASan traces; hand it one real-shape bug
    # pointed at the copied vuln.c so try_template_fix matches against real source.
    bug = TriagedBug(
        crash_type="stack-buffer-overflow",
        top_frames=["main"],
        file_path=str(tgt / "vuln.c"),
        line_number=5,
        severity=10,
        hash_signature="abc123",
        original_crashes=[tmp_path / "crash1"],
    )

    import ai_kavach.triage as triage_mod

    monkeypatch.setattr(triage_mod, "deduplicate_crashes", lambda crashes: [bug])

    # Seam 4: verify rebuild/replay (needs clang again) → patch verified.
    ok = VerificationResult(verified=True, failed_stage=None, failure_reason=None)

    import ai_kavach.verify as verify_mod

    monkeypatch.setattr(verify_mod, "verify_patch", lambda patch, b, t: ok)

    # The failure mode under test: LLM client construction dies post-stall.
    class StallClient:
        def __init__(self):
            raise RuntimeError("LLM stalled past cap")

    monkeypatch.setattr(orch, "LLMClient", StallClient)

    trace: list[str] = []
    findings = orch._run_c_pipeline(tgt, "llm_stall_test", tmp_path / "runs", trace, lambda m: None)

    assert len(findings) >= 1, f"no findings; trace={trace}"
    f = findings[0]
    assert f["rca"] == "LLM unavailable"
    assert f["cwe"] == "CWE-unknown"
    assert f["verified"] is True  # template tier carried it
