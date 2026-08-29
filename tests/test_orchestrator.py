"""Tests for the pipeline orchestrator (src/ai_kavach/orchestrator.py)."""

import re
from pathlib import Path

import pytest

from ai_kavach import orchestrator as orch
from ai_kavach.orchestrator import (
    SKIP_DIRS,
    VULN_PATTERNS,
    _finding_to_triaged_bug,
    detect_target_mode,
    discover_files,
    static_scan,
)


def _make_tree(tmp_path: Path) -> Path:
    """Create a small source tree with one vulnerable JS file and one clean C file."""
    src = tmp_path / "proj"
    sub = src / "app"
    sub.mkdir(parents=True)
    (sub / "bad.js").write_text(
        "const el = document.getElementById('x');\n"
        "el.innerHTML = userInput;\n",
        encoding="utf-8",
    )
    (src / "clean.c").write_text(
        "#include <string.h>\nint main(void) { return 0; }\n",
        encoding="utf-8",
    )
    # node_modules must be skipped by discovery
    junk = src / "node_modules" / "pkg"
    junk.mkdir(parents=True)
    (junk / "evil.js").write_text("eval(input);\n", encoding="utf-8")
    return src


def test_discover_files_skips_node_modules(tmp_path):
    root = _make_tree(tmp_path)
    files = discover_files(root)
    rels = [str(f.relative_to(root)).replace("\\", "/") for f in files]
    assert "app/bad.js" in rels
    assert "clean.c" in rels
    assert not any("node_modules" in r for r in rels)


def test_discover_files_respects_max_files(tmp_path):
    root = tmp_path / "many"
    root.mkdir()
    for i in range(10):
        (root / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
    assert len(discover_files(root, max_files=3)) == 3


def test_skip_dirs_contains_common_noise():
    for d in ("node_modules", ".git", "__pycache__"):
        assert d in SKIP_DIRS


def test_static_scan_finds_innerhtml_and_dedups_per_file_type(tmp_path):
    src = tmp_path / "web"
    src.mkdir()
    # Two innerHTML sinks + one eval in the same file → only ONE XSS finding
    (src / "page.js").write_text(
        "a.innerHTML = x;\nb.innerHTML = y;\ndocument.write(z);\neval(w);\n",
        encoding="utf-8",
    )
    findings = static_scan([src / "page.js"], src)
    types = [f["type"] for f in findings]
    # One finding per (file, vuln_type): XSS appears once despite 3 sink lines
    assert types.count("Cross-Site Scripting") == 1
    assert any(f["severity"] == "HIGH" for f in findings)
    assert all(f["status"] == "Pending" for f in findings)
    assert all(f["location"].startswith("page.js:") for f in findings)


def test_static_scan_skips_import_lines(tmp_path):
    src = tmp_path / "imp"
    src.mkdir()
    # A require() line mentioning eval-like text must not be flagged
    (src / "m.js").write_text("const e = require('evallib');\n", encoding="utf-8")
    assert static_scan([src / "m.js"], src) == []


def test_vuln_patterns_have_triple_shape():
    for entry in VULN_PATTERNS:
        vuln_type, pattern, severity = entry
        assert isinstance(vuln_type, str) and vuln_type
        # Every regex must compile
        re.compile(pattern)
        assert severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_detect_target_mode_classifications(tmp_path):
    """c / web / mixed classification incl. the ambiguous Makefile+package.json case."""
    # C source + sibling build script (repo's targets/ layout) → c.
    # Each case gets its own isolated parent so sibling-marker checks don't
    # see markers meant for another case.
    c_root = tmp_path / "c_case"
    c_tgt = c_root / "tgt"
    c_tgt.mkdir(parents=True)
    (c_tgt / "vuln.c").write_text("int main(){return 0;}\n", encoding="utf-8")
    (c_root / "build_target.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    assert detect_target_mode(c_tgt) == "c"

    # C source but NO build entry anywhere → web (can't fuzz what won't build)
    no_build = tmp_path / "nobuild_case" / "tgt"
    no_build.mkdir(parents=True)
    (no_build / "vuln.c").write_text("int main(){return 0;}\n", encoding="utf-8")
    assert detect_target_mode(no_build) == "web"

    # JS-only → web
    web_tgt = tmp_path / "web_case" / "tgt"
    web_tgt.mkdir(parents=True)
    (web_tgt / "app.js").write_text("el.innerHTML = x;\n", encoding="utf-8")
    (web_tgt / "package.json").write_text("{}", encoding="utf-8")
    assert detect_target_mode(web_tgt) == "web"

    # Mixed: C extension with Makefile + JS frontend → BOTH pipelines
    mixed = tmp_path / "mixed_case" / "tgt"
    sub = mixed / "native"
    sub.mkdir(parents=True)
    (sub / "native.c").write_text("int f(int a){return a;}\n", encoding="utf-8")
    (sub / "Makefile").write_text("all:\n\tcc native.c\n", encoding="utf-8")
    (sub / "index.js").write_text("document.write(x);\n", encoding="utf-8")
    (sub / "package.json").write_text("{}", encoding="utf-8")
    assert detect_target_mode(mixed) == "mixed"


def test_finding_to_triaged_bug_maps_fields(tmp_path):
    target_root = tmp_path / "tgt"
    (target_root / "src").mkdir(parents=True)
    (target_root / "src" / "vuln.c").write_text("char b[4];\n", encoding="utf-8")

    finding = {
        "id": "VULN-001",
        "type": "Heap Buffer Overflow",
        "location": "src/vuln.c:2",
        "line_text": "strcpy(b, argv[1]);",
        "severity": "CRITICAL",
    }
    bug = _finding_to_triaged_bug(finding, target_root)

    assert bug.crash_type == "Heap Buffer Overflow"
    assert Path(bug.file_path) == target_root / "src" / "vuln.c"
    assert bug.severity == 10
    assert bug.hash_signature == "VULN-001"


# ── Phase 2 scanner-selection tests ──────────────────────────────────────


def _run_phase2_only(tmp_path: Path, monkeypatch, semgrep_available: bool):
    """
    Run run_pipeline up to and including Phase 2 by stubbing everything after:
    the LLM client constructor raises so Phase 3 takes its 'LLM unavailable'
    branch, and summary writing is captured via a spy.
    Returns (trace_lines, findings_written_to_summary).
    """
    root = tmp_path / "web_tgt"
    src = root / "app"
    src.mkdir(parents=True)
    (src / "bad.js").write_text("el.innerHTML = userInput;\n", encoding="utf-8")

    # run_pipeline imports these names from ai_kavach.static_analysis at call
    # time, so patch them on the source module. When faking availability we
    # point at the REAL semgrep in the venv so the subprocess actually runs.
    from ai_kavach.static_analysis import _find_semgrep as real_find_semgrep

    if semgrep_available:
        real_path = real_find_semgrep()
        if real_path is None:
            pytest.skip("Semgrep not installed; Semgrep-path test needs it.")
        monkeypatch.setattr("ai_kavach.static_analysis._find_semgrep", lambda: real_path)
    else:
        monkeypatch.setattr("ai_kavach.static_analysis._find_semgrep", lambda: None)

    # Make Phase 3 bail immediately (LLM unavailable branch)
    class BoomClient:
        def __init__(self):
            raise RuntimeError("no llm in tests")

    monkeypatch.setattr(orch, "LLMClient", BoomClient)

    runs_dir = tmp_path / "runs"

    orch.run_pipeline(root, "phase2_test", runs_dir)


def _read_trace(runs_dir: Path, run_id: str) -> list[str]:
    import json

    f = runs_dir / run_id / "summary.json"
    return json.loads(f.read_text(encoding="utf-8")).get("agent_trace", [])


def test_pipeline_falls_back_to_patterns_when_semgrep_missing(tmp_path, monkeypatch):
    """No Semgrep binary → pattern scan must still produce sane findings."""
    _run_phase2_only(tmp_path, monkeypatch, semgrep_available=False)
    trace = _read_trace(tmp_path / "runs", "phase2_test")
    joined = "\n".join(trace)
    assert "pattern matching" in joined
    assert "Cross-Site Scripting" in joined  # innerHTML line must be found
    # And it must say WHY it fell back
    assert any("Semgrep not installed" in line for line in trace)


def test_pipeline_uses_semgrep_when_available(tmp_path, monkeypatch):
    """Semgrep present → Semgrep path taken; findings carry clean names."""
    _run_phase2_only(tmp_path, monkeypatch, semgrep_available=True)
    trace = _read_trace(tmp_path / "runs", "phase2_test")
    joined = "\n".join(trace)
    assert "(Semgrep)" in joined
    # The custom C rules won't match a JS file; registry rules may or may not
    # fire on one line. We only assert the scan completed without falling back.
    assert "falling back to pattern matching" not in joined
    assert "Semgrep scan complete" in joined


def test_pipeline_falls_back_when_semgrep_scan_errors(tmp_path, monkeypatch):
    """Semgrep installed but scan blows up → graceful fallback to patterns."""
    root = tmp_path / "tgt2"
    src = root / "a"
    src.mkdir(parents=True)
    (src / "x.js").write_text("document.write(userInput);\n", encoding="utf-8")

    monkeypatch.setattr("ai_kavach.static_analysis._find_semgrep", lambda: "/fake/semgrep")
    # Force run_static_scan to raise → except-branch fallback
    monkeypatch.setattr(
        "ai_kavach.static_analysis.run_static_scan",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    class BoomClient:
        def __init__(self):
            raise RuntimeError("no llm in tests")

    monkeypatch.setattr(orch, "LLMClient", BoomClient)

    runs_dir = tmp_path / "runs"
    orch.run_pipeline(root, "fallback_err", runs_dir)
    trace = _read_trace(runs_dir, "fallback_err")
    joined = "\n".join(trace)
    assert "falling back to pattern matching" in joined
    assert "Pattern scan complete" in joined
    assert "Cross-Site Scripting" in joined
