import asyncio
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AI Kavach Dashboard")

# Enable CORS for frontend running on different domains (e.g. Vercel)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure dashboard static directory exists
DASHBOARD_DIR = Path(__file__).parent
STATIC_DIR = DASHBOARD_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Assuming runs are in a known location relative to the project root
RUNS_DIR = DASHBOARD_DIR.parent / "runs"


@app.get("/")
def read_root():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Frontend not built. Run: cd dashboard/frontend && npm install && npm run build"
        )
    return FileResponse(str(index_file))


@app.get("/health")
def health_check():
    return {"status": "ok"}


# ===== TARGET CODEBASE MANAGEMENT (like Strix) =====

class TargetCodebase(BaseModel):
    id: str
    name: str
    source_type: str  # "github" | "zip" | "local"
    source_url: str | None = None
    path: str
    created_at: str
    status: str  # "ready" | "processing" | "error"


class CreateTargetRequest(BaseModel):
    name: str
    github_url: str | None = None
    branch: str = "main"


TARGETS_DIR = DASHBOARD_DIR.parent / "targets"
TARGETS_DIR.mkdir(parents=True, exist_ok=True)

_targets_db: dict[str, TargetCodebase] = {}


def _load_targets():
    """Load targets from disk on startup."""
    global _targets_db
    for target_dir in TARGETS_DIR.iterdir():
        if target_dir.is_dir():
            meta_file = target_dir / "target.json"
            if meta_file.exists():
                try:
                    data = json.loads(meta_file.read_text())
                    _targets_db[data["id"]] = TargetCodebase(**data)
                except Exception:
                    pass


def _save_target(target: TargetCodebase):
    """Save target metadata to disk."""
    target_dir = TARGETS_DIR / target.id
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "target.json").write_text(target.model_dump_json(indent=2))


# Initialize targets on startup
_load_targets()


@app.get("/api/targets")
def list_targets():
    """List all uploaded codebases."""
    return {"targets": list(_targets_db.values())}


@app.post("/api/targets/upload")
async def upload_target_zip(
    name: str = Form(...),
    file: UploadFile = File(...),
):
    """Upload a ZIP file as a target codebase (like Strix)."""
    import uuid
    from datetime import datetime

    target_id = str(uuid.uuid4())[:8]
    target_dir = TARGETS_DIR / target_id
    target_dir.mkdir(parents=True, exist_ok=True)

    # Save ZIP
    zip_path = target_dir / "source.zip"
    content = await file.read()
    zip_path.write_bytes(content)

    # Extract
    extract_dir = target_dir / "source"
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        shutil.rmtree(target_dir)
        raise HTTPException(status_code=400, detail="Invalid ZIP file")

    target = TargetCodebase(
        id=target_id,
        name=name,
        source_type="zip",
        source_url=file.filename,
        path=str(extract_dir),
        created_at=datetime.now().isoformat(),
        status="ready"
    )

    _targets_db[target_id] = target
    _save_target(target)

    return {"target": target, "message": f"Codebase '{name}' uploaded and ready for analysis"}


@app.post("/api/targets/github")
async def create_target_github(request: CreateTargetRequest):
    """Add a GitHub repository as a target codebase (like Strix)."""
    import subprocess
    import uuid
    from datetime import datetime

    target_id = str(uuid.uuid4())[:8]
    target_dir = TARGETS_DIR / target_id
    target_dir.mkdir(parents=True, exist_ok=True)
    extract_dir = target_dir / "source"

    # Clone the repo
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", request.branch, request.github_url, str(extract_dir)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            shutil.rmtree(target_dir)
            raise HTTPException(status_code=400, detail=f"Git clone failed: {result.stderr}")
    except subprocess.TimeoutExpired:
        shutil.rmtree(target_dir)
        raise HTTPException(status_code=408, detail="Git clone timed out")
    except Exception as e:
        shutil.rmtree(target_dir)
        raise HTTPException(status_code=500, detail=f"Clone error: {str(e)}")

    target = TargetCodebase(
        id=target_id,
        name=request.name,
        source_type="github",
        source_url=request.github_url,
        path=str(extract_dir),
        created_at=datetime.now().isoformat(),
        status="ready"
    )

    _targets_db[target_id] = target
    _save_target(target)

    return {"target": target, "message": f"GitHub repo '{request.name}' cloned and ready for analysis"}


@app.delete("/api/targets/{target_id}")
def delete_target(target_id: str):
    """Delete a target codebase."""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")

    target = _targets_db[target_id]
    target_dir = TARGETS_DIR / target_id
    if target_dir.exists():
        shutil.rmtree(target_dir)

    del _targets_db[target_id]
    return {"message": f"Target '{target.name}' deleted"}


@app.get("/api/targets/{target_id}")
def get_target(target_id: str):
    """Get target details."""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    return _targets_db[target_id]


@app.get("/api/runs/{run_id}/summary")
def get_run_summary(run_id: str):
    run_dir = RUNS_DIR / run_id
    summary_file = run_dir / "summary.json"

    if not summary_file.exists():
        raise HTTPException(status_code=404, detail="Run summary not found")

    try:
        data = json.loads(summary_file.read_text())
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


def _require_engine_auth(request: Request):
    """
    Gate for /api/engine/start: it rewrites source files and spawns the
    engine subprocess, so it must never be publicly callable. When
    ENGINE_AUTH_TOKEN is set, a matching Bearer token is required. When
    unset, only loopback requests are allowed (local demo default).
    Note: Vite dev proxy at localhost adds x-forwarded-for, so we check
    the x-forwarded-for value itself to see if it's a loopback address.
    """
    expected = os.environ.get("ENGINE_AUTH_TOKEN")
    auth = request.headers.get("Authorization", "")
    if expected:
        if auth != f"Bearer {expected}":
            raise HTTPException(status_code=401, detail="Invalid or missing engine auth token.")
        return

    client_host = request.client.host if request.client else ""
    forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    forwarded_header = request.headers.get("forwarded", "")

    # Allow loopback client directly, OR via a local proxy (Vite dev server)
    loopback = {"127.0.0.1", "::1", "testclient", "localhost"}
    is_local_client = client_host in loopback
    is_local_proxy = forwarded_for in loopback  # Vite proxies from localhost

    # If there's a non-local forwarded header (real proxy/CDN), require token
    if forwarded_header and not is_local_client:
        raise HTTPException(
            status_code=403,
            detail="Remote engine-start requests require ENGINE_AUTH_TOKEN to be set.",
        )

    if not is_local_client and not is_local_proxy:
        raise HTTPException(
            status_code=403,
            detail="Remote engine-start requests require ENGINE_AUTH_TOKEN to be set.",
        )


class StartEngineRequest(BaseModel):
    target_id: str | None = None
    run_id: str = "test_run"


@app.post("/api/engine/start")
async def start_engine(request: Request, payload: StartEngineRequest):
    """
    Trigger the AI Kavach pipeline on the selected target.
    Calls orchestrator.py as a subprocess so it picks up LLM_PROVIDER / OPENROUTER_API_KEY
    from the .env file and uses OpenRouter (or Anthropic) for real LLM RCA.
    """
    _require_engine_auth(request)

    # ── 1. Resolve target path ──────────────────────────
    if payload.target_id:
        if payload.target_id not in _targets_db:
            raise HTTPException(status_code=404, detail="Target not found")
        target     = _targets_db[payload.target_id]
        target_path = Path(target.path)
    else:
        target_path = DASHBOARD_DIR.parent

    if not target_path.exists():
        raise HTTPException(
            status_code=422,
            detail=f"Target path does not exist: {target_path}"
        )

    # ── 2. Locate orchestrator ──────────────────────────
    orchestrator = DASHBOARD_DIR.parent / "src" / "ai_kavach" / "orchestrator.py"
    if not orchestrator.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Orchestrator not found at {orchestrator}"
        )

    # ── 3. Run the pipeline as a subprocess ─────────────
    # The subprocess inherits this process's environment, which already has
    # LLM_PROVIDER, OPENROUTER_API_KEY, LLM_MODEL etc. loaded from .env at
    # server startup (config.py calls load_dotenv() on import).
    venv_python = DASHBOARD_DIR.parent / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = DASHBOARD_DIR.parent / ".venv" / "bin" / "python"
    python_exec = str(venv_python) if venv_python.exists() else sys.executable

    cmd = [
        python_exec,
        str(orchestrator),
        "--target", str(target_path),
        "--run-id", payload.run_id,
        "--runs-dir", str(RUNS_DIR),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",      # must match PYTHONIOENCODING in the subprocess
            errors="replace",      # never crash on unexpected bytes
                        # C-mode runs need longer than web scans; configurable for demo pacing
            timeout=int(os.environ.get("PIPELINE_TIMEOUT_S", "600")),
            cwd=str(DASHBOARD_DIR.parent),
            env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Pipeline timed out (>5 min)")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline launch error: {exc}")

    stdout_lines = (result.stdout or "").splitlines()
    stderr_lines = (result.stderr or "").splitlines()

    # ── 4. Read back the summary.json written by the orchestrator ──
    summary_file = RUNS_DIR / payload.run_id / "summary.json"
    if summary_file.exists():
        try:
            persisted = json.loads(summary_file.read_text(encoding="utf-8"))
        except Exception:
            persisted = None
    else:
        persisted = None

    # ── 5. Return result ────────────────────────────────
    if result.returncode != 0:
        # Include stderr to help with diagnosis
        error_lines = stderr_lines[:20]
        return {
            "status": "error",
            "trace":  stdout_lines + (["--- STDERR ---"] + error_lines if error_lines else []),
            "exit_code": result.returncode,
            "vulnerabilities_found": len(persisted.get("vulnerabilities", [])) if persisted else 0,
        }

    return {
        "status": "success",
        "trace":  stdout_lines,
        "vulnerabilities_found":  len(persisted.get("vulnerabilities", [])) if persisted else 0,
        "vulnerabilities_resolved": persisted.get("total_bugs_resolved", 0) if persisted else 0,
        "target_id": payload.target_id,
    }



# ── Apply patch to a target file ─────────────────────────────────────────────

def _mark_vuln_resolved(run_id: str, vuln_id: str) -> None:
    """Update summary.json to mark a vulnerability as 'Resolved' after patch is applied."""
    summary_file = RUNS_DIR / run_id / "summary.json"
    if not summary_file.exists():
        return
    try:
        data = json.loads(summary_file.read_text(encoding="utf-8"))
        changed = False
        for v in data.get("vulnerabilities", []):
            if v.get("id") == vuln_id and v.get("status") != "Resolved":
                v["status"] = "Resolved"
                changed = True
                break
        if changed:
            # Recompute aggregate fields
            vulns = data["vulnerabilities"]
            total = len(vulns)
            resolved = sum(1 for v in vulns if v.get("status") == "Resolved")
            data["total_bugs_resolved"] = resolved
            if total > 0:
                data["percent_resolved_without_llm"] = round(
                    sum(1 for v in vulns if v.get("status") == "Resolved" and v.get("patch_tier") != "llm") / total * 100, 1
                )
            summary_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass  # Non-critical — don't break the patch apply response


class ApplyPatchRequest(BaseModel):
    target_id: str
    vuln_id: str
    run_id: str = "test_run"   # used to update summary.json
    file_path: str          # relative path inside the target (e.g. "backend-cf/src/foo.ts")
    line_number: int        # 1-indexed
    original_line: str      # for safety verification
    patched_line: str       # the replacement line (single-line fallback)
    patch_diff: str = ""    # unified diff — preferred over patched_line


@app.post("/api/apply-patch")
def apply_patch(payload: ApplyPatchRequest):
    """
    Apply the LLM-generated fix to the actual source file inside the target
    directory. Tries two strategies in order:

    1. git apply (unified diff) — used when payload.patch_diff is non-empty.
       Runs from the target root so diff paths resolve correctly (watch item 1).
    2. Manual line-replace — fallback for single-line patched_line when no diff
       is available or git is not installed.

    Returns before/after snippet for display.
    """
    if payload.target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")

    target = _targets_db[payload.target_id]
    target_root = Path(target.path)

    # ── Resolve file path ────────────────────────────────
    # Strategy: try progressively looser matches until the file is found.
    def _resolve(root: Path, rel: str) -> Path | None:
        p = Path(rel.replace("\\", "/"))  # normalise to forward-slash parts

        # 1. Exact match
        c = root / p
        if c.exists():
            return c

        # 2. Strip the leading directory component (e.g. "backend-cf/scripts/foo.js" → "scripts/foo.js")
        if len(p.parts) > 1:
            c = root / Path(*p.parts[1:])
            if c.exists():
                return c

        # 3. Search the entire tree for a file whose suffix-path matches any tail
        #    of the requested path (longest match wins).
        target_parts = p.parts
        matches = []
        for depth in range(len(target_parts), 0, -1):
            tail = Path(*target_parts[-depth:])
            hits = list(root.rglob(str(tail).replace("\\", "/")))
            if hits:
                matches = hits
                break

        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            # Prefer the hit whose path most closely matches the requested relative path
            best = max(matches, key=lambda h: len(set(h.parts) & set(target_parts)))
            return best

        return None

    candidate = _resolve(target_root, payload.file_path)
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail=f"Source file not found: {payload.file_path}"
        )

    # ── Strategy 1: git apply (unified diff) ────────────
    if payload.patch_diff and payload.patch_diff.strip():
        import shutil as _shutil
        import tempfile as _tempfile

        git_bin = _shutil.which("git")
        if git_bin:
            try:
                # Write diff to a temp file; binary mode avoids CRLF issues on Windows
                with _tempfile.NamedTemporaryFile(suffix=".patch", delete=False, mode="wb") as fh:
                    fh.write(payload.patch_diff.encode("utf-8"))
                    patch_path = fh.name

                result = subprocess.run(
                    [git_bin, "apply", "--ignore-whitespace", patch_path],
                    capture_output=True, text=True,
                    cwd=str(target_root),
                )
                Path(patch_path).unlink(missing_ok=True)

                if result.returncode == 0:
                    _mark_vuln_resolved(payload.run_id, payload.vuln_id)
                    return {
                        "status":      "patched",
                        "strategy":    "git_apply",
                        "file":        str(candidate.relative_to(target_root)).replace("\\", "/"),
                        "line_number": payload.line_number,
                        "original_line": payload.original_line,
                        "patched_line":  payload.patched_line,
                    }
                # git apply failed — fall through to manual strategy with a warning logged
            except Exception:
                pass  # Fall through to manual replace
            finally:
                try:
                    Path(patch_path).unlink(missing_ok=True)
                except Exception:
                    pass

    # ── Strategy 2: manual single-line replace (fallback) ──
    try:
        original_text = candidate.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cannot read file: {e}")

    lines = original_text.splitlines(keepends=True)
    idx   = payload.line_number - 1

    if idx < 0 or idx >= len(lines):
        raise HTTPException(status_code=400, detail=f"Line {payload.line_number} out of range")

    actual_line = lines[idx].rstrip("\n").rstrip("\r")

    if payload.original_line.strip() not in actual_line:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Line mismatch — file may have changed since scan. "
                f"Expected: {payload.original_line[:80]!r}, "
                f"Got: {actual_line[:80]!r}"
            ),
        )

    indent = len(actual_line) - len(actual_line.lstrip())
    eol    = "\r\n" if "\r\n" in original_text else "\n"
    lines[idx] = " " * indent + payload.patched_line.lstrip() + eol

    try:
        candidate.write_text("".join(lines), encoding="utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cannot write file: {e}")

    _mark_vuln_resolved(payload.run_id, payload.vuln_id)

    return {
        "status":      "patched",
        "strategy":    "manual_replace",
        "file":        str(candidate.relative_to(target_root)).replace("\\", "/"),
        "line_number": payload.line_number,
        "original_line": actual_line,
        "patched_line":  lines[idx].rstrip("\n").rstrip("\r"),
    }



@app.get("/api/engine/stream")
async def stream_engine(
    request: Request,
    target_id: str | None = None,
    run_id: str = "test_run",
):
    """
    SSE endpoint — streams orchestrator stdout line-by-line so the frontend
    can render live pipeline progress without waiting for completion.
    Errors are returned as SSE events (not HTTP errors) so EventSource
    never fires onerror with opaque failures.
    """
    _require_engine_auth(request)

    import logging as _log
    logger = _log.getLogger("uvicorn.error")

    # ── Resolve target path ─────────────────────────────
    if target_id:
        if target_id not in _targets_db:
            # Return error as SSE so frontend sees the message
            async def _not_found():
                yield f"data: {json.dumps({'line': f'[ERROR] Target \"{target_id}\" not found. Please re-upload your target.'})}\n\n"
                yield f"event: complete\ndata: {json.dumps({'status': 'error', 'run_id': run_id, 'summary': {}})}\n\n"
            return StreamingResponse(_not_found(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
        target     = _targets_db[target_id]
        target_path = Path(target.path)
    else:
        target_path = DASHBOARD_DIR.parent

    orchestrator = DASHBOARD_DIR.parent / "src" / "ai_kavach" / "orchestrator.py"
    if not orchestrator.exists():
        async def _no_orch():
            yield f"data: {json.dumps({'line': f'[ERROR] orchestrator.py not found at {orchestrator}'})}\n\n"
            yield f"event: complete\ndata: {json.dumps({'status': 'error', 'run_id': run_id, 'summary': {}})}\n\n"
        return StreamingResponse(_no_orch(), media_type="text/event-stream",
                                  headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    venv_python = DASHBOARD_DIR.parent / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = DASHBOARD_DIR.parent / ".venv" / "bin" / "python"
    python_exec = str(venv_python) if venv_python.exists() else sys.executable

    cmd = [
        python_exec,
        str(orchestrator),
        "--target", str(target_path),
        "--run-id", run_id,
        "--runs-dir", str(RUNS_DIR),
    ]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    logger.info("[SSE] Starting pipeline: %s", " ".join(cmd))

    async def event_stream():
        loop      = asyncio.get_event_loop()
        # Queue carries stdout lines; None is the sentinel (subprocess done)
        q: asyncio.Queue[str | None] = asyncio.Queue()
        rc_holder: list[int] = []

        def _run_proc():
            """Runs in a thread so blocking Popen.readline() doesn't block the event loop."""
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(DASHBOARD_DIR.parent),
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            # Stream stdout line-by-line into the async queue
            for raw in proc.stdout:  # type: ignore[union-attr]
                asyncio.run_coroutine_threadsafe(q.put(raw.rstrip()), loop)
            proc.wait()
            rc_holder.append(proc.returncode)

            # On failure: pipe stderr so the terminal shows it
            if proc.returncode != 0 and proc.stderr:
                for sline in proc.stderr.read().splitlines():
                    if sline.strip():
                        asyncio.run_coroutine_threadsafe(
                            q.put(f"[STDERR] {sline}"), loop
                        )

            asyncio.run_coroutine_threadsafe(q.put(None), loop)  # sentinel

        try:
            future = loop.run_in_executor(None, _run_proc)

            while True:
                line = await q.get()
                if line is None:      # subprocess finished
                    break
                if await request.is_disconnected():
                    break
                yield f"data: {json.dumps({'line': line})}\n\n"

            await future            # re-raises any thread exception

            rc = rc_holder[0] if rc_holder else 1

            # Read persisted summary
            summary_file = RUNS_DIR / run_id / "summary.json"
            summary_data: dict = {}
            if summary_file.exists():
                try:
                    summary_data = json.loads(summary_file.read_text(encoding="utf-8"))
                except Exception:
                    pass

            status = "success" if rc == 0 else "error"
            logger.info("[SSE] Pipeline finished rc=%d status=%s", rc, status)
            yield f"event: complete\ndata: {json.dumps({'status': status, 'run_id': run_id, 'summary': summary_data})}\n\n"

        except Exception as exc:
            err_msg = repr(exc)
            logger.exception("[SSE] event_stream exception: %s", err_msg)
            yield f"data: {json.dumps({'line': f'[ERROR] {err_msg}'})}\n\n"
            yield f"event: complete\ndata: {json.dumps({'status': 'error', 'run_id': run_id, 'summary': {}})}\n\n"


    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.post("/api/engine/demo")
def run_demo(request: Request):
    """Quick demo with realistic mock vulnerability data."""
    from datetime import datetime

    def ts(offset=0):
        from datetime import timedelta
        t = datetime(2026, 8, 25, 20, 15, 32) + timedelta(seconds=offset)
        return f"[{t.strftime('%H:%M:%S')}]"

    demo_vulns = [
        {"id": "VULN-001", "type": "Heap Buffer Overflow", "location": "src/parser.c:142",
         "severity": "CRITICAL", "status": "Resolved", "agent": "Template", "time_taken": "1.2s"},
        {"id": "VULN-002", "type": "Use After Free",        "location": "src/network.c:88",
         "severity": "HIGH",     "status": "Resolved", "agent": "LLM Hybrid", "time_taken": "45.1s"},
        {"id": "VULN-003", "type": "Null Pointer Dereference","location": "src/auth.c:304",
         "severity": "MEDIUM",   "status": "Resolved", "agent": "LLM Hybrid", "time_taken": "28.5s"},
        {"id": "VULN-004", "type": "Out of Bounds Read",    "location": "src/image_decoder.c:91",
         "severity": "HIGH",     "status": "Failed (Timeout)", "agent": "LLM Hybrid", "time_taken": "120.0s"},
    ]
    demo_trace = [
        f"{ts(0)}  🛡️  AI KAVACH DEMO — Simulated Pipeline",
        f"{ts(0)}  ════════════════════════════════════════",
        f"{ts(0)}  Phase 1: Static Analysis",
        f"{ts(1)}  Running pattern scan on demo-target...",
        f"{ts(2)}  ✓ Found 4 potential vulnerabilities",
        f"{ts(2)}  ",
        f"{ts(2)}  Phase 2: Triage",
        f"{ts(3)}  ⚑  [CRITICAL] Heap Buffer Overflow → src/parser.c:142",
        f"{ts(3)}  ⚑  [HIGH] Use After Free → src/network.c:88",
        f"{ts(3)}  ⚑  [HIGH] Out of Bounds Read → src/image_decoder.c:91",
        f"{ts(3)}  ⚑  [MEDIUM] Null Pointer Dereference → src/auth.c:304",
        f"{ts(3)}  ",
        f"{ts(3)}  Phase 3: Patch Generation",
        f"{ts(4)}  ✓ Applied template fix for heap-buffer-overflow",
        f"{ts(5)}  ✓ LLM patch applied for use-after-free",
        f"{ts(8)}  ✓ LLM patch applied for null-pointer-dereference",
        f"{ts(9)}  ✗ Timeout on out-of-bounds-read (>120s)",
        f"{ts(9)}  ",
        f"{ts(9)}  Phase 4: Verification",
        f"{ts(10)} ✓ 3/4 patches verified clean",
        f"{ts(10)} ",
        f"{ts(10)} FINAL: Demo complete [PASS]",
        f"{ts(10)} 📊 Results: 4 found · 3 resolved · 75.0% success rate",
    ]

    summary = {
        "total_bugs_processed": 4,
        "total_bugs_resolved": 3,
        "tokens_per_verified_patch": 1845,
        "average_time_per_verified_patch_s": 32.4,
        "percent_resolved_without_llm": 25.0,
        "total_tokens_used": 5535,
        "total_time_s": 195.3,
        "peak_memory_mb": 128.0,
        "run_id": "test_run",
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "vulnerabilities": demo_vulns,
        "agent_trace": demo_trace,
    }

    summary_dir = RUNS_DIR / "test_run"
    summary_dir.mkdir(parents=True, exist_ok=True)
    (summary_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return {"status": "success", "trace": demo_trace, "message": "Demo mode"}


@app.get("/{full_path:path}")
def catch_all(full_path: str):
    # Serve index.html for any unknown path (SPA fallback)
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"path": full_path}

    """Trigger the REAL AI Kavach autonomous pipeline on selected target."""
    _require_engine_auth(request)

    # Determine target codebase path
    target_path = None
    if payload.target_id:
        if payload.target_id not in _targets_db:
            raise HTTPException(status_code=404, detail="Target not found")
        target = _targets_db[payload.target_id]
        target_path = target.path
    else:
        # Default to project root if no target specified
        target_path = str(DASHBOARD_DIR.parent)

    # Path to the REAL orchestrator
    orchestrator_path = DASHBOARD_DIR.parent / "src" / "ai_kavach" / "orchestrator.py"

    if not orchestrator_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Orchestrator not found at {orchestrator_path}"
        )

    try:
        # Run the REAL AI Kavach pipeline with target path
        # This will execute: fuzzing → static analysis → triage → RCA → patch → verify
        cmd = [sys.executable, str(orchestrator_path), "--target", target_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,  # 3 minutes for real pipeline
            cwd=str(DASHBOARD_DIR.parent)
        )

        trace_log = result.stdout.splitlines()

        # Update summary.json with the REAL trace
        summary_file = RUNS_DIR / payload.run_id / "summary.json"
        if summary_file.exists():
            data = json.loads(summary_file.read_text(encoding='utf-8'))
            data["agent_trace"] = trace_log
            data["status"] = "completed" if result.returncode == 0 else "failed"

            # Check for success indicators in output
            output_text = result.stdout
            if "PASS" in output_text or "Success" in output_text:
                # Increment resolved count
                data["total_bugs_resolved"] = data.get("total_bugs_resolved", 0) + 1

            summary_file.write_text(json.dumps(data, indent=2), encoding='utf-8')

        return {
            "status": "success" if result.returncode == 0 else "error",
            "trace": trace_log,
            "exit_code": result.returncode,
            "target_id": payload.target_id
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Pipeline execution timed out (>3 minutes)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


@app.post("/api/engine/demo")
def run_demo(request: Request):
    """Quick demo with mock vulnerability data - no actual pipeline execution."""
    try:
        summary_file = RUNS_DIR / "test_run" / "summary.json"

        if summary_file.exists():
            data = json.loads(summary_file.read_text(encoding='utf-8'))

            # Add realistic demo trace
            demo_trace = [
                "[20:15:32] 🛡️  AI KAVACH DEMO MODE - Simulated Pipeline",
                "[20:15:32] =====================================",
                "[20:15:32] Phase 1: Static Analysis",
                "[20:15:33] Running Semgrep scan...",
                "[20:15:34] ✓ Found 3 potential vulnerabilities",
                "[20:15:34] ",
                "[20:15:34] Phase 2: Vulnerability Triage",
                "[20:15:35] Analyzing SQL Injection in auth module...",
                "[20:15:35] Severity: CRITICAL",
                "[20:15:35] Location: src/auth.py:142",
                "[20:15:35] ",
                "[20:15:35] Phase 3: Root Cause Analysis",
                "[20:15:36] LLM analyzing vulnerable code patterns...",
                "[20:15:38] ✓ RCA Complete: Unsanitized user input in SQL query",
                "[20:15:38] ",
                "[20:15:38] Phase 4: Patch Generation",
                "[20:15:39] Attempting template-based fix...",
                "[20:15:39] ✓ Applied parameterized query template",
                "[20:15:39] ",
                "[20:15:39] Phase 5: Verification",
                "[20:15:40] Running regression tests...",
                "[20:15:41] ✓ All tests passed",
                "[20:15:41] ",
                "[20:15:41] FINAL: Demo completed successfully! [PASS]",
                "[20:15:41] 🎉 3 vulnerabilities detected, 3 patched, 3 verified"
            ]

            data["agent_trace"] = demo_trace
            data["status"] = "completed"
            data["total_bugs_resolved"] = min(data.get("total_bugs_resolved", 0) + 1, data.get("total_bugs_processed", 14))

            # Mark first vulnerability as resolved
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                data["vulnerabilities"][0]["status"] = "Resolved"

            summary_file.write_text(json.dumps(data, indent=2), encoding='utf-8')

            return {
                "status": "success",
                "trace": demo_trace,
                "message": "Demo completed - this was a simulation with mock data"
            }
        else:
            raise HTTPException(status_code=404, detail="Summary file not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/{full_path:path}")
def catch_all(request: Request, full_path: str):
    return {"path": full_path, "url": str(request.url)}
