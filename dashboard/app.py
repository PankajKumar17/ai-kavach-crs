import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="AI Kavach Dashboard")

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
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
def health_check():
    return {"status": "ok"}


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
        raise HTTPException(status_code=500, detail=str(e))

import subprocess
import sys

@app.post("/api/engine/start")
def start_engine():
    engine_path = DASHBOARD_DIR.parent / "engine" / "orchestrator.py"
    vuln_path = DASHBOARD_DIR.parent / "engine" / "target_app" / "vulnerable.py"
    
    try:
        # 1. Force the file to be vulnerable again for the demo loop
        vuln_code = vuln_path.read_text(encoding='utf-8')
        vuln_code = vuln_code.replace(
            "query = \"SELECT * FROM users WHERE username = ?\"\n    \n    try:\n        cursor.execute(query, (username,))", 
            "query = f\"SELECT * FROM users WHERE username = '{username}'\"\n    \n    try:\n        cursor.execute(query)"
        )
        vuln_path.write_text(vuln_code, encoding='utf-8')
        
        # 2. Run the orchestrator backend
        result = subprocess.run([sys.executable, str(engine_path)], capture_output=True, text=True, timeout=20)
        trace_log = result.stdout.splitlines()
        
        # 3. Update summary.json with the REAL trace
        summary_file = RUNS_DIR / "test_run" / "summary.json"
        if summary_file.exists():
            data = json.loads(summary_file.read_text(encoding='utf-8'))
            data["agent_trace"] = trace_log
            
            # Update mock vulnerability status based on engine success
            if "FINAL: Vulnerability fixed successfully! [PASS]" in result.stdout:
                data["vulnerabilities"][0]["status"] = "Resolved"
                data["vulnerabilities"][0]["severity"] = "CRITICAL"
                data["total_bugs_resolved"] = 12 + 1
            else:
                data["vulnerabilities"][0]["status"] = "Failed"
                
            summary_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
            
        return {"status": "success", "trace": trace_log}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from fastapi import Request
@app.get("/{full_path:path}")
def catch_all(request: Request, full_path: str):
    return {"path": full_path, "url": str(request.url)}
