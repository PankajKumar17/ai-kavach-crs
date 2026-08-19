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
