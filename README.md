# AI Kavach Cyber Reasoning System

This project is a cyber-reasoning system for the AI Kavach hackathon (Indian Army Terrier Cyber Quest 2026).

## Features

- **Autonomous Vulnerability Discovery**: Automated fuzzing and static analysis
- **AI-Powered Patching**: LLM-driven patch generation with template fallbacks
- **Verification Harness**: Automated regression testing of patches
- **Real-time Dashboard**: Production React/Vite web interface with live agent traces
- **Metrics Tracking**: MTTD, MTTR, success rates, and AI efficiency

## Quick Start

### Backend Setup

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows
source .venv/bin/activate    # Linux/Mac

# Install dependencies
pip install -e .
pip install pytest pytest-asyncio pytest-cov pytest-mock httpx semgrep

# Set API key (optional for testing)
$env:ANTHROPIC_API_KEY = "your-key-here"  # Windows
export ANTHROPIC_API_KEY="your-key-here"   # Linux/Mac

# Run tests
pytest -v
```

### Frontend Setup & Build

```bash
# Windows
.\setup-frontend.ps1

# Linux/Mac
bash setup-frontend.sh
```

This will:
1. Install Node.js dependencies
2. Run TypeScript type checking
3. Lint the code
4. Build production bundle to `dashboard/static/`

### Run Dashboard

```bash
# Start the FastAPI server
python -m uvicorn dashboard.app:app --reload

# Open browser to http://localhost:8000
```

## Architecture

### Backend (Python/FastAPI)
- **FastAPI** web server with REST API
- **Fuzzing**: AFL++ integration for crash discovery
- **Static Analysis**: Semgrep for vulnerability detection
- **Triage**: ASan trace parsing and deduplication
- **RCA**: Root cause analysis via Claude API
- **Patch Generation**: Hybrid template + LLM approach
- **Verification**: Automated regression harness

### Frontend (React/Vite)
- **React 18** with TypeScript
- **TanStack Query** for data fetching
- **Army-themed design system** with green accents
- **Real-time trace viewer** with syntax highlighting
- **Metrics dashboard** with sortable vulnerability table
- **Engine control** with auth token support

## Dashboard Features

### Key Metrics Cards
- **Success Rate**: Percentage of vulnerabilities resolved
- **MTTD**: Mean Time To Detect vulnerabilities
- **MTTR**: Mean Time To Repair (patch + verify)
- **AI Efficiency**: Percentage resolved via templates (no LLM)

### Vulnerabilities Table
- Sortable by severity, status, or time
- Severity badges: CRITICAL, HIGH, MEDIUM, LOW
- Status indicators: Resolved, Failed, Pending
- Agent type and execution time

### Agent Trace Panel
- Real-time streaming logs from reasoning pipeline
- Syntax highlighting for success/failure/phases
- Auto-scroll during live execution
- Timestamp extraction and formatting

### Engine Control
- One-click pipeline trigger
- Auth token input for remote deployments
- Live status indicator
- Error handling with dismissible banners

## Deployment

### Local Development
```bash
# Frontend dev server with hot reload
cd dashboard/frontend
npm run dev

# Backend in another terminal
python -m uvicorn dashboard.app:app --reload
```

### Production (Vercel)
```bash
# Build frontend
cd dashboard/frontend && npm run build && cd ../..

# Deploy
vercel deploy
```

### Production (Render)
```bash
# Uses render.yaml blueprint
# Automatically builds Docker image with static assets
# Deploy via Render dashboard
```

## Project Structure

```
ai-kavach-crs/
├── dashboard/
│   ├── frontend/          # React/Vite source
│   │   ├── src/
│   │   │   ├── components/  # UI components
│   │   │   ├── App.tsx
│   │   │   ├── api.ts       # API client
│   │   │   └── types.ts
│   │   ├── package.json
│   │   └── vite.config.ts
│   ├── static/            # Build output (served by FastAPI)
│   └── app.py             # FastAPI backend
├── src/ai_kavach/
│   ├── fuzzing.py
│   ├── static_analysis.py
│   ├── triage.py
│   ├── rca.py
│   ├── patch_gen/
│   ├── verify.py
│   └── orchestrator.py
├── tests/
├── runs/                  # Run data and traces
├── pyproject.toml
└── README.md
```

## API Endpoints

- `GET /` - Serve dashboard (index.html)
- `GET /health` - Health check
- `GET /api/runs/{run_id}/summary` - Fetch run metrics and vulnerabilities
- `POST /api/engine/start` - Trigger autonomous pipeline

## Environment Variables

```bash
# Backend
ANTHROPIC_API_KEY=your-key-here
ENGINE_AUTH_TOKEN=secret-token-for-remote-start

# Frontend (optional)
VITE_API_BASE=http://localhost:8000
```

## Testing

```bash
# Run all tests
pytest -v

# With coverage
pytest --cov=src/ai_kavach --cov-report=html

# Specific test file
pytest tests/test_dashboard.py -v
```

## Tech Stack

**Backend:**
- Python 3.11+
- FastAPI + Uvicorn
- Claude API (Anthropic)
- Semgrep
- AFL++ (WSL/Linux)

**Frontend:**
- React 18
- TypeScript
- Vite
- TanStack Query
- CSS Custom Properties

## License

Built for Indian Army Terrier Cyber Quest 2026