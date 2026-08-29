# AI Kavach Dashboard Frontend

Production-ready React/Vite frontend for the AI Kavach Cyber Reasoning System.

## Features

- **Real-time Metrics**: MTTD, MTTR, success rate, and AI efficiency metrics
- **Vulnerability Tracking**: Sortable, filterable table with severity and status badges
- **Live Agent Trace**: Real-time streaming of agent reasoning logs with syntax highlighting
- **Engine Control**: Trigger autonomous vulnerability detection pipeline
- **Responsive Design**: Clean, professional UI optimized for army hackathon demo
- **Type-safe**: Full TypeScript coverage with strict mode

## Tech Stack

- **React 18** - UI library
- **Vite** - Build tool and dev server
- **TypeScript** - Type safety
- **TanStack Query** - Data fetching and caching
- **CSS Custom Properties** - Design system tokens

## Development

### Prerequisites

- Node.js 18+ and npm
- Backend API running on `http://localhost:8000`

### Setup

```bash
# Install dependencies
npm install

# Start dev server (with API proxy)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Type check
npx tsc --noEmit

# Lint
npm run lint
```

### Environment Variables

Create `.env` file for custom API base URL:

```bash
VITE_API_BASE=http://localhost:8000
```

## Build Output

Production build outputs to `../static/` directory, which is served by the FastAPI backend:

```
dashboard/
├── frontend/       # Source code (this directory)
│   ├── src/
│   │   ├── components/
│   │   ├── App.tsx
│   │   ├── api.ts
│   │   └── types.ts
│   └── package.json
└── static/         # Build output (served by FastAPI)
    ├── index.html
    ├── assets/
    └── ...
```

## Design System

### Color Palette

- **Primary**: Army green (`#2E7D32`)
- **Severity Colors**:
  - CRITICAL: `#D32F2F`
  - HIGH: `#F57C00`
  - MEDIUM: `#FBC02D`
  - LOW: `#388E3C`
- **Neutrals**: Clean whites/grays for backgrounds and borders

### Typography

- **Sans**: Inter (body text, UI)
- **Mono**: JetBrains Mono (code, traces, metrics)
- **Base size**: 14px with 1.5 line-height

### Components

- **MetricCard**: Key metrics with large numbers and subtitles
- **VulnerabilitiesTable**: Sortable table with severity/status badges
- **AgentTrace**: Terminal-style log viewer with auto-scroll
- **EngineControl**: Pipeline trigger with auth token input

## API Integration

The frontend connects to these backend endpoints:

- `GET /api/runs/{run_id}/summary` - Fetch run metrics and vulnerabilities
- `POST /api/engine/start` - Trigger the orchestration pipeline
- `GET /health` - Health check

Authentication is optional for localhost, required for remote deployments via `ENGINE_AUTH_TOKEN`.

## Production Deployment

### With Vercel

The backend `vercel.json` already includes the frontend bundle:

```bash
cd dashboard/frontend
npm install
npm run build
cd ../..
vercel deploy
```

### With Render

The `render.yaml` blueprint builds the Docker image with static assets:

```bash
cd dashboard/frontend
npm install
npm run build
# Deploy via Render dashboard
```

### Standalone

```bash
npm run build
# Serve ../static/ with any static file server
```

## License

Built for Indian Army Terrier Cyber Quest 2026