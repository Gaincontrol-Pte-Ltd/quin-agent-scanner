# Quin Scanner — Web UI

A full-stack web interface for Quin Agent Scanner: dark OLED design with a Google-style search bar.

## Structure

```
ui/
  backend/    FastAPI server wrapping the quin_scanner library
  frontend/   React + TypeScript + Vite + Tailwind CSS
```

## Quick Start

### 1. Backend

```bash
# From repo root
pip install fastapi uvicorn[standard] python-dotenv pydantic

uvicorn ui.backend.main:app --reload --port 8000
```

Make sure your `.env` has the API keys (same as CLI).

### 2. Frontend

```bash
cd ui/frontend
npm install
npm run dev        # starts on http://localhost:5173
```

The Vite dev server proxies `/api/*` to `http://localhost:8000`.

## Pages

| Route | Description |
|-------|-------------|
| `/` | Home — Google-style search bar |
| `/scanning/:jobId` | Animated progress while scan runs |
| `/results/:jobId` | Full report: agents, risks, vulns, tools |

## Production build

```bash
cd ui/frontend && npm run build
# Serve dist/ with any static host or FastAPI's StaticFiles
```
