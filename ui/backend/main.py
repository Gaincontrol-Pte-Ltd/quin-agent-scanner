"""Quin Scanner Web UI — FastAPI backend.

Wraps the quin_scanner library and exposes HTTP endpoints for the React frontend.
Run with:  uvicorn ui.backend.main:app --reload  (from repo root)
"""
from __future__ import annotations

import sys
import os
import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Load .env from the repo root (same behaviour as the CLI)
from dotenv import find_dotenv, load_dotenv
load_dotenv(find_dotenv(usecwd=True))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add repo root to sys.path so quin_scanner is importable when running from ui/backend
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import RepoAccessorFactory

app = FastAPI(title="Quin Scanner UI API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store keyed by job_id
_jobs: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    no_llm: bool = False
    llm_provider: str | None = None
    llm_model: str | None = None
    github_token: str | None = None
    branch: str = "main"
    min_confidence: float = 0.0
    no_vuln_check: bool = False


class ScanJobResponse(BaseModel):
    job_id: str
    status: str  # "pending" | "running" | "done" | "error"
    started_at: str


def _sanitize(obj: Any) -> Any:
    """Recursively replace control characters in strings so JSON stays valid."""
    if isinstance(obj, str):
        return "".join(ch if ch >= " " or ch in "\t\n\r" else "?" for ch in obj)
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj]
    return obj


def _run_scan(job_id: str, req: ScanRequest) -> None:
    """Blocking scan — runs in a thread via asyncio.to_thread."""
    _jobs[job_id]["status"] = "running"

    try:
        cfg = ScannerConfig.load_from_args(
            llm_provider=req.llm_provider,
            llm_model=req.llm_model,
            no_llm=req.no_llm,
            github_token=req.github_token or os.getenv("GITHUB_TOKEN"),
        )
        if req.no_vuln_check:
            cfg.vuln_check_enabled = False

        accessor = RepoAccessorFactory.create(
            req.target,
            github_token=cfg.github_token,
            branch=req.branch,
        )
        try:
            report = ScanOrchestrator().run(accessor, cfg, verbose=False)
        finally:
            accessor.cleanup()

        if req.min_confidence > 0.0:
            report.artifacts = [
                f for f in report.artifacts if f.confidence >= req.min_confidence
            ]

        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = _sanitize(report.to_dict())

    except Exception as exc:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(exc)


@app.post("/api/scan", response_model=ScanJobResponse, status_code=202)
async def start_scan(req: ScanRequest) -> ScanJobResponse:
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    _jobs[job_id] = {"status": "pending", "started_at": now, "result": None, "error": None}

    # Run the blocking scan in a thread pool
    asyncio.create_task(asyncio.to_thread(_run_scan, job_id, req))

    return ScanJobResponse(job_id=job_id, status="pending", started_at=now)


@app.get("/api/scan/{job_id}")
async def get_job_status(job_id: str) -> dict[str, Any]:
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = _jobs[job_id]
    return {
        "job_id": job_id,
        "status": job["status"],
        "started_at": job.get("started_at"),
        "error": job.get("error"),
        "result": job.get("result") if job["status"] == "done" else None,
    }


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
