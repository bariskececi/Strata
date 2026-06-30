"""Dashboard backend: serves the analysed inventory and the topology UI."""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Strata Dashboard")


def _load() -> dict:
    path = os.environ.get("STRATA_RESULTS", "strata_results.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"meta": {}, "assets": [], "flows": [], "findings": [],
                "error": f"results file not found: {path}"}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/api/data")
async def data() -> JSONResponse:
    return JSONResponse(_load())


app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
