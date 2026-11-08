import asyncio
import ipaddress
import json
import random
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

import config
import scenarios
import security
import settings
from events import bus
from incident_log import AttackerTracker, IncidentLog
from packet_monitor import NetworkIDS
from pipeline import Pipeline
from response import ResponseEngine

SIM_LOG = config.LOG_DIR / "simulation_incidents.jsonl"
SIM_DB = config.LOG_DIR / "simulation_attackers.json"
_state = {}


# --------------------------------------------------------------------------
# Mirror the REAL IDS (separate process) into the event stream
# --------------------------------------------------------------------------
async def _tail_live():
    log_path, status_path = config.INCIDENT_LOG, config.STATUS_PATH
    pos = log_path.stat().st_size if log_path.exists() else 0      # don't replay old history
    last_mtime = status_path.stat().st_mtime if status_path.exists() else 0
    while True:
        await asyncio.sleep(1)
        try:
            if log_path.exists():
                size = log_path.stat().st_size
                if size < pos:
                    pos = 0
                if size > pos:
                    with open(log_path, "rb") as f:
                        f.seek(pos)
                        data = f.read()
                    end = data.rfind(b"\n")
                    if end >= 0:                                    # only complete lines
                        pos += end + 1
                        for line in data[:end].splitlines():
                            if line.strip():
                                bus.publish({**json.loads(line), "simulated": False})
            if status_path.exists():
                m = status_path.stat().st_mtime
                if m != last_mtime:
                    last_mtime = m
                    bus.publish({**json.loads(status_path.read_text()), "simulated": False})
        except Exception as e:                                      # never kill the tail task
            print("[live-tail]", e)


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(_tail_live())
    yield
    task.cancel()


app = FastAPI(title="IDS simulation API", lifespan=lifespan)


def get_state() -> dict:
    if not _state:
        try:
            ids = NetworkIDS.load()
        except RuntimeError as e:
            raise HTTPException(503, f"{e} Run: python ids_pipeline.py train --simulate")
        _state["pipe"] = Pipeline(ids, ResponseEngine(dry_run=True),     # ALWAYS dry-run here
                                  IncidentLog(SIM_LOG), AttackerTracker(SIM_DB), simulated=True)
    return _state


class Scenario(BaseModel):
    type: Literal["normal", "port_scan", "syn_flood", "host_sweep", "custom"] = "port_scan"
    src_ip: str = "203.0.113.50"
    packets: int = Field(150, ge=1, le=5000)
    windows: int = Field(1, ge=1, le=20)
    idle_windows: int = Field(0, ge=0, le=20)
    unique_ports: int = Field(1, ge=1, le=65535)
    syn_ratio: float = Field(0.1, ge=0, le=1)
    avg_size: float = Field(500, ge=40, le=1500)
    simulate_file_breach: bool = False
    background: bool = True
    real_cut: bool = False        # forward the cut to the live IDS if the sim reaches SEVERE

class CutSetting(BaseModel):
    cut_level: Literal["ELEVATED", "HIGH", "SEVERE", "OFF"]


class Confirm(BaseModel):
    # A JSON body is required: a cross-origin page can't send one without a CORS preflight,
    # so random websites can't trigger these endpoints through your browser.
    confirm: Literal[True]


# --------------------------------------------------------------------------
# Simulation (always dry-run)
# --------------------------------------------------------------------------
@app.post("/api/simulate")
def simulate(s: Scenario):
    try:
        ipaddress.ip_address(s.src_ip)
    except ValueError:
        raise HTTPException(422, "src_ip is not a valid IP address")
    pipe, rng, results = get_state()["pipe"], random.Random(), []
    for w in range(s.windows + s.idle_windows):
        attacking = w < s.windows
        pkts = scenarios.background(rng) if s.background else []
        if attacking:
            pkts += scenarios.build(s.model_dump(), rng)
        fim = ([{"path": "(simulated) config.py", "change": "modified"}]
               if s.simulate_file_breach and w == 0 else [])
        report, dets = pipe.process(pkts, config.WINDOW_SECONDS, fim, set(config.WHITELIST))
        results.append({
            "window": w + 1, "phase": "attack" if attacking else "idle",
            "detections": [{k: d[k] for k in ("src", "label", "severity", "packets", "attack_prob", "ml_score")}
                           for d in dets],
            "per_ip": report["per_ip"], "host_score": report["host_score"],
            "overall": report["overall"], "action": report["action"],
            "network_cut": pipe.cut})

    if s.real_cut and pipe.cut:              # the simulation hit the cut level -> tell the live IDS
        settings.send_command("cut")

    return {"windows": results}


@app.post("/api/restore")
def restore():
    pipe = get_state()["pipe"]
    pipe.manual_restore()
    return {"ok": True}


@app.post("/api/reset")
def reset():
    st = get_state()
    old = st["pipe"]
    st["pipe"] = Pipeline(old.ids, ResponseEngine(dry_run=True), old.log, old.tracker, simulated=True)
    return {"ok": True}


# --------------------------------------------------------------------------
# Settings + live control (the API only writes a command file; the IDS acts on it)
# --------------------------------------------------------------------------
@app.get("/api/settings")
def get_settings():
    return {"cut_level": settings.get_cut_level(), "choices": settings.CUT_CHOICES,
            "thresholds": config.LEVEL_THRESHOLDS}


@app.post("/api/settings")
def update_settings(s: CutSetting):
    return {"cut_level": settings.set_cut_level(s.cut_level)}


@app.post("/api/live/cut")
def live_cut(_: Confirm):
    settings.send_command("cut")
    return {"ok": True, "note": "command sent to the running IDS"}


@app.post("/api/live/restore")
def live_restore(_: Confirm):
    settings.send_command("restore")
    return {"ok": True, "note": "command sent to the running IDS"}


# --------------------------------------------------------------------------
# Read-only data
# --------------------------------------------------------------------------
@app.get("/api/state")
def current_state():
    pipe = get_state()["pipe"]
    return {"ip_scores": pipe.risk.ip_scores, "host_score": pipe.risk.host_score}


@app.get("/api/attackers")
def attackers():
    return get_state()["pipe"].tracker.profiles


@app.get("/api/incidents")
def incidents(limit: int = 20):
    if not SIM_LOG.exists():
        return []
    lines = [l for l in SIM_LOG.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [json.loads(l) for l in lines[-max(1, min(limit, 200)):]]


@app.get("/api/stream")
async def stream():
    sub = bus.subscribe()

    async def gen():
        try:
            for e in list(bus.history):
                yield f"data: {json.dumps(e, default=security.json_default)}\n\n"
            while True:
                try:
                    e = await asyncio.wait_for(sub[1].get(), 15)
                    yield f"data: {json.dumps(e, default=security.json_default)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            bus.unsubscribe(sub)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/")
def page():
    return FileResponse(Path(__file__).parent / "simulate.html")