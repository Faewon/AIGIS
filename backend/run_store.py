"""Durable run manifests independent of the currently selected telemetry DB."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import time

from backend.observability import event


def _path():
    from backend import database
    return Path(os.getenv("AIGIS_RUN_DB", str(Path(database.DATASETS_DIR) / "aigis_runs.db")))


def save_run(run_id: str, config: dict, result: dict, status: str = "COMPLETED"):
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=30)) as conn, conn:
        conn.execute("CREATE TABLE IF NOT EXISTS simulation_runs "
                     "(run_id TEXT PRIMARY KEY, created_ms INTEGER, status TEXT, config_json TEXT, result_json TEXT)")
        conn.execute("INSERT INTO simulation_runs VALUES (?,?,?,?,?)",
                     (run_id, int(time.time() * 1000), status, json.dumps(config), json.dumps(result)))
    event("simulation.saved", run_id=run_id, status=status, seed=config.get("seed"))


def get_run(run_id: str):
    path = _path()
    if not path.exists():
        return None
    with closing(sqlite3.connect(path)) as conn:
        row = conn.execute("SELECT status, config_json, result_json FROM simulation_runs WHERE run_id=?", (run_id,)).fetchone()
    return {"run_id": run_id, "status": row[0], "configuration": json.loads(row[1]), "result": json.loads(row[2])} if row else None
