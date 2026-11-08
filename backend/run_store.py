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
        conn.execute("INSERT INTO simulation_runs VALUES (?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET "
                     "status=excluded.status, config_json=excluded.config_json, result_json=excluded.result_json",
                     (run_id, int(time.time() * 1000), status, json.dumps(config), json.dumps(result)))
    event("simulation.saved", run_id=run_id, status=status, seed=config.get("seed"))


def get_run(run_id: str):
    path = _path()
    if not path.exists():
        return None
    with closing(sqlite3.connect(path)) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='simulation_runs'").fetchone():
            return None
        row = conn.execute("SELECT status, config_json, result_json FROM simulation_runs WHERE run_id=?", (run_id,)).fetchone()
    return {"run_id": run_id, "status": row[0], "configuration": json.loads(row[1]), "result": json.loads(row[2])} if row else None


def list_runs(limit=50):
    path = _path()
    if not path.exists():
        return []
    with closing(sqlite3.connect(path)) as conn:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE name='simulation_runs'").fetchone()
        if not exists:
            return []
        rows = conn.execute("SELECT run_id, created_ms, status, config_json FROM simulation_runs "
                            "ORDER BY created_ms DESC, run_id DESC LIMIT ?", (max(1, min(limit, 100)),)).fetchall()
    return [{"run_id": row[0], "created_ms": row[1], "status": row[2],
             "configuration": json.loads(row[3])} for row in rows]
