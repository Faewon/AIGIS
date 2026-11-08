"""Offline project checks. Run from the project root with python -m scratch.check_project."""
import ast
import base64
from collections import Counter
from contextlib import ExitStack
import hashlib
import gc
from html.parser import HTMLParser
import importlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
failures = []
notes = []


def check(label, passed, detail=""):
    print(f"{'PASS' if passed else 'FAIL'} {label}" + (f": {detail}" if detail else ""))
    if not passed:
        failures.append(label)


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.handlers = []
        self.scripts = []
        self.script = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        self.handlers.extend(value for key, value in attrs.items() if key.startswith("on") and value)
        if tag == "script":
            self.script = []

    def handle_data(self, data):
        if self.script is not None:
            self.script.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.script is not None:
            self.scripts.append("".join(self.script))
            self.script = None


def syntax_checks():
    files = list(ROOT.glob("*.py")) + list((ROOT / "backend").rglob("*.py")) + list((ROOT / "tests").rglob("*.py")) + [Path(__file__)]
    for path in files:
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (SyntaxError, UnicodeError) as exc:
            failures.append(f"Python syntax: {path}: {exc}")
    check("Python syntax", not failures, f"{len(files)} files")
    from backend.dashboard import build_dashboard
    html, javascript = build_dashboard(str(ROOT / "frontend/index.html"))
    doc = Document()
    doc.feed(html)
    doc.scripts.append(javascript)
    for i, source in enumerate(doc.scripts):
        result = subprocess.run(["node", "--check"], input=source, text=True, encoding="utf-8", capture_output=True)
        check(f"Dashboard JavaScript syntax {i + 1}", result.returncode == 0, result.stderr.strip())
    for path in (ROOT / "backend").rglob("*.js"):
        result = subprocess.run(["node", "--check", str(path)], text=True, encoding="utf-8", capture_output=True)
        check(f"JavaScript syntax {path.relative_to(ROOT)}", result.returncode == 0, result.stderr.strip())
    duplicates = {key: value for key, value in Counter(doc.ids).items() if value > 1}
    check("Unique HTML IDs", not duplicates, json.dumps(duplicates))
    functions = set(re.findall(r"\bfunction\s+(\w+)\s*\(", "\n".join(doc.scripts)))
    calls = set()
    for handler in doc.handlers:
        calls.update(re.findall(r"(?<![.\w])([A-Za-z_$][\w$]*)\s*\(", handler))
    missing = sorted(calls - functions - {"if", "encodeURIComponent", "decodeURIComponent", "Number", "String", "parseInt", "alert", "confirm"})
    check("Static handler function references", not missing, json.dumps(missing))
    return doc


def smoke_checks(doc):
    from fastapi.testclient import TestClient
    from backend import server, database, data_simulator

    # Force the offline gateway, and isolate startup, streaming, and upload writes.
    server.global_llm_engine.configure("heuristic")
    with tempfile.TemporaryDirectory(prefix="aigis_full_check_") as directory, ExitStack() as stack:
        root = Path(directory)
        uploads = root / "backend/datasets/uploads"
        uploads.mkdir(parents=True)
        db_path = str(root / "telemetry.db")
        for key, value in {"DATASETS_DIR": str(root), "UPLOADS_DIR": str(uploads), "DB_PATH": db_path, "ACTIVE_DB_PATH": db_path, "ACTIVE_DB_NAME": "telemetry.db"}.items():
            stack.enter_context(patch.object(database, key, value))
        stack.enter_context(patch.object(server, "BASE_DIR", directory))
        stack.enter_context(patch.object(server.stream_engine, "db_path", db_path))
        stack.enter_context(patch.object(data_simulator, "CSV_PATH", str(root / "sample.csv")))
        for agent in (server.global_fintech_sentinel, server.global_quant_investigator, server.global_secops_copilot):
            stack.enter_context(patch.object(agent, "db_path", db_path))
        headers = {"X-AIGIS-Token": server.AIGIS_API_TOKEN}
        with TestClient(server.app, raise_server_exceptions=False) as client:
            check("Startup initializes isolated database", Path(db_path).exists())
            response = client.get("/")
            check("Dashboard without login", response.status_code == 200 and 'www-authenticate' not in response.headers)
            csp = response.headers.get("content-security-policy", "")
            actual = Document()
            actual.feed(response.text)
            check("Strict external script CSP", "script-src 'self';" in csp and not any(actual.scripts) and not actual.handlers)
            response_script = client.get("/assets/dashboard.js")
            result = subprocess.run(["node", "--check"], input=response_script.text, text=True, encoding="utf-8", capture_output=True)
            check("Served external JavaScript", response_script.status_code == 200 and result.returncode == 0, result.stderr.strip())
            check("Compact CSP header", len(csp.encode()) < 1024)
            print("INFO CSP header bytes:", len(csp.encode()))
            paths = ["agent/config", "target/status", "wargame/state", "wargame/scenarios", "dataset/info", "database/stats", "database/info", "database/schema", "database/model", "database/table_data", "database/rows", "database/uploads", "stream/status", "stream/events", "sentinel/status", "sentinel/incidents", "sentinel/policies", "investigator/latest", "workorder/generate", "patches/export"]
            route_paths = {route.path for route in server.app.routes}
            for path in paths:
                full = "/api/v1/" + path
                if full not in route_paths:
                    continue
                response = client.get(full, headers=headers)
                check(f"GET {full}", response.status_code == 200, f"HTTP {response.status_code}")
            for path, body in [("database/sql", {"query": "SELECT COUNT(*) AS count FROM telemetry"}), ("database/text_to_sql", {"prompt": "count telemetry rows", "execute": False}), ("scanner/pii", {"content": "ordinary text"}), ("scanner/openapi", {"raw_spec": '{"openapi":"3.0.0","paths":{}}'}), ("sentinel/evaluate", {"window_seconds": 15}), ("investigator/diagnose", {"window_seconds": 60}), ("copilot/chat", {"query": "hello"}), ("fintech/evaluate_risk", {"amount": 10}), ("fintech/velocity_rule", {"limit": 5}), ("sentinel/policies/toggle", {"rule_id": "missing-rule", "is_active": 0}), ("stream/pause", {}), ("stream/resume", {})]:
                response = client.post("/api/v1/" + path, json=body, headers=headers)
                check(f"POST /api/v1/{path}", response.status_code == 200, f"HTTP {response.status_code}")
            event = server.stream_engine._generate_event()
            server.stream_engine._flush_batch([event])
            for path in ("database/classify", "database/classify_deep"):
                response = client.post("/api/v1/" + path, json={"sample_limit": 100}, headers=headers)
                check(f"POST /api/v1/{path}", response.status_code == 200 and response.json().get("success") is True, response.text[:150])
            # Use actual SQLite and CSV importers rather than stubs.
            uploaded = root / "source.db"
            conn = sqlite3.connect(uploaded)
            conn.execute("CREATE TABLE sample (value INTEGER)")
            conn.execute("INSERT INTO sample VALUES (1)")
            conn.commit()
            conn.close()
            response = client.post("/api/v1/database/upload_db", headers=headers, files={"file": ("sample.db", uploaded.read_bytes())})
            check("SQLite multipart upload and real activation", response.status_code == 200 and response.json().get("success") is True, response.text[:250])
            response = client.post("/api/v1/database/upload_csv", headers=headers, files={"file": ("sample.csv", b"name,value\nalpha,1\nbeta,2\n")})
            check("CSV multipart upload and real import", response.status_code == 200 and response.json().get("success") is True, response.text[:250])
            for path in ("database/rows", "investigator/latest"):
                response = client.get("/api/v1/" + path, headers=headers)
                check(f"Custom CSV compatibility GET {path}", response.status_code < 500, f"HTTP {response.status_code}")
            response = client.post("/api/v1/investigator/diagnose", json={"window_seconds": 60}, headers=headers)
            check("Custom CSV compatibility POST investigator/diagnose", response.status_code == 200 and response.json().get("status") == "UNSUPPORTED_DATASET", response.text[:150])
            response = client.get("/api/v1/investigator/latest", headers=headers)
            check("Cached report belongs to current dataset", response.status_code == 200 and response.json().get("status") == "UNSUPPORTED_DATASET")
            try:
                server.global_quant_investigator._compute_concurrency_metrics_in_process("/api/v1/voucher/claim", 60)
            except Exception as exc:
                print("INFO Custom CSV investigator exception:", type(exc).__name__, str(exc))
            time.sleep(2.2)
            check("Background streaming flush", server.stream_engine.metrics["total_streamed"] > 0)
        check("Shutdown stops streaming", not server.stream_engine.is_running)
        # Release unreachable connections leaked by the diagnosed exception path
        # so Windows can remove this check's disposable database files.
        gc.collect()


if __name__ == "__main__":
    document = syntax_checks()
    smoke_checks(document)
    print("\nTOTAL FAILURES:", len(failures))
    for failure in failures:
        print(" -", failure)
    raise SystemExit(bool(failures))
