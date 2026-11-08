from backend.stream_engine import stream_engine

from contextlib import asynccontextmanager


from backend.pii_scanner import global_pii_scanner
from backend.patch_exporter import global_patch_exporter

import os
import hmac
import json
from backend.dashboard import build_dashboard
from pydantic import BaseModel, ConfigDict, Field, ValidationError
import html
import secrets
import uuid
import time
import threading
from pathlib import Path

import asyncio
from typing import Dict, Any
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from backend.mock_target.store import mock_store
from backend.llm_engine import global_llm_engine
from backend.data_simulator import generate_million_row_dataset, get_dataset_metadata, CSV_PATH
from backend.database import (
    get_db_stats, query_telemetry_rows, execute_raw_sql, import_csv_to_db,
    import_custom_csv_to_db, set_active_db, get_active_db_info, get_db_tables,
    get_table_schema, DB_PATH, init_db, list_uploaded_databases,
    delete_uploaded_database, get_database_model_graph, query_table_data,
    get_incident_memory, add_incident_memory, get_policy_rules, toggle_policy_rule,
)
from backend.text_to_sql import generate_sql_from_prompt
from backend.agents.rea_dissector import READissectorAgent
from backend.agents.red_cerebrus import RedCerebrusAgent
from backend.agents.sandbox_runner import SandboxRunnerAgent
from backend.agents.blue_aegis import BlueAegisAgent
from backend.agents.arbiter import ArenaArbiterAgent
from backend.agents.adversarial_trainer import global_adversarial_trainer
from backend.agents.fintech_sentinel import global_fintech_sentinel
from backend.agents.quant_investigator import global_quant_investigator
from backend.agents.secops_copilot import global_secops_copilot
from backend.agents.work_order_generator import global_work_order_generator
from backend.simulation import simulation_scope
from backend.run_store import get_run, save_run
from backend.observability import event

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup: make sure the default DB has its schema on a fresh clone
    try:
        init_db()
    except Exception as e:
        print(f"[AIGIS] Failed to initialise default database schema: {e}")
    try:
        stream_engine.start(tps=10, attack_ratio=0.01)
        print("[AIGIS] Live Telemetry Stream Engine started (10 TPS, 99% Benign, 1% Attack).")
    except Exception as e:
        print(f"[AIGIS] Failed to start stream engine: {e}")
    yield
    # shutdown
    try:
        stream_engine.stop()
    except Exception:
        pass

AIGIS_API_TOKEN = os.getenv("AIGIS_API_TOKEN") or secrets.token_urlsafe(32)
_ENABLE_DOCS = os.getenv("AIGIS_ENABLE_DOCS", "0") == "1"


class ApiInput(BaseModel):
    """Shared validation for JSON fields used by the dashboard API."""
    model_config = ConfigDict(extra="allow", allow_inf_nan=False)
    max_limit: int = Field(default=50, ge=1, le=10000)
    burst_streams: int = Field(default=15, ge=1, le=100)
    cycles: int = Field(default=5, ge=1, le=20)
    rounds: int = Field(default=1, ge=1, le=10)
    total_rows: int = Field(default=1000000, ge=1, le=2000000)
    attack_ratio: float = Field(default=0.01, ge=0, le=0.5)
    sample_limit: int = Field(default=5000, ge=1, le=1000000)
    tps: int = Field(default=10, ge=1, le=200)
    window_seconds: int = Field(default=60, ge=1, le=3600)
    limit: int = Field(default=5, ge=1, le=10000)
    amount: float = 500.0
    device_entropy: float = Field(default=0.85, ge=0, le=1)
    simulated_velocity: int | None = Field(default=None, ge=1, le=10000)
    is_active: int = Field(default=1, ge=0, le=1)
    provider: str = "heuristic"
    api_key: str = ""
    model_name: str = ""
    base_url: str = ""
    query: str = ""
    db_path: str = ""
    prompt: str = ""
    execute: bool = True
    filename: str | None = None
    scenario: str = ""
    content: str = ""
    raw_spec: str = "{}"
    client_ip: str = ""
    user_id: str = ""
    voucher_code: str = ""
    rule_id: str = ""
    target_endpoint: str = ""
    threat_type: str = ""
    incident_id: str | None = None
    epoch_ms: int = Field(default=0, ge=0)
    timestamp: str = ""
    severity: str = ""
    velocity_tps: float = 0.0
    financial_loss: float = 0.0
    rca_summary: str = ""
    remediation_patch: str = ""
    status: str = ""
    seed: int | None = Field(default=None, ge=0, le=4294967295)


_simulation_lock = threading.Lock()

app = FastAPI(
    title="AIGIS Autonomous Wargame Engine",
    description="Adversarial Intelligence for Generative Immunity & Security — Multi-Agent Proving Ground",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if _ENABLE_DOCS else None,
    redoc_url="/redoc" if _ENABLE_DOCS else None,
    openapi_url="/openapi.json" if _ENABLE_DOCS else None,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)


@app.middleware("http")
async def local_api_auth_middleware(request: Request, call_next):
    """Require the per-process token for every API call; the UI receives it in a meta tag."""
    if request.url.path.startswith("/api/"):
        supplied = request.headers.get("x-aigis-token", "")
        # Plain <a href> downloads can't set headers; allow a query token for this read-only GET only.
        if not supplied and request.method == "GET" and request.url.path == "/api/v1/dataset/download":
            supplied = request.query_params.get("token", "")
        if not hmac.compare_digest(supplied, AIGIS_API_TOKEN):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        if request.method in {"POST", "PUT", "PATCH"} and not request.url.path.endswith(("/upload_db", "/upload_csv")):
            try:
                raw = await request.body()
                body = json.loads(raw) if raw else {}
                validated = ApiInput.model_validate(body)
                normalized = validated.model_dump(exclude_unset=True)
                request._body = json.dumps(normalized).encode()
                request._json = normalized
            except (ValueError, ValidationError):
                return JSONResponse(status_code=422, content={"detail": "Invalid request body or field value"})
    request_id = uuid.uuid4().hex
    started = time.perf_counter()
    path = request.url.path
    isolated = path in {"/api/v1/wargame/run_full", "/api/v1/wargame/train", "/api/v1/wargame/scenario/run"}
    shared_mutation = request.method == "POST" and (
        path.startswith(("/api/v1/target/", "/api/v1/voucher/", "/api/v1/fintech/", "/api/v1/wargame/stage/"))
        or path == "/api/v1/wargame/recheck_multicycle")
    if shared_mutation:
        while not _simulation_lock.acquire(blocking=False):
            await asyncio.sleep(0.01)
    try:
        if isolated:
            body = await request.json()
            with simulation_scope(body.get("seed")) as run:
                request.state.simulation_run = run
                response = await call_next(request)
        else:
            response = await call_next(request)
    finally:
        if shared_mutation:
            _simulation_lock.release()
    event("http.completed", request_id=request_id, method=request.method, path=path,
          status=response.status_code, duration_ms=round((time.perf_counter()-started)*1000, 2))
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

# Khởi tạo các Agent
rea_agent = READissectorAgent()
red_agent = RedCerebrusAgent()
sandbox_agent = SandboxRunnerAgent()
blue_agent = BlueAegisAgent()
arbiter_agent = ArenaArbiterAgent()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
BUNDLE_FILE = os.path.join(BASE_DIR, "backend", "mock_target", "checkout_bundle.js")

# Bộ nhớ lưu trạng thái Wargame hiện tại
wargame_state = {
    "current_stage": "IDLE",
    "rea_report": None,
    "red_report": None,
    "initial_attack_report": None,
    "patch_report": None,
    "retest_attack_report": None,
    "regression_report": None,
    "dossier": None
}

# ==============================================================================
# 1. AGENT CONFIGURATION & LLM SETTINGS
# ==============================================================================

@app.get("/api/v1/agent/config")
async def get_agent_config():
    """Lấy thông tin trạng thái Agent Engine và mô hình LLM đang kết nối"""
    return global_llm_engine.get_status()

@app.post("/api/v1/agent/config")
async def set_agent_config(request: Request):
    """Cấu hình Nhà cung cấp LLM, API Key và Model từ giao diện"""
    data = await request.json()
    provider = data.get("provider", "heuristic")
    api_key = data.get("api_key", "")
    model_name = data.get("model_name", "")
    base_url = data.get("base_url", "")
    global_llm_engine.configure(provider=provider, api_key=api_key, model_name=model_name, base_url=base_url)
    return {
        "status": "CONFIG_UPDATED",
        "current_config": global_llm_engine.get_status(),
        "provider": provider,
        "model_name": global_llm_engine.model_name
    }

@app.post("/api/v1/agent/test_key")
async def test_agent_api_key(request: Request):
    """Kiểm tra trực tiếp API Key kết nối thực tế tới Cloud LLM (Gemini, Groq, OpenAI)"""
    data = await request.json()
    provider = data.get("provider")
    api_key = data.get("api_key")
    model_name = data.get("model_name")
    
    if provider:
        global_llm_engine.configure(provider=provider, api_key=api_key or "", model_name=model_name or "")
        
    result = await global_llm_engine.test_connection()
    return result

# ==============================================================================
# 2. TARGET ENDPOINTS (Hệ thống giả lập bị tấn công)
# ==============================================================================

@app.post("/api/v1/voucher/claim")
async def claim_voucher_endpoint(request: Request):
    data = await request.json()
    user_id = data.get("user_id", "anonymous_user")
    voucher_code = data.get("voucher_code", "TET2026_DEFAULT")
    amount = float(data.get("amount", 500.0))
    res = await mock_store.claim_voucher(user_id=user_id, voucher_code=voucher_code, amount=amount)
    return JSONResponse(status_code=res.get("status_code", 200), content=res)

@app.get("/api/v1/target/status")
async def get_target_status():
    return {
        "budget_remaining": mock_store.budget_remaining,
        "vouchers_issued_count": len(mock_store.vouchers_issued),
        "patch_enabled": mock_store.patch_enabled,
        "user_claims": mock_store.user_claims
    }

@app.post("/api/v1/target/reset")
async def reset_target():
    mock_store.reset()
    global wargame_state
    wargame_state = {
        "current_stage": "IDLE",
        "rea_report": None,
        "red_report": None,
        "initial_attack_report": None,
        "patch_report": None,
        "retest_attack_report": None,
        "regression_report": None,
        "dossier": None
    }
    return {"message": "Target and Wargame state reset successfully."}

# ==============================================================================
# 3. WARGAME STEP-BY-STEP AGENT EXECUTION
# ==============================================================================

@app.post("/api/v1/wargame/stage/1_rea")
async def run_stage_rea():
    report = await rea_agent.analyze_target(BUNDLE_FILE)
    wargame_state["rea_report"] = report
    wargame_state["current_stage"] = "STAGE_1_REA_COMPLETED"
    return report

@app.post("/api/v1/wargame/stage/2_red_team")
async def run_stage_red(request: Request = None):
    burst_count = 15
    if request:
        try:
            body = await request.json()
            burst_count = int(body.get("burst_streams", 15))
        except Exception:
            pass
    burst_count = min(burst_count, 100)

    if not wargame_state.get("rea_report"):
        wargame_state["rea_report"] = await rea_agent.analyze_target(BUNDLE_FILE)
        
    report = await red_agent.generate_attack_plan(wargame_state["rea_report"], concurrency_burst=burst_count)
    wargame_state["red_report"] = report
    wargame_state["current_stage"] = "STAGE_2_RED_PLAN_READY"
    return report

@app.post("/api/v1/wargame/stage/3_sandbox_attack")
async def run_stage_attack(request: Request = None):
    burst_count = 15
    if request:
        try:
            body = await request.json()
            burst_count = int(body.get("burst_streams", 15))
        except Exception:
            pass
    burst_count = min(burst_count, 100)

    # Clean reset so exploit consistently demonstrates vulnerability
    mock_store.reset()
    report = await sandbox_agent.execute_burst_attack(
        user_id="usr_attacker_cerebrus_01",
        voucher_code="TET2026_VIP",
        burst_count=burst_count,
        amount=500.0
    )
    wargame_state["initial_attack_report"] = report
    wargame_state["current_stage"] = "STAGE_3_INITIAL_ATTACK_COMPLETED"
    return report

@app.post("/api/v1/wargame/stage/4_blue_patch")
async def run_stage_patch():
    if not wargame_state.get("initial_attack_report"):
        return {"error": "Must execute attack first."}
    report = await blue_agent.analyze_and_synthesize_patch(wargame_state["initial_attack_report"])
    wargame_state["patch_report"] = report
    wargame_state["current_stage"] = "STAGE_4_PATCH_DEPLOYED"
    return report

@app.post("/api/v1/wargame/stage/5_retest")
async def run_stage_retest(request: Request = None):
    burst_count = 15
    if request:
        try:
            body = await request.json()
            burst_count = int(body.get("burst_streams", 15))
        except Exception:
            pass
    burst_count = min(burst_count, 100)

    # Tấn công lại sau khi đã vá
    retest_report = await sandbox_agent.execute_burst_attack(
        user_id="usr_attacker_cerebrus_01",
        voucher_code="TET2026_VIP",
        burst_count=burst_count,
        amount=500.0
    )
    wargame_state["retest_attack_report"] = retest_report

    # Chạy kiểm tra zero-regression
    regression_report = await blue_agent.run_zero_regression_test(sample_users=50)
    wargame_state["regression_report"] = regression_report
    wargame_state["current_stage"] = "STAGE_5_RETEST_AND_REGRESSION_COMPLETED"
    return {
        "retest": retest_report,
        "regression": regression_report
    }

@app.post("/api/v1/wargame/recheck_multicycle")
async def run_multicycle_recheck_endpoint(request: Request = None):
    """Chạy kiểm tra lại nhiều chu kỳ liên tiếp với vi sai thời gian ngẫu nhiên (Multi-Cycle Retest)"""
    cycles = 5
    burst_count = 15
    body = {}
    if request:
        try:
            body = await request.json()
            cycles = int(body.get("cycles", 5))
            burst_count = int(body.get("burst_streams", 15))
        except Exception:
            pass
    cycles = min(cycles, 20)
    burst_count = min(burst_count, 100)
    # Copy the deployed control configuration into an isolated retest store.
    enabled, modules = mock_store.patch_enabled, dict(mock_store.patch_modules)
    with simulation_scope(body.get("seed") if request else None) as run:
        mock_store.patch_enabled, mock_store.patch_modules = enabled, modules
        result = await global_adversarial_trainer.run_multicycle_recheck(
            cycles=cycles, burst_streams=burst_count, seed=run["seed"])
        config = {**run, "kind": "recheck", "cycles": cycles, "burst_streams": burst_count,
                  "patch_enabled": enabled, "patch_modules": modules}
        result.update(run_id=run["run_id"], configuration=config)
        await asyncio.to_thread(save_run, run["run_id"], config, result)
        return result

@app.post("/api/v1/wargame/stage/6_dossier")
async def run_stage_dossier():
    attack_report = wargame_state.get("initial_attack_report", {})
    patch_report = wargame_state.get("patch_report", {})
    regression_report = wargame_state.get("regression_report", {})
    retest_report = wargame_state.get("retest_attack_report", {})
    dossier = await arbiter_agent.generate_dossier(attack_report, patch_report, regression_report, retest_report)
    wargame_state["dossier"] = dossier
    wargame_state["current_stage"] = "WARGAME_FINISHED"
    return dossier

@app.post("/api/v1/wargame/train")
async def train_adversarial_wargame(request: Request = None):
    """Huấn luyện đối kháng đa vòng Red vs Blue (Co-Evolution Training)"""
    rounds = 3
    burst_count = 15
    body = {}
    if request:
        try:
            body = await request.json()
            rounds = int(body.get("rounds", 3))
            burst_count = int(body.get("burst_streams", 15))
        except Exception:
            pass
    rounds = min(rounds, 10)
    burst_count = min(burst_count, 100)
            
    result = await global_adversarial_trainer.train_adversarial_rounds(
        total_rounds=rounds, burst_streams=burst_count, seed=body.get("seed") if request else None)
    return result

@app.post("/api/v1/wargame/run_full")
async def run_full_wargame(request: Request = None):
    """Chạy toàn bộ 5 Agent Wargame trong 1 chu trình duy nhất"""
    body = await request.json() if request else {}
    result = await global_adversarial_trainer.train_adversarial_rounds(
        total_rounds=body.get("rounds", 1), burst_streams=body.get("burst_streams", 15), seed=body.get("seed"))
    pair = result["round_evidence"][-1]
    rea = await rea_agent.analyze_target(BUNDLE_FILE)
    red = await red_agent.generate_attack_plan(rea, concurrency_burst=body.get("burst_streams", 15))
    return {**result, "stage": "WARGAME_FINISHED", "initial_attack": pair["attack"],
            "rea": rea, "red_team": red,
            "blue_team": {"patch_code": global_adversarial_trainer.generate_composite_patch_diff([])},
            "retest": pair["retest"], "regression": result["regression_report"]}

@app.get("/api/v1/wargame/state")
async def get_wargame_state():
    return wargame_state


@app.get("/api/v1/wargame/runs/{run_id}")
async def get_simulation_run(run_id: str):
    result = await asyncio.to_thread(get_run, run_id)
    return result if result else JSONResponse(status_code=404, content={"error": "Run not found"})


@app.post("/api/v1/wargame/runs/{run_id}/replay")
async def replay_simulation_run(run_id: str):
    saved = await asyncio.to_thread(get_run, run_id)
    if not saved:
        return JSONResponse(status_code=404, content={"error": "Run not found"})
    config = saved["configuration"]
    if config.get("kind") == "recheck":
        with simulation_scope(config["seed"]) as run:
            mock_store.patch_enabled = config["patch_enabled"]
            mock_store.patch_modules = config["patch_modules"]
            result = await global_adversarial_trainer.run_multicycle_recheck(
                config["cycles"], config["burst_streams"], seed=config["seed"])
            replay_config = {**config, **run}
            result.update(run_id=run["run_id"], configuration=replay_config)
            await asyncio.to_thread(save_run, run["run_id"], replay_config, result)
            return result
    return await global_adversarial_trainer.train_adversarial_rounds(
        total_rounds=config["total_rounds"], burst_streams=config["burst_streams"], seed=config["seed"])

# ==============================================================================
# 4. DATASET EXPLORER & SYNTHETIC TELEMETRY (1,000,000 ROWS)
# ==============================================================================

@app.get("/api/v1/dataset/info")
async def get_dataset_info_endpoint():
    """Lấy thông tin siêu dữ liệu & bản xem trước dataset 1M dòng"""
    return get_dataset_metadata()

@app.post("/api/v1/dataset/generate")
async def generate_dataset_endpoint(request: Request = None):
    """Sinh tập dữ liệu mô phỏng 1,000,000 dòng cực kỳ chi tiết"""
    total_rows = 1_000_000
    attack_ratio = 0.035
    body = {}
    if request:
        try:
            body = await request.json()
            total_rows = int(body.get("total_rows", 1_000_000))
            attack_ratio = float(body.get("attack_ratio", 0.035))
        except Exception:
            pass
    total_rows = max(1, min(total_rows, 2_000_000))
    attack_ratio = max(0.001, min(attack_ratio, 0.5))

    stats = await asyncio.to_thread(generate_million_row_dataset, total_rows=total_rows, attack_ratio=attack_ratio,
                                    seed=body.get("seed") if request else None)
    return stats

@app.get("/api/v1/dataset/download")
async def download_dataset_endpoint():
    """Tải trực tiếp file CSV 1,000,000 dòng về máy"""
    if os.path.exists(CSV_PATH):
        return FileResponse(
            path=CSV_PATH,
            filename="aigis_simulated_traffic_1m.csv",
            media_type="text/csv"
        )
    return JSONResponse(status_code=404, content={"error": "Dataset not yet generated."})

# ==============================================================================
# 5. DATABASE INTEGRATION (SQLite 3 Connection for 1,000,000 Rows)
# ==============================================================================

@app.get("/api/v1/database/stats")
async def get_database_stats_endpoint():
    """Lấy trạng thái kết nối & tổng quan dữ liệu trong SQLite Database"""
    return get_db_stats()

@app.get("/api/v1/database/info")
async def get_active_db_info_endpoint():
    """Lấy thông tin Database hiện hành đang kết nối"""
    return get_active_db_info()

@app.get("/api/v1/database/schema")
async def get_database_schema_endpoint(table_name: str = "telemetry"):
    """Lấy cấu trúc bảng và danh sách các bảng trong DB"""
    tables = get_db_tables()
    schema = get_table_schema(table_name)
    return {"tables": tables, "active_table": table_name, "schema": schema}

@app.get("/api/v1/database/model")
async def get_database_model_endpoint():
    """Lấy mô hình lược đồ quan hệ bảng (Power BI Model View Graph: 20 Pages & Relationships)"""
    return get_database_model_graph()

@app.get("/api/v1/database/table_data")
async def get_database_table_data_endpoint(table_name: str = "telemetry", limit: int = 15, offset: int = 0, search: str = ""):
    """Truy vấn dữ liệu chi tiết của từng bảng (Power BI Data View) có phân trang & tìm kiếm"""
    return query_table_data(table_name=table_name, limit=limit, offset=offset, search=search)

@app.get("/api/v1/database/rows")
async def get_database_rows_endpoint(limit: int = 20, offset: int = 0, filter_type: str = "all"):
    """Truy vấn danh sách rows trực tiếp từ SQLite Database với filter và pagination"""
    rows = query_telemetry_rows(limit=limit, offset=offset, filter_type=filter_type)
    return {"rows": rows, "count": len(rows), "filter_type": filter_type}

@app.post("/api/v1/database/sql")
async def execute_sql_endpoint(request: Request):
    """Thực thi câu lệnh SQL SELECT an toàn từ giao diện người dùng"""
    body = await request.json()
    query = body.get("query", "SELECT * FROM telemetry LIMIT 10")
    max_limit = int(body.get("max_limit", 50))
    result = await asyncio.to_thread(execute_raw_sql, query, max_limit)
    return result

@app.post("/api/v1/database/connect")
async def connect_database_endpoint(request: Request):
    """Kết nối thẳng tới một file SQLite Database (.db, .sqlite) trên máy"""
    body = await request.json()
    db_path = body.get("db_path", "").strip()
    if body.get("db_path") == "default":
        from backend.database import DB_PATH as default_db_path
        db_path = default_db_path
    if not db_path:
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing db_path parameter"})
    res = set_active_db(db_path)
    return res

async def _stream_upload_to_disk(file: UploadFile, dest_path: Path, max_bytes: int = 50 * 1024 * 1024) -> tuple[bool, str]:
    total = 0
    completed = False
    created = False
    try:
        with open(dest_path, "xb") as fout:
            created = True
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    return False, "File exceeds upload size limit"
                fout.write(chunk)
        completed = True
        return True, ""
    finally:
        try:
            if created and not completed:
                dest_path.unlink(missing_ok=True)
        finally:
            await file.close()


@app.post("/api/v1/database/upload_db")
async def upload_database_endpoint(file: UploadFile = File(...)):
    """Tải lên file Database SQLite (.db, .sqlite) và kết nối thẳng"""
    original_name = os.path.basename(file.filename or "").strip()
    if not original_name.lower().endswith((".db", ".sqlite", ".sqlite3")):
        return JSONResponse(status_code=400, content={"success": False, "error": "Only .db, .sqlite, and .sqlite3 database files are accepted"})

    upload_dir = Path(BASE_DIR) / "backend" / "datasets" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex[:12]}{Path(original_name).suffix.lower()}"
    dest_path = upload_dir / stored_name

    ok, error = await _stream_upload_to_disk(file, dest_path)
    if not ok:
        return JSONResponse(status_code=413, content={"success": False, "error": error})

    res = set_active_db(str(dest_path))
    if not res.get("success"):
        try:
            dest_path.unlink(missing_ok=True)
        except OSError:
            pass
    if isinstance(res, dict):
        res["source_name"] = original_name
        res["stored_name"] = stored_name
        res["source_type"] = "db"
    return res

@app.post("/api/v1/database/upload_csv")
async def upload_csv_endpoint(file: UploadFile = File(...), table_name: str = "telemetry"):
    """Tải lên file CSV bất kỳ và nạp thẳng vào SQLite Database"""
    original_name = os.path.basename(file.filename or "").strip()
    if not original_name.lower().endswith(".csv"):
        return JSONResponse(status_code=400, content={"success": False, "error": "Only .csv files are accepted"})

    upload_dir = Path(BASE_DIR) / "backend" / "datasets" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex[:12]}.csv"
    dest_path = upload_dir / stored_name

    ok, error = await _stream_upload_to_disk(file, dest_path)
    if not ok:
        return JSONResponse(status_code=413, content={"success": False, "error": error})

    dest_db = upload_dir / f"{Path(stored_name).stem}.db"
    res = await asyncio.to_thread(
        import_custom_csv_to_db,
        str(dest_path),
        table_name,
        str(dest_db),
    )
    if isinstance(res, dict):
        res["source_name"] = original_name
        res["stored_name"] = stored_name
        res["source_type"] = "csv"
    return res

@app.post("/api/v1/database/text_to_sql")
async def text_to_sql_endpoint(request: Request):
    """AI Text-to-SQL: Dịch câu hỏi tiếng Việt/Anh thành SQL SQLite và thực thi"""
    body = await request.json()
    prompt = body.get("prompt", "").strip()
    execute = bool(body.get("execute", True))
    if not prompt:
        return JSONResponse(status_code=400, content={"success": False, "error": "Query prompt cannot be empty"})
    
    result = await generate_sql_from_prompt(prompt, execute=execute)
    return result

@app.post("/api/v1/database/sync")
async def sync_csv_to_database():
    """Đồng bộ nạp toàn bộ file CSV 1,000,000 dòng vào SQLite Database"""
    return await asyncio.to_thread(import_csv_to_db)

# ==============================================================================
# 5. FRONTEND SERVING
# ==============================================================================


@app.get("/api/v1/database/uploads")
async def get_uploaded_databases_list():
    """Liệt kê danh sách các cơ sở dữ liệu và file CSV đã tải lên"""
    return list_uploaded_databases()

@app.post("/api/v1/database/delete")
async def delete_database_endpoint(request: Request = None):
    """Xóa một database/csv đã tải lên hoặc xóa database custom hiện tại"""
    filename = None
    if request:
        try:
            body = await request.json()
            filename = body.get("filename")
        except Exception:
            pass
    res = delete_uploaded_database(filename)
    return res


@app.post("/api/v1/database/classify")
async def classify_dataset_traffic(request: Request = None):
    """AIGIS AI Engine: Tự động quét và xác định Benign Traffic vs Attack Events"""
    sample_limit = 5000
    if request:
        try:
            body = await request.json()
            sample_limit = int(body.get("sample_limit", 5000))
        except Exception:
            pass
    from backend.traffic_classifier import run_autonomous_dataset_classification
    res = await asyncio.to_thread(run_autonomous_dataset_classification, sample_limit=sample_limit)
    return res


@app.post("/api/v1/database/classify_deep")
async def classify_dataset_deep_dive(request: Request = None):
    """AIGIS AI Engine: Deep-Dive Multi-Stage Forensic Classification"""
    sample_limit = 10000
    if request:
        try:
            body = await request.json()
            sample_limit = int(body.get("sample_limit", 10000))
        except Exception:
            pass
    from backend.traffic_classifier import run_deep_dive_traffic_classification
    res = await run_deep_dive_traffic_classification(sample_limit=sample_limit)
    return res

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        dashboard, _ = build_dashboard(index_path)
        token_meta = f'<meta name="aigis-token" content="{html.escape(AIGIS_API_TOKEN, quote=True)}">'
        dashboard = dashboard.replace("</head>", token_meta + "\n</head>", 1)
        policy = ("default-src 'self'; script-src 'self'; worker-src 'self'"
                  + "; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        return HTMLResponse(content=dashboard, headers={"Content-Security-Policy": policy})
    return HTMLResponse(content="<h1>AIGIS Dashboard not found in frontend/index.html</h1>", status_code=404)


@app.get("/assets/model-layout-worker.js")
async def model_layout_worker():
    return FileResponse(os.path.join(FRONTEND_DIR, "model-layout-worker.js"), media_type="text/javascript")


@app.get("/assets/model-layout.js")
async def model_layout_engine():
    return FileResponse(os.path.join(FRONTEND_DIR, "model-layout.js"), media_type="text/javascript")


@app.get("/assets/vendor/elk.bundled.js")
async def model_layout_vendor():
    return FileResponse(os.path.join(FRONTEND_DIR, "vendor", "elk.bundled.js"), media_type="text/javascript")


@app.get("/assets/dashboard.js")
async def dashboard_script():
    _, script = build_dashboard(os.path.join(FRONTEND_DIR, "index.html"))
    return Response(script, media_type="text/javascript")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.server:app", host="127.0.0.1", port=8000, reload=False)


# ==============================================================================
# 10. MULTI-SCENARIO VULNERABILITY WARGAMING SUITE (PILLAR 1)
# ==============================================================================

@app.get("/api/v1/wargame/scenarios")
async def list_wargame_scenarios():
    """Danh mục 4 kịch bản lỗ hổng nghiệp vụ trong AIGIS"""
    return {
        "scenarios": [
            {
                "id": "TOCTOU_RACE_CONDITION",
                "name": "Concurrency Race Condition (TOCTOU)",
                "category": "Time-of-Check to Time-of-Use",
                "owasp_api": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
                "cwe": "CWE-367",
                "cvss": 8.8,
                "target_endpoint": "/api/v1/voucher/claim",
                "description": "Multi-stream single-packet concurrency burst exploiting delayed database balance commit."
            },
            {
                "id": "BOLA_IDOR",
                "name": "BOLA / IDOR Account Drain",
                "category": "Broken Object Level Authorization",
                "owasp_api": "API1:2023 - Broken Object Level Authorization",
                "cwe": "CWE-639",
                "cvss": 9.1,
                "target_endpoint": "/api/v1/account/{account_id}/withdraw",
                "description": "Unauthorized direct object reference debiting funds from arbitrary victim accounts."
            },
            {
                "id": "NEGATIVE_AMOUNT_TAMPERING",
                "name": "Negative Amount & Parameter Tampering",
                "category": "Input Boundary Violation",
                "owasp_api": "API3:2023 - Broken Object Property Level Authorization",
                "cwe": "CWE-20",
                "cvss": 8.5,
                "target_endpoint": "/api/v1/payment/checkout",
                "description": "Manipulating transaction amounts with negative numbers or inverted discounts to reverse cash flow."
            },
            {
                "id": "STEP_SKIPPING_STATE_BYPASS",
                "name": "Step-Skipping & State Machine Bypass",
                "category": "Workflow State Inversion",
                "owasp_api": "API6:2023 - Business Logic Abuse",
                "cwe": "CWE-840",
                "cvss": 7.9,
                "target_endpoint": "/api/v1/order/confirm",
                "description": "Directly invoking fulfillment state transition while bypassing intermediate payment steps."
            }
        ]
    }

@app.post("/api/v1/wargame/scenario/run")
async def run_scenario_wargame(request: Request = None):
    """Thực thi tấn công và kiểm định theo từng kịch bản lỗ hổng nghiệp vụ"""
    scenario = "TOCTOU_RACE_CONDITION"
    burst_count = 15
    if request:
        try:
            body = await request.json()
            scenario = body.get("scenario", "TOCTOU_RACE_CONDITION")
            burst_count = int(body.get("burst_streams", 15))
        except Exception:
            pass

    if scenario == "ALL_SCENARIOS_COMPOSITE":
        # Chạy kiểm thử liên hoàn cả 4 kịch bản
        r1 = await sandbox_agent.execute_burst_attack(burst_count=burst_count)
        r2 = await sandbox_agent.execute_bola_attack()
        r3 = await sandbox_agent.execute_tamper_attack()
        r4 = await sandbox_agent.execute_step_skipping_attack()
        total_loss = r1["total_stolen_amount"] + r2["total_stolen_amount"] + r3["total_stolen_amount"] + r4["total_stolen_amount"]
        all_vulnerable = any([r1["is_vulnerable"], r2["is_vulnerable"], r3["is_vulnerable"], r4["is_vulnerable"]])
        return {
            "scenario": "ALL_SCENARIOS_COMPOSITE",
            "is_vulnerable": all_vulnerable,
            "total_capital_at_risk": total_loss,
            "results": {
                "toctou_race_condition": r1,
                "bola_idor": r2,
                "negative_amount_tampering": r3,
                "step_skipping_state_bypass": r4
            }
        }

    return await sandbox_agent.execute_scenario(scenario=scenario, burst_count=burst_count)

# ==============================================================================
# 11. PII & SENSITIVE DATA EXPOSURE SCANNER (PILLAR 2)
# ==============================================================================

@app.post("/api/v1/scanner/pii")
async def scan_pii_endpoint(request: Request = None):
    """Dò quét rò rỉ thẻ tín dụng (PAN), CCCD, Bearer Token trong dữ liệu"""
    content = ""
    if request:
        try:
            body = await request.json()
            content = body.get("content", "")
        except Exception:
            pass
    if not content:
        # Mặc định quét mẫu dữ liệu telemetry active
        content = "Sample response: User Bob claimed voucher. Card: 4532-0150-1234-5678, CCCD: 079201019283, Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_secret"

    return global_pii_scanner.scan_content(content)

@app.post("/api/v1/scanner/openapi")
async def scan_openapi_endpoint(request: Request = None):
    """Nạp và bóc tách đồ thị API từ tài liệu OpenAPI / Swagger JSON"""
    raw_spec = "{}"
    if request:
        try:
            body = await request.json()
            raw_spec = body.get("raw_spec", "{}")
        except Exception:
            pass
    return global_pii_scanner.parse_openapi_spec(raw_spec)

# ==============================================================================
# 12. MULTI-LANGUAGE & EDGE 0-DAY WAF PATCH EXPORTER (PILLAR 3)
# ==============================================================================

@app.get("/api/v1/patches/export")
async def export_patches_endpoint(vulnerability_type: str = "TOCTOU_RACE_CONDITION", endpoint: str = "/api/v1/voucher/claim"):
    """Xuất bản vá đa ngôn ngữ (Python, Java Spring, Go) và quy tắc Cloudflare/NGINX/AWS WAF"""
    return global_patch_exporter.generate_all_patches(vulnerability_type=vulnerability_type, endpoint=endpoint)

# ==============================================================================
# 13. FINTECH RISK & VELOCITY ENGINE (PILLAR 4 - Sardine & Feedzai inspired)
# ==============================================================================

@app.post("/api/v1/fintech/evaluate_risk")
async def evaluate_fintech_risk_endpoint(request: Request = None):
    """Đánh giá rủi ro 4 tầng: ALLOW, CHALLENGE_FACEID_OTP, HOLD_REVIEW, BLOCK"""
    client_ip = "192.168.1.105"
    user_id = "usr_client_889"
    amount = 5000.0
    device_entropy = 0.85
    simulated_velocity = None
    if request:
        try:
            body = await request.json()
            client_ip = body.get("client_ip", "192.168.1.105")
            user_id = body.get("user_id", "usr_client_889")
            amount = float(body.get("amount", 5000.0))
            device_entropy = float(body.get("device_entropy", 0.85))
            simulated_velocity = body.get("simulated_velocity")
        except Exception:
            pass

    return mock_store.evaluate_transaction_risk(
        client_ip=client_ip,
        user_id=user_id,
        amount=amount,
        device_entropy=device_entropy,
        simulated_velocity=simulated_velocity,
    )

@app.post("/api/v1/fintech/velocity_rule")
async def set_velocity_rule_endpoint(request: Request = None):
    """Cấu hình luật vận tốc (Velocity Limit per 10s)"""
    limit = 5
    if request:
        try:
            body = await request.json()
            limit = int(body.get("limit", 5))
            mock_store.velocity_limit_per_10s = limit
        except Exception:
            pass
    return {
        "success": True,
        "message": f"Updated velocity threshold to {limit} requests per 10 seconds.",
        "velocity_limit_per_10s": mock_store.velocity_limit_per_10s
    }


# =========================================================================
# REAL-TIME CONTINUOUS STREAMING ENGINE ENDPOINTS
# =========================================================================


@app.get("/api/v1/stream/status")
async def get_stream_status_endpoint():
    """Lấy trạng thái và các chỉ số đo lường của Live Streaming Telemetry"""
    return stream_engine.get_status()

@app.post("/api/v1/stream/start")
async def start_stream_endpoint(request: Request = None):
    """Bắt đầu luồng phát dữ liệu viễn trắc liên tục"""
    tps = 10
    attack_ratio = 0.01
    if request:
        try:
            body = await request.json()
            tps = int(body.get("tps", 10))
            attack_ratio = float(body.get("attack_ratio", 0.01))
        except Exception:
            pass
    tps = max(1, min(tps, 200))
    attack_ratio = max(0.0, min(attack_ratio, 0.5))
    return stream_engine.start(tps=tps, attack_ratio=attack_ratio)

@app.post("/api/v1/stream/pause")
async def pause_stream_endpoint():
    """Tạm dừng luồng phát dữ liệu"""
    return stream_engine.pause()

@app.post("/api/v1/stream/resume")
async def resume_stream_endpoint():
    """Tiếp tục phát luồng dữ liệu"""
    return stream_engine.resume()

@app.post("/api/v1/stream/stop")
async def stop_stream_endpoint():
    """Dừng hoàn toàn luồng phát dữ liệu"""
    return stream_engine.stop()

@app.get("/api/v1/stream/events")
async def get_stream_events_endpoint(limit: int = 15):
    """Lấy danh sách các sự kiện viễn trắc mới nhất từ bộ đệm RAM (đáp ứng < 5ms)"""
    return {
        "status": stream_engine.get_status(),
        "events": stream_engine.get_events(limit=limit)
    }
# ==============================================================================
# 9. FINTECH SENTINEL & ARIA-INSPIRED OPERATIONAL SURVEILLANCE
# ==============================================================================

@app.get("/api/v1/sentinel/status")
async def get_sentinel_status_endpoint():
    """Lấy trạng thái giám sát, dự báo drift và Contextual Stand-Down của Sentinel"""
    return global_fintech_sentinel.get_status()

@app.post("/api/v1/sentinel/evaluate")
async def evaluate_sentinel_endpoint(request: Request = None):
    """Thực thi vòng lặp phân tích chuỗi thời gian Sentinel trên cửa sổ trượt"""
    window_sec = 15
    if request:
        try:
            data = await request.json()
            window_sec = int(data.get("window_seconds", 15))
        except Exception:
            pass
    window_sec = max(1, min(window_sec, 3600))
    return await asyncio.to_thread(global_fintech_sentinel.evaluate_telemetry, window_seconds=window_sec)

@app.post("/api/v1/sentinel/simulate")
async def simulate_sentinel_scenario_endpoint(request: Request):
    """Giả lập kịch bản (flash_sale, toctou_attack, drift_accelerate, normal) để kiểm chứng Sentinel"""
    data = await request.json()
    scenario = data.get("scenario", "flash_sale")
    return global_fintech_sentinel.simulate_scenario(scenario=scenario)

@app.get("/api/v1/sentinel/incidents")
async def get_sentinel_incidents_endpoint(limit: int = 50):
    """Lấy danh mục các sự kiện lỗ hổng và giải pháp trong Incident Memory KB"""
    return {
        "success": True,
        "count": len(get_incident_memory(limit=limit)),
        "incidents": get_incident_memory(limit=limit)
    }

@app.post("/api/v1/sentinel/incidents")
async def add_sentinel_incident_endpoint(request: Request):
    """Ghi nhận một sự cố mới vào Incident Memory KB"""
    data = await request.json()
    success = add_incident_memory(data)
    return {"success": success, "incident": data}

@app.get("/api/v1/sentinel/policies")
async def get_sentinel_policies_endpoint():
    """Lấy danh mục các quy tắc nghiệp vụ và cửa sổ khuyến mãi Flash Sale của Sentinel"""
    return {
        "success": True,
        "policies": get_policy_rules()
    }

@app.post("/api/v1/sentinel/policies/toggle")
async def toggle_sentinel_policy_endpoint(request: Request):
    """Bật/tắt một quy tắc kiểm tra của Sentinel"""
    data = await request.json()
    rule_id = data.get("rule_id", "")
    is_active = int(data.get("is_active", 1))
    success = toggle_policy_rule(rule_id=rule_id, is_active=is_active)
    return {
        "success": success,
        "rule_id": rule_id,
        "is_active": is_active,
        "policies": get_policy_rules()
    }
# ==============================================================================
# 10. DEEP QUANT INVESTIGATOR & PYTHON SANDBOX RCA
# ==============================================================================

@app.post("/api/v1/investigator/diagnose")
async def diagnose_investigator_endpoint(request: Request = None):
    """Thực thi phân tích định lượng RCA chuyên sâu với mã Python tự sinh chạy trong sandbox"""
    target_endpoint = "/api/v1/voucher/claim"
    window_sec = 60
    threat_type = "TOCTOU_RACE_CONDITION"
    if request:
        try:
            data = await request.json()
            target_endpoint = data.get("target_endpoint", target_endpoint)
            window_sec = int(data.get("window_seconds", window_sec))
            threat_type = data.get("threat_type", threat_type)
        except Exception:
            pass
    return await global_quant_investigator.diagnose_anomaly(
        target_endpoint=target_endpoint,
        window_seconds=window_sec,
        threat_type=threat_type
    )

@app.get("/api/v1/investigator/latest")
async def get_latest_investigator_endpoint():
    """Lấy báo cáo RCA định lượng và đoạn mã Python mới nhất của Deep Investigator"""
    if global_quant_investigator.latest_report:
        return global_quant_investigator.latest_report
    # Auto-run if empty
    return await global_quant_investigator.diagnose_anomaly()
# ==============================================================================
# 11. SECOPS COPILOT & WORK ORDER GENERATOR (ARIA Q&A & WOG ADAPTATION)
# ==============================================================================

@app.post("/api/v1/copilot/chat")
async def copilot_chat_endpoint(request: Request):
    """Khung đối thoại SecOps Copilot với khả năng ủy quyền tự động cho Deep Investigator"""
    data = await request.json()
    query = data.get("query", "")
    return await global_secops_copilot.answer_query(query=query)

@app.get("/api/v1/workorder/generate")
async def generate_work_order_endpoint(target_endpoint: str = "/api/v1/voucher/claim"):
    """Tổng hợp phiếu can thiệp kỹ thuật SecOps Work Order chuẩn từ kết quả RCA"""
    return global_work_order_generator.generate_work_order(target_endpoint=target_endpoint)

@app.post("/api/v1/workorder/deploy")
async def deploy_work_order_endpoint():
    """Mô phỏng triển khai Canary Rollout 3 giai đoạn (5% -> 25% -> 100%) và xác minh Zero-Regression"""
    return global_work_order_generator.simulate_rollout()
