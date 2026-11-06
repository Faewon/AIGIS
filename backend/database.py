import os
import sqlite3
import csv
import time
from typing import Dict, Any, List, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
DB_PATH = os.path.join(DATASETS_DIR, "aigis_telemetry.db")
CSV_PATH = os.path.join(DATASETS_DIR, "aigis_simulated_traffic_1m.csv")

# Dynamic active database tracking
ACTIVE_DB_PATH = DB_PATH
ACTIVE_DB_NAME = "aigis_telemetry.db"

def get_connection(custom_path: Optional[str] = None) -> sqlite3.Connection:
    """Tạo kết nối tới SQLite Database với cấu hình tối ưu hiệu năng WAL"""
    global ACTIVE_DB_PATH
    target = custom_path or ACTIVE_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    conn = sqlite3.connect(target, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA cache_size = -64000") # 64MB cache
    return conn

def set_active_db(path: str) -> Dict[str, Any]:
    """Chuyển đổi kết nối trực tiếp sang một Database SQLite bất kỳ trên máy"""
    global ACTIVE_DB_PATH, ACTIVE_DB_NAME
    abs_path = os.path.abspath(path.strip().strip('"').strip("'"))
    if not os.path.exists(abs_path):
        return {"success": False, "error": f"Database file not found at: {abs_path}"}

    try:
        conn = sqlite3.connect(abs_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [r[0] for r in cur.fetchall()]
        conn.close()

        ACTIVE_DB_PATH = abs_path
        ACTIVE_DB_NAME = os.path.basename(abs_path)
        size_mb = round(os.path.getsize(ACTIVE_DB_PATH) / (1024 * 1024), 2)

        return {
            "success": True,
            "connected": True,
            "db_path": ACTIVE_DB_PATH,
            "db_name": ACTIVE_DB_NAME,
            "tables": tables,
            "size_mb": size_mb,
            "stats": get_db_stats()
        }
    except Exception as e:
        return {"success": False, "error": f"File is not a valid SQLite database: {str(e)}"}

def get_active_db_info() -> Dict[str, Any]:
    """Lấy thông tin Database hiện hành đang kết nối"""
    global ACTIVE_DB_PATH, ACTIVE_DB_NAME
    size_mb = round(os.path.getsize(ACTIVE_DB_PATH) / (1024 * 1024), 2) if os.path.exists(ACTIVE_DB_PATH) else 0.0
    tables = get_db_tables()
    return {
        "active_db_path": ACTIVE_DB_PATH,
        "active_db_name": ACTIVE_DB_NAME,
        "size_mb": size_mb,
        "tables": tables,
        "connected": os.path.exists(ACTIVE_DB_PATH)
    }

def get_db_tables(custom_path: Optional[str] = None) -> List[str]:
    """Liệt kê danh sách bảng trong Database"""
    try:
        conn = get_connection(custom_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [r[0] for r in cur.fetchall()]
        conn.close()
        return tables
    except Exception:
        return []

def get_table_schema(table_name: str = "telemetry") -> List[Dict[str, Any]]:
    """Lấy cấu trúc metadata các cột của một bảng"""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table_name})")
        cols = [
            {"cid": r[0], "name": r[1], "type": r[2], "notnull": bool(r[3]), "dflt_value": r[4], "pk": bool(r[5])}
            for r in cur.fetchall()
        ]
        conn.close()
        return cols
    except Exception:
        return []

def init_db(force_recreate: bool = False) -> bool:
    """Khởi tạo cấu trúc bảng Telemetry trong SQLite nếu chưa tồn tại"""
    if force_recreate and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass

    conn = get_connection(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS telemetry (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT,
        epoch_ms INTEGER,
        user_id TEXT,
        session_id TEXT,
        account_age_days INTEGER,
        kyc_level TEXT,
        credit_score INTEGER,
        client_ip TEXT,
        ip_country TEXT,
        ip_isp TEXT,
        is_datacenter_proxy INTEGER,
        user_agent TEXT,
        device_type TEXT,
        os_platform TEXT,
        tls_ja3_hash TEXT,
        http_protocol TEXT,
        http_method TEXT,
        api_endpoint TEXT,
        has_idempotency_key INTEGER,
        burst_stream_id TEXT,
        burst_concurrency_rank TEXT,
        network_rtt_ms REAL,
        server_latency_ms REAL,
        transaction_amount_usd REAL,
        status_code_unpatched INTEGER,
        status_code_patched INTEGER,
        is_attack INTEGER,
        attack_type TEXT
    )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_is_attack ON telemetry(is_attack)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attack_type ON telemetry(attack_type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_burst ON telemetry(burst_stream_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user ON telemetry(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_epoch ON telemetry(epoch_ms)")

    init_sentinel_tables(conn)

    conn.commit()
    conn.close()
    return True

def init_sentinel_tables(conn: Optional[sqlite3.Connection] = None) -> bool:
    """Khoi tao cac bang Incident Memory va Policy Rules cho FinTech Sentinel va Knowledge Base"""
    should_close = False
    if conn is None:
        conn = get_connection(DB_PATH)
        should_close = True

    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_memory (
        incident_id TEXT PRIMARY KEY,
        epoch_ms INTEGER,
        timestamp TEXT,
        threat_type TEXT,
        target_endpoint TEXT,
        severity TEXT,
        velocity_tps REAL,
        financial_loss REAL,
        rca_summary TEXT,
        remediation_patch TEXT,
        status TEXT
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_epoch ON incident_memory(epoch_ms DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incident_threat ON incident_memory(threat_type)")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS policy_rules (
        rule_id TEXT PRIMARY KEY,
        name TEXT,
        rule_type TEXT,
        endpoint TEXT,
        threshold_value REAL,
        active_from TEXT,
        active_to TEXT,
        is_active INTEGER,
        description TEXT
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_policy_endpoint ON policy_rules(endpoint)")

    # Seed incidents if empty
    cur.execute("SELECT COUNT(*) FROM incident_memory")
    if cur.fetchone()[0] == 0:
        now_ms = int(time.time() * 1000)
        seed_incidents = [
            (
                "INC-2026-001",
                now_ms - 86400000,
                "2026-11-02 10:14:22.105",
                "TOCTOU_RACE_CONDITION",
                "/api/v1/voucher/claim",
                "CRITICAL",
                18.5,
                7500.0,
                "Sub-millisecond gap between SELECT balance check and UPDATE transaction commit allowed 15 concurrent voucher redemptions in single HTTP/2 packet.",
                "Redis SET NX distributed lock with 3.0s lease TTL on user_id key to serialize atomic voucher redemption.",
                "RESOLVED"
            ),
            (
                "INC-2026-002",
                now_ms - 43200000,
                "2026-11-02 22:30:15.820",
                "SYBIL_SWARM",
                "/api/v1/cart/checkout",
                "HIGH",
                34.2,
                12400.0,
                "Distributed bot swarm of 30 randomized user identities routed through datacenter proxies to bypass single-account velocity limits.",
                "Enforced JA3 TLS client fingerprint throttling and subnet CIDR rate limiter combined with device integrity check.",
                "RESOLVED"
            ),
            (
                "INC-2026-003",
                now_ms - 14400000,
                "2026-11-03 07:15:00.412",
                "NEGATIVE_AMOUNT_TAMPERING",
                "/api/v1/payment/checkout",
                "HIGH",
                8.0,
                4800.0,
                "Client-side payload modification sent negative transaction amounts resulting in refund balance inflation.",
                "Added strict Pydantic model validation with PositiveFloat assertion and signed HMAC payload token.",
                "RESOLVED"
            )
        ]
        cur.executemany("""
        INSERT INTO incident_memory (
            incident_id, epoch_ms, timestamp, threat_type, target_endpoint,
            severity, velocity_tps, financial_loss, rca_summary, remediation_patch, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, seed_incidents)

    # Seed policy rules if empty
    cur.execute("SELECT COUNT(*) FROM policy_rules")
    if cur.fetchone()[0] == 0:
        seed_policies = [
            (
                "RULE_FLASH_SALE_TET",
                "Tet Super Sale 50% Flash Promotion",
                "FLASH_SALE_WINDOW",
                "/api/v1/voucher/claim",
                50.0,
                "2026-11-01 00:00:00",
                "2026-11-10 23:59:59",
                1,
                "Allows up to 50 TPS during promotional flash sale if user entropy > 80% and proxy ratio < 15% (Contextual Stand-Down)."
            ),
            (
                "RULE_BURST_CEILING",
                "Global API Gateway Burst Ceiling",
                "MAX_BURST_TPS",
                "*",
                30.0,
                "2026-01-01 00:00:00",
                "2026-12-31 23:59:59",
                1,
                "Upper velocity safety ceiling triggering drift warnings when sustained above 30 TPS across all endpoints."
            ),
            (
                "RULE_USER_CONCURRENCY",
                "Per-User Sub-Second Concurrency Limit",
                "USER_CONCURRENCY_LIMIT",
                "/api/v1/voucher/claim",
                2.0,
                "2026-01-01 00:00:00",
                "2026-12-31 23:59:59",
                1,
                "Maximum 2 concurrent requests per user within 100ms window to detect microsecond race conditions."
            )
        ]
        cur.executemany("""
        INSERT INTO policy_rules (
            rule_id, name, rule_type, endpoint, threshold_value,
            active_from, active_to, is_active, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, seed_policies)

    conn.commit()
    if should_close:
        conn.close()
    return True

def get_incident_memory(limit: int = 50) -> List[Dict[str, Any]]:
    """Lay danh sach ho so su co va ban va trong qua khu tu Incident Memory KB"""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM incident_memory ORDER BY epoch_ms DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

def add_incident_memory(incident: Dict[str, Any]) -> bool:
    """Them ho so su co moi vao Incident Memory KB"""
    try:
        conn = get_connection()
        cur = conn.cursor()
        now_ms = int(time.time() * 1000)
        cur.execute("""
        INSERT OR REPLACE INTO incident_memory (
            incident_id, epoch_ms, timestamp, threat_type, target_endpoint,
            severity, velocity_tps, financial_loss, rca_summary, remediation_patch, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.get("incident_id") or f"INC-{int(time.time())}",
            incident.get("epoch_ms") or now_ms,
            incident.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
            incident.get("threat_type", "UNKNOWN_THREAT"),
            incident.get("target_endpoint", "/api/v1/generic"),
            incident.get("severity", "MEDIUM"),
            float(incident.get("velocity_tps", 0.0)),
            float(incident.get("financial_loss", 0.0)),
            incident.get("rca_summary", ""),
            incident.get("remediation_patch", ""),
            incident.get("status", "RESOLVED")
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def get_policy_rules() -> List[Dict[str, Any]]:
    """Lay danh sach quy tac nghiep vu va cua so khuyen mai cua Sentinel"""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM policy_rules ORDER BY rule_id ASC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

def toggle_policy_rule(rule_id: str, is_active: int) -> bool:
    """Bat/tat mot quy tac Sentinel"""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE policy_rules SET is_active = ? WHERE rule_id = ?", (is_active, rule_id))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def import_csv_to_db(csv_file_path: Optional[str] = None, chunk_size: int = 50_000) -> Dict[str, Any]:
    """
    Nạp toàn bộ file CSV 1,000,000 dòng vào SQLite Database mặc định.
    Sử dụng batch insert và PRAGMA tối ưu hóa để nạp chỉ trong vài giây.
    """
    path = csv_file_path or CSV_PATH
    return import_custom_csv_to_db(csv_file_path=path, table_name="telemetry", chunk_size=chunk_size)

def import_custom_csv_to_db(csv_file_path: str, table_name: str = "telemetry", target_db_path: Optional[str] = None, chunk_size: int = 50_000) -> Dict[str, Any]:
    """
    Nạp bất kỳ file CSV nào (kể cả file tải lên từ người dùng) vào SQLite.
    Tự động suy diễn cấu trúc schema nếu không phải định dạng telemetry mặc định.
    """
    global ACTIVE_DB_PATH, ACTIVE_DB_NAME
    if not os.path.exists(csv_file_path):
        return {"success": False, "error": f"CSV file not found at {csv_file_path}"}

    t0 = time.time()
    dest_db = target_db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(dest_db)), exist_ok=True)

    with open(csv_file_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return {"success": False, "error": "CSV file is empty!"}

    col_count = len(header)
    is_standard_telemetry = (col_count == 29 and "event_id" in header)

    conn = sqlite3.connect(dest_db)
    cur = conn.cursor()
    cur.execute("PRAGMA synchronous = OFF")
    cur.execute("PRAGMA journal_mode = MEMORY")

    if is_standard_telemetry:
        init_db(force_recreate=(dest_db == DB_PATH))
    else:
        # Tạo bảng động cho file CSV tùy chỉnh
        safe_cols = [re_sub(col.strip()) for col in header]
        col_defs = ", ".join([f'"{c}" TEXT' for c in safe_cols])
        cur.execute(f'DROP TABLE IF EXISTS "{table_name}"')
        cur.execute(f'CREATE TABLE "{table_name}" ({col_defs})')

    placeholders = ",".join(["?"] * col_count)
    insert_sql = f'INSERT INTO "{table_name}" VALUES ({placeholders})'

    total_imported = 0
    with open(csv_file_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader) # skip header
        batch = []
        for row in reader:
            if len(row) == col_count:
                batch.append(row)
                if len(batch) >= chunk_size:
                    cur.executemany(insert_sql, batch)
                    total_imported += len(batch)
                    batch.clear()

        if batch:
            cur.executemany(insert_sql, batch)
            total_imported += len(batch)
            batch.clear()

    if is_standard_telemetry:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_is_attack ON telemetry(is_attack)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_attack_type ON telemetry(attack_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_burst ON telemetry(burst_stream_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_user ON telemetry(user_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_epoch ON telemetry(epoch_ms)")

    conn.commit()
    conn.close()

    ACTIVE_DB_PATH = os.path.abspath(dest_db)
    ACTIVE_DB_NAME = os.path.basename(dest_db)

    elapsed = time.time() - t0
    db_size_mb = round(os.path.getsize(dest_db) / (1024 * 1024), 2) if os.path.exists(dest_db) else 0.0

    return {
        "success": True,
        "rows_imported": total_imported,
        "table_name": table_name,
        "columns": header,
        "time_taken_sec": round(elapsed, 2),
        "db_size_mb": db_size_mb,
        "db_path": ACTIVE_DB_PATH,
        "db_name": ACTIVE_DB_NAME
    }

def re_sub(val: str) -> str:
    """Loại bỏ ký tự đặc biệt khỏi tên cột SQL"""
    import re
    cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', val)
    return cleaned if cleaned else "col"

def get_db_stats() -> Dict[str, Any]:
    """Lấy số liệu thống kê tổng hợp từ Database hiện hành"""
    global ACTIVE_DB_PATH, ACTIVE_DB_NAME
    if not os.path.exists(ACTIVE_DB_PATH):
        return {"connected": False, "total_rows": 0, "status": "DATABASE_NOT_CREATED"}

    conn = get_connection()
    cur = conn.cursor()

    try:
        tables = get_db_tables()
        if not tables:
            conn.close()
            return {"connected": True, "total_rows": 0, "status": "DATABASE_EMPTY", "db_name": ACTIVE_DB_NAME}

        # Nếu có bảng telemetry, chạy thống kê chuyên sâu
        if "telemetry" in tables:
            cur.execute("SELECT COUNT(*) FROM telemetry")
            total_rows = cur.fetchone()[0]

            if total_rows == 0:
                conn.close()
                return {"connected": True, "total_rows": 0, "status": "DATABASE_EMPTY", "db_name": ACTIVE_DB_NAME}

            cur.execute("SELECT COUNT(*) FROM telemetry WHERE is_attack = 0")
            benign_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM telemetry WHERE is_attack = 1")
            attack_count = cur.fetchone()[0]

            cur.execute("SELECT attack_type, COUNT(*) FROM telemetry WHERE is_attack = 1 GROUP BY attack_type")
            attacks_by_type = dict(cur.fetchall())

            cur.execute("SELECT SUM(transaction_amount_usd) FROM telemetry WHERE is_attack = 1 AND status_code_unpatched = 200")
            unpatched_theft = cur.fetchone()[0] or 0.0

            cur.execute("SELECT SUM(transaction_amount_usd) FROM telemetry WHERE is_attack = 1 AND status_code_patched = 429")
            patched_saved = cur.fetchone()[0] or 0.0

            cur.execute("SELECT COUNT(DISTINCT user_id) FROM telemetry")
            unique_users = cur.fetchone()[0]

            db_size_mb = round(os.path.getsize(ACTIVE_DB_PATH) / (1024 * 1024), 2)
            conn.close()

            return {
                "connected": True,
                "status": "ONLINE",
                "db_name": ACTIVE_DB_NAME,
                "db_path": ACTIVE_DB_PATH,
                "total_rows": total_rows,
                "benign_rows": benign_count,
                "attack_rows": attack_count,
                "unique_users": unique_users,
                "attacks_by_type": attacks_by_type,
                "unpatched_total_drained_usd": round(unpatched_theft, 2),
                "patched_total_saved_usd": round(patched_saved, 2),
                "db_size_mb": db_size_mb,
                "tables": tables
            }

        # Nếu là database tùy chỉnh khác
        primary_table = tables[0]
        cur.execute(f'SELECT COUNT(*) FROM "{primary_table}"')
        total_rows = cur.fetchone()[0]
        db_size_mb = round(os.path.getsize(ACTIVE_DB_PATH) / (1024 * 1024), 2)
        conn.close()

        return {
            "connected": True,
            "status": "ONLINE_CUSTOM",
            "db_name": ACTIVE_DB_NAME,
            "db_path": ACTIVE_DB_PATH,
            "total_rows": total_rows,
            "benign_rows": 0,
            "attack_rows": 0,
            "unique_users": 0,
            "attacks_by_type": {},
            "unpatched_total_drained_usd": 0.0,
            "patched_total_saved_usd": 0.0,
            "db_size_mb": db_size_mb,
            "tables": tables,
            "primary_table": primary_table
        }
    except Exception as e:
        conn.close()
        return {"connected": False, "error": str(e), "total_rows": 0, "db_name": ACTIVE_DB_NAME}

def query_telemetry_rows(limit: int = 20, offset: int = 0, filter_type: str = "all") -> List[Dict[str, Any]]:
    """Truy vấn các dòng dữ liệu với filter và pagination trực tiếp qua SQL"""
    global ACTIVE_DB_PATH
    if not os.path.exists(ACTIVE_DB_PATH):
        return []

    tables = get_db_tables()
    if not tables:
        return []

    table_name = "telemetry" if "telemetry" in tables else tables[0]
    conn = get_connection()
    cur = conn.cursor()

    try:
        if table_name == "telemetry":
            if filter_type == "attack":
                sql = "SELECT * FROM telemetry WHERE is_attack = 1 ORDER BY epoch_ms DESC LIMIT ? OFFSET ?"
                params = (limit, offset)
            elif filter_type == "benign":
                sql = "SELECT * FROM telemetry WHERE is_attack = 0 ORDER BY epoch_ms DESC LIMIT ? OFFSET ?"
                params = (limit, offset)
            else:
                sql = "SELECT * FROM telemetry ORDER BY epoch_ms DESC LIMIT ? OFFSET ?"
                params = (limit, offset)
        else:
            sql = f'SELECT * FROM "{table_name}" LIMIT ? OFFSET ?'
            params = (limit, offset)

        cur.execute(sql, params)
        raw_rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        
        # Tự động gắn nhãn AI Classification cho từng dòng dữ liệu
        try:
            from .traffic_classifier import classify_traffic_row
        except Exception:
            try:
                from traffic_classifier import classify_traffic_row
            except Exception:
                classify_traffic_row = None

        if classify_traffic_row:
            for r in raw_rows:
                r["ai_classification"] = classify_traffic_row(r)
        return raw_rows
    except Exception:
        conn.close()
        return []

def execute_raw_sql(sql_query: str, max_limit: int = 50) -> Dict[str, Any]:
    """
    Thực thi câu lệnh SQL SELECT an toàn từ giao diện người dùng (Interactive SQL Console & Text-to-SQL).
    Chỉ cho phép các lệnh đọc (SELECT, EXPLAIN, PRAGMA, WITH).
    """
    global ACTIVE_DB_PATH
    clean_sql = sql_query.strip()
    first_word = clean_sql.split()[0].upper() if clean_sql else ""

    if first_word not in ("SELECT", "EXPLAIN", "PRAGMA", "WITH"):
        return {
            "success": False,
            "error": "Security Restriction: Only read-only queries (SELECT, WITH, EXPLAIN) are permitted."
        }

    if not os.path.exists(ACTIVE_DB_PATH):
        return {"success": False, "error": f"Database file does not exist at {ACTIVE_DB_PATH}. Please import first."}

    t0 = time.time()
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(clean_sql)
        columns = [desc[0] for desc in cur.description] if cur.description else []
        rows = [list(r) for r in cur.fetchmany(max_limit)]
        elapsed = time.time() - t0
        conn.close()
        return {
            "success": True,
            "columns": columns,
            "rows": rows,
            "rows_count": len(rows),
            "execution_time_ms": round(elapsed * 1000, 2),
            "sql_query": clean_sql
        }
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e), "sql_query": clean_sql}


def list_uploaded_databases() -> List[Dict[str, Any]]:
    """Liệt kê tất cả các file database/csv đã được người dùng tải lên"""
    upload_dir = os.path.join(DATASETS_DIR, "uploads")
    if not os.path.exists(upload_dir):
        return []
    
    files = []
    for f in os.listdir(upload_dir):
        fp = os.path.join(upload_dir, f)
        if os.path.isfile(fp):
            ext = os.path.splitext(f)[1].lower()
            if ext in [".db", ".sqlite", ".sqlite3", ".csv"]:
                size_mb = round(os.path.getsize(fp) / (1024 * 1024), 2)
                is_active = (os.path.abspath(fp) == os.path.abspath(ACTIVE_DB_PATH))
                files.append({
                    "filename": f,
                    "filepath": fp,
                    "size_mb": size_mb,
                    "type": "database" if ext in [".db", ".sqlite", ".sqlite3"] else "csv",
                    "is_active": is_active
                })
    return files

def delete_uploaded_database(filename: Optional[str] = None) -> Dict[str, Any]:
    """
    Xóa một database đã upload hoặc xóa database custom hiện tại.
    Không bao giờ cho phép xóa database mặc định `aigis_telemetry.db`.
    Sau khi xóa, tự động kết nối lại `aigis_telemetry.db`.
    """
    global ACTIVE_DB_PATH, ACTIVE_DB_NAME
    upload_dir = os.path.join(DATASETS_DIR, "uploads")
    
    target_file = None
    if filename:
        clean_name = os.path.basename(filename.strip())
        target_file = os.path.join(upload_dir, clean_name)
    else:
        # Nếu không truyền filename, kiểm tra xem DB hiện tại có phải là custom/uploaded không
        if os.path.abspath(ACTIVE_DB_PATH) == os.path.abspath(DB_PATH):
            return {
                "success": False,
                "error": "Cannot delete core benchmark database 'aigis_telemetry.db'. You can only delete imported or custom databases."
            }
        target_file = ACTIVE_DB_PATH

    if not target_file or not os.path.exists(target_file):
        return {"success": False, "error": f"File to delete not found: {target_file}"}

    # An toàn tuyệt đối: không xóa DB_PATH
    if os.path.abspath(target_file) == os.path.abspath(DB_PATH):
        return {"success": False, "error": "Protected file: Cannot delete default 'aigis_telemetry.db'."}

    deleted_name = os.path.basename(target_file)

    # Nếu file đang xóa chính là DB đang active, chuyển active về DB_PATH trước
    was_active = (os.path.abspath(target_file) == os.path.abspath(ACTIVE_DB_PATH))
    if was_active:
        ACTIVE_DB_PATH = DB_PATH
        ACTIVE_DB_NAME = "aigis_telemetry.db"

    # Xóa file (và các file WAL, SHM liên quan nếu có)
    try:
        if os.path.exists(target_file):
            os.remove(target_file)
        for extra in ["-wal", "-shm", "-journal"]:
            extra_file = target_file + extra
            if os.path.exists(extra_file):
                try:
                    os.remove(extra_file)
                except Exception:
                    pass
            
        return {
            "success": True,
            "deleted_file": deleted_name,
            "was_active": was_active,
            "restored_default": was_active,
            "active_db": ACTIVE_DB_NAME,
            "active_db_path": ACTIVE_DB_PATH,
            "message": f"Successfully deleted '{deleted_name}'. Active database is now '{ACTIVE_DB_NAME}'."
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to delete file '{deleted_name}': {str(e)}"}


# ==============================================================================
# POWER BI STYLE MULTI-PAGE DATA VIEW & SCHEMA RELATIONSHIP MODEL
# ==============================================================================

TABLE_METADATA_REGISTRY = {
    "incident_memory": {
        "type": "KNOWLEDGE",
        "category": "Incident KB & Forensics",
        "color": "#e11d48",
        "icon": "",
        "description": "Historical business logic exploits, root cause analyses, and verified CRS defense patches."
    },
    "policy_rules": {
        "type": "POLICY",
        "category": "Governance & Policies",
        "color": "#8b5cf6",
        "icon": "",
        "description": "Operational business rules, promotional flash sale windows, and Sentinel stand-down criteria."
    },
    "telemetry": {
        "type": "FACT",
        "category": "Core Telemetry",
        "color": "#0284c7",
        "icon": "",
        "description": "Real-time FinTech API traffic, concurrency bursts, and attack events."
    },
    "dim_users": {
        "type": "DIMENSION",
        "category": "Identity & Accounts",
        "color": "#10b981",
        "icon": "",
        "description": "Master customer identity, account tiers, credit rating, and KYC status."
    },
    "dim_wallets": {
        "type": "DIMENSION",
        "category": "Identity & Accounts",
        "color": "#10b981",
        "icon": "",
        "description": "Multi-currency digital wallet balances and daily transfer ceilings."
    },
    "dim_merchants": {
        "type": "DIMENSION",
        "category": "Commercial Partners",
        "color": "#f59e0b",
        "icon": "",
        "description": "E-Commerce, airline, and F&B merchant profiles and settlement accounts."
    },
    "dim_vouchers": {
        "type": "DIMENSION",
        "category": "Promotions & Rewards",
        "color": "#f59e0b",
        "icon": "",
        "description": "Promotional campaigns, budget caps, and concurrency target vouchers."
    },
    "dim_devices": {
        "type": "DIMENSION",
        "category": "Infrastructure & Telemetry",
        "color": "#64748b",
        "icon": "",
        "description": "Device hardware fingerprints, TLS JA3 hashes, and entropy ratings."
    },
    "dim_ip_locations": {
        "type": "DIMENSION",
        "category": "Infrastructure & Telemetry",
        "color": "#64748b",
        "icon": "",
        "description": "GeoIP intelligence, ASN routing, and datacenter proxy detection."
    },
    "dim_api_endpoints": {
        "type": "DIMENSION",
        "category": "Security & Architecture",
        "color": "#8b5cf6",
        "icon": "",
        "description": "API Gateway route catalog, auth requirements, and OWASP categories."
    },
    "fact_payment_checkout": {
        "type": "FACT",
        "category": "Financial Transactions",
        "color": "#0284c7",
        "icon": "",
        "description": "Checkout transactions, voucher applied, net settlement, and order status."
    },
    "fact_audit_log": {
        "type": "FACT",
        "category": "Security & Governance",
        "color": "#ec4899",
        "icon": "",
        "description": "Administrative actions, parameter mutations, and kernel audit trails."
    },
    "fact_risk_evaluations": {
        "type": "FACT",
        "category": "Risk & Scoring",
        "color": "#ef4444",
        "icon": "",
        "description": "4-Tier real-time scoring, velocity tracking, and challenge decisions."
    },
    "dim_cards_pan": {
        "type": "DIMENSION",
        "category": "Payment Instruments",
        "color": "#10b981",
        "icon": "",
        "description": "Tokenized payment card numbers, BIN validation, and Luhn compliance."
    },
    "dim_bank_accounts": {
        "type": "DIMENSION",
        "category": "Payment Instruments",
        "color": "#10b981",
        "icon": "",
        "description": "Linked domestic bank accounts and verification states."
    },
    "fact_fraud_alerts": {
        "type": "FACT",
        "category": "Security & SOC",
        "color": "#ef4444",
        "icon": "",
        "description": "SOC incidents, suspicious velocity spikes, and automated mitigations."
    },
    "fact_concurrency_locks": {
        "type": "FACT",
        "category": "Security & SOC",
        "color": "#ef4444",
        "icon": "",
        "description": "Redis distributed mutex lock acquisition, hold duration, and race flags."
    },
    "dim_compliance_rules": {
        "type": "DIMENSION",
        "category": "Compliance & Governance",
        "color": "#8b5cf6",
        "icon": "",
        "description": "PCI-DSS 4.0 requirements, SBV Circulars, and OWASP API Top 10 rules."
    },
    "fact_adversarial_rounds": {
        "type": "FACT",
        "category": "Wargame Analytics",
        "color": "#6366f1",
        "icon": "",
        "description": "Red Cerebrus vs Blue Aegis adversarial evolution rounds and ELO tracking."
    },
    "dim_waf_policies": {
        "type": "DIMENSION",
        "category": "Security & Architecture",
        "color": "#8b5cf6",
        "icon": "",
        "description": "Edge WAF filter rules for Cloudflare, AWS WAF, and NGINX Lua."
    },
    "dim_sessions": {
        "type": "DIMENSION",
        "category": "Identity & Accounts",
        "color": "#10b981",
        "icon": "",
        "description": "Active JWT sessions, token hashes, expiration, and revocation flags."
    },
    "fact_capital_losses": {
        "type": "FACT",
        "category": "Financial Transactions",
        "color": "#0284c7",
        "icon": "",
        "description": "Financial loss quantification, unpatched leak vs patched capital saved."
    }
}

MODEL_RELATIONSHIPS = [
    {"id": "rel_01", "from_table": "dim_users", "from_col": "user_id", "to_table": "telemetry", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_02", "from_table": "dim_users", "from_col": "user_id", "to_table": "dim_wallets", "to_col": "user_id", "cardinality": "1:1"},
    {"id": "rel_03", "from_table": "dim_users", "from_col": "user_id", "to_table": "dim_devices", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_04", "from_table": "dim_users", "from_col": "user_id", "to_table": "fact_payment_checkout", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_05", "from_table": "dim_users", "from_col": "user_id", "to_table": "fact_audit_log", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_06", "from_table": "dim_users", "from_col": "user_id", "to_table": "fact_risk_evaluations", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_07", "from_table": "dim_users", "from_col": "user_id", "to_table": "dim_cards_pan", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_08", "from_table": "dim_users", "from_col": "user_id", "to_table": "dim_bank_accounts", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_09", "from_table": "dim_users", "from_col": "user_id", "to_table": "fact_fraud_alerts", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_10", "from_table": "dim_users", "from_col": "user_id", "to_table": "fact_concurrency_locks", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_11", "from_table": "dim_users", "from_col": "user_id", "to_table": "dim_sessions", "to_col": "user_id", "cardinality": "1:*"},
    {"id": "rel_12", "from_table": "dim_merchants", "from_col": "merchant_id", "to_table": "fact_payment_checkout", "to_col": "merchant_id", "cardinality": "1:*"},
    {"id": "rel_13", "from_table": "dim_vouchers", "from_col": "voucher_code", "to_table": "fact_payment_checkout", "to_col": "voucher_code", "cardinality": "1:*"},
    {"id": "rel_14", "from_table": "dim_api_endpoints", "from_col": "endpoint_path", "to_table": "telemetry", "to_col": "api_endpoint", "cardinality": "1:*"},
    {"id": "rel_15", "from_table": "dim_api_endpoints", "from_col": "endpoint_path", "to_table": "dim_waf_policies", "to_col": "endpoint_path", "cardinality": "1:*"},
    {"id": "rel_16", "from_table": "dim_ip_locations", "from_col": "client_ip", "to_table": "telemetry", "to_col": "client_ip", "cardinality": "1:*"},
    {"id": "rel_17", "from_table": "telemetry", "from_col": "event_id", "to_table": "fact_payment_checkout", "to_col": "event_id", "cardinality": "1:*"},
    {"id": "rel_18", "from_table": "telemetry", "from_col": "event_id", "to_table": "fact_risk_evaluations", "to_col": "event_id", "cardinality": "1:*"},
    {"id": "rel_19", "from_table": "telemetry", "from_col": "event_id", "to_table": "fact_fraud_alerts", "to_col": "event_id", "cardinality": "1:*"},
    {"id": "rel_20", "from_table": "telemetry", "from_col": "event_id", "to_table": "fact_concurrency_locks", "to_col": "event_id", "cardinality": "1:*"},
    {"id": "rel_21", "from_table": "telemetry", "from_col": "event_id", "to_table": "fact_capital_losses", "to_col": "event_id", "cardinality": "1:*"},
    {"id": "rel_22", "from_table": "dim_sessions", "from_col": "session_id", "to_table": "telemetry", "to_col": "session_id", "cardinality": "1:*"}
]

def get_database_model_graph() -> Dict[str, Any]:
    """Trả về mô hình quan hệ Schema đồ họa chuẩn Power BI Model View"""
    global ACTIVE_DB_PATH
    if not os.path.exists(ACTIVE_DB_PATH):
        return {"success": False, "error": "Database not found"}

    tables = get_db_tables()
    conn = get_connection()
    cur = conn.cursor()

    table_nodes = []
    # Grid positioning coordinates for Power BI Canvas layout
    POSITIONS = {
        "telemetry": {"x": 480, "y": 280},
        "dim_users": {"x": 100, "y": 80},
        "dim_wallets": {"x": 100, "y": 380},
        "dim_merchants": {"x": 100, "y": 620},
        "dim_vouchers": {"x": 100, "y": 860},
        "dim_devices": {"x": 480, "y": 60},
        "dim_ip_locations": {"x": 480, "y": 740},
        "dim_api_endpoints": {"x": 860, "y": 80},
        "fact_payment_checkout": {"x": 480, "y": 520},
        "fact_audit_log": {"x": 860, "y": 300},
        "fact_risk_evaluations": {"x": 860, "y": 520},
        "dim_cards_pan": {"x": 1240, "y": 80},
        "dim_bank_accounts": {"x": 1240, "y": 300},
        "fact_fraud_alerts": {"x": 860, "y": 740},
        "fact_concurrency_locks": {"x": 1240, "y": 520},
        "dim_compliance_rules": {"x": 1240, "y": 740},
        "fact_adversarial_rounds": {"x": 1620, "y": 80},
        "dim_waf_policies": {"x": 1620, "y": 300},
        "dim_sessions": {"x": 1620, "y": 520},
        "fact_capital_losses": {"x": 1620, "y": 740},
        "incident_memory": {"x": 2000, "y": 80},
        "policy_rules": {"x": 2000, "y": 380}
    }

    try:
        for idx, t in enumerate(tables):
            meta = TABLE_METADATA_REGISTRY.get(t, {
                "type": "TABLE",
                "category": "General",
                "color": "#0284c7",
                "icon": "",
                "description": f"Relational dataset table {t}"
            })

            cur.execute(f'PRAGMA table_info("{t}")')
            cols_info = cur.fetchall()
            columns = [
                {
                    "cid": c[0],
                    "name": c[1],
                    "type": c[2],
                    "pk": bool(c[5]),
                    "notnull": bool(c[3])
                }
                for c in cols_info
            ]

            cur.execute(f'SELECT COUNT(*) FROM "{t}"')
            row_count = cur.fetchone()[0]

            pos = POSITIONS.get(t, {"x": 100 + (idx % 4) * 380, "y": 80 + (idx // 4) * 240})

            table_nodes.append({
                "id": t,
                "name": t,
                "page_number": idx + 1,
                "type": meta["type"],
                "category": meta["category"],
                "color": meta["color"],
                "icon": meta["icon"],
                "description": meta["description"],
                "row_count": row_count,
                "columns": columns,
                "x": pos["x"],
                "y": pos["y"]
            })

        conn.close()

        # Filter relationships to only existing tables
        existing_table_names = set(tables)
        active_relationships = [
            r for r in MODEL_RELATIONSHIPS
            if r["from_table"] in existing_table_names and r["to_table"] in existing_table_names
        ]

        return {
            "success": True,
            "total_tables": len(table_nodes),
            "total_relationships": len(active_relationships),
            "architecture": "FinTech Star-Snowflake Data Model",
            "active_database": ACTIVE_DB_NAME,
            "tables": table_nodes,
            "relationships": active_relationships
        }
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e), "tables": [], "relationships": []}

def query_table_data(table_name: str = "telemetry", limit: int = 15, offset: int = 0, search: str = "") -> Dict[str, Any]:
    """Truy vấn dữ liệu chi tiết của từng bảng (Data View) hỗ trợ phân trang và tìm kiếm"""
    global ACTIVE_DB_PATH
    if not os.path.exists(ACTIVE_DB_PATH):
        return {"success": False, "error": "Database not found"}

    tables = get_db_tables()
    if not tables:
        return {"success": False, "error": "No tables found"}

    if table_name not in tables:
        table_name = "telemetry" if "telemetry" in tables else tables[0]

    conn = get_connection()
    cur = conn.cursor()

    try:
        # Schema columns
        cur.execute(f'PRAGMA table_info("{table_name}")')
        cols_info = cur.fetchall()
        columns = [
            {"name": c[1], "type": c[2], "pk": bool(c[5])}
            for c in cols_info
        ]
        col_names = [c["name"] for c in columns]

        # Determine sorting clause: Newest records at top
        if "epoch_ms" in col_names:
            order_clause = "ORDER BY epoch_ms DESC"
        elif "timestamp" in col_names:
            order_clause = "ORDER BY timestamp DESC"
        else:
            order_clause = "ORDER BY rowid DESC"

        # Count total rows
        if search and col_names:
            search_clause = " OR ".join([f'"{c}" LIKE ?' for c in col_names if c])
            count_sql = f'SELECT COUNT(*) FROM "{table_name}" WHERE {search_clause}'
            cur.execute(count_sql, [f"%{search}%"] * len(col_names))
            total_rows = cur.fetchone()[0]

            data_sql = f'SELECT * FROM "{table_name}" WHERE {search_clause} {order_clause} LIMIT ? OFFSET ?'
            params = [f"%{search}%"] * len(col_names) + [limit, offset]
            cur.execute(data_sql, params)
        else:
            cur.execute(f'SELECT COUNT(*) FROM "{table_name}"')
            total_rows = cur.fetchone()[0]

            data_sql = f'SELECT * FROM "{table_name}" {order_clause} LIMIT ? OFFSET ?'
            cur.execute(data_sql, (limit, offset))

        raw_rows = [dict(row) for row in cur.fetchall()]
        conn.close()

        total_pages = max(1, (total_rows + limit - 1) // limit)
        current_page = (offset // limit) + 1

        meta = TABLE_METADATA_REGISTRY.get(table_name, {
            "type": "TABLE",
            "category": "Dataset",
            "icon": "",
            "description": ""
        })

        return {
            "success": True,
            "table_name": table_name,
            "type": meta.get("type", "TABLE"),
            "category": meta.get("category", "Dataset"),
            "description": meta.get("description", ""),
            "total_rows": total_rows,
            "limit": limit,
            "offset": offset,
            "current_page": current_page,
            "total_pages": total_pages,
            "columns": columns,
            "rows": raw_rows
        }
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e), "table_name": table_name, "rows": [], "columns": []}
