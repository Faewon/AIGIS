"""
AIGIS Text-to-SQL (NL2SQL) Engine
Chuyển đổi câu hỏi ngôn ngữ tự nhiên (Tiếng Việt & Tiếng Anh) thành câu lệnh SQLite tối ưu.
Hỗ trợ cả LLM (Gemini, Groq, Llama, OpenAI) và Heuristic Semantic Parser offline.
"""

import re
import json
import time
from typing import Dict, Any, List
from .llm_engine import global_llm_engine
from .database import execute_raw_sql, get_table_schema, get_db_tables, get_active_db_info

SCHEMA_DOCUMENTATION = """
Bảng 'telemetry' chứa dữ liệu lưu lượng mạng & giao dịch FinTech (1,000,000 bản ghi):
- event_id (TEXT PRIMARY KEY): Mã định danh duy nhất của sự kiện (ví dụ: 'EVT-AIGIS-00000001')
- timestamp (TEXT): Chuỗi thời gian ISO microsecond (ví dụ: '2026-10-25 12:00:00.025000')
- epoch_ms (INTEGER): Timestamp thời gian thực dạng mili-giây
- user_id (TEXT): Định danh khách hàng (ví dụ: 'usr_customer_52883')
- session_id (TEXT): Phiên làm việc
- account_age_days (INTEGER): Tuổi đời tài khoản (ngày)
- kyc_level (TEXT): Cấp độ xác minh danh tính ('NONE', 'BASIC', 'VERIFIED_TIER_2')
- credit_score (INTEGER): Điểm tín dụng (300-850)
- client_ip (TEXT): Địa chỉ IP nguồn của client
- ip_country (TEXT): Quốc gia nguồn (VN, US, SG, JP, DE, CN, ...)
- ip_isp (TEXT): Tên nhà cung cấp mạng / ISP (VNPT, Viettel, FPT, NTT, Cloudflare Proxy, ...)
- is_datacenter_proxy (INTEGER): 1 nếu là IP từ máy chủ proxy/datacenter (nguy cơ cao), 0 nếu là IP dân cư
- user_agent (TEXT): Trình duyệt & thiết bị
- device_type (TEXT): 'mobile', 'desktop', 'bot_headless'
- os_platform (TEXT): 'iOS', 'Android', 'Windows', 'Linux'
- tls_ja3_hash (TEXT): Chữ ký vân tay giao vận TLS
- http_protocol (TEXT): 'HTTP/1.1', 'HTTP/2', 'HTTP/3'
- http_method (TEXT): 'GET', 'POST', 'PUT'
- api_endpoint (TEXT): Đường dẫn API ('/api/v1/voucher/claim', '/api/v1/cart/items', '/api/v1/catalog/product', '/api/v1/wallet/balance', ...)
- has_idempotency_key (INTEGER): 1 nếu có header Idempotency-Key chống gửi lặp, 0 nếu thiếu
- burst_stream_id (TEXT): Mã nhóm gói tin gửi đồng thời trong kỹ thuật đua lệnh ('BURST-TET-xxxx' hoặc 'NONE')
- burst_concurrency_rank (TEXT): Số thứ tự gói tin trong đợt burst (ví dụ: 'STREAM 01/30')
- network_rtt_ms (REAL): Độ trễ đường truyền mạng (mili-giây)
- server_latency_ms (REAL): Thời gian xử lý tại backend (mili-giây)
- transaction_amount_usd (REAL): Số tiền giao dịch hoặc giá trị voucher ($)
- status_code_unpatched (INTEGER): Mã HTTP trả về TRƯỚC KHI VÁ LỖI (200 là thành công/bị khai thác, 400 là từ chối)
- status_code_patched (INTEGER): Mã HTTP trả về SAU KHI VÁ LỖI (429 là bị chặn đứng bởi Aegis Idempotency Guard)
- is_attack (INTEGER): 1 nếu là sự kiện tấn công bảo mật logic, 0 nếu là lưu lượng khách hàng bình thường
- attack_type (TEXT): 'RACE_CONDITION_BURST', 'CREDENTIAL_STUFFING', 'SHADOW_API_PROBE', hoặc 'BENIGN'
"""

def heuristic_nl2sql(prompt: str) -> Dict[str, str]:
    """Bộ phân tích cú pháp ngữ nghĩa Heuristic offline (100% không cần internet hay API key)"""
    p = prompt.lower().strip()
    
    # 1. Top countries by theft / attacks
    if any(k in p for k in ["quốc gia", "country", "countries"]):
        if any(k in p for k in ["tiền", "thiệt hại", "usd", "stolen", "drained", "theft", "loss"]):
            return {
                "sql": "SELECT ip_country, COUNT(*) as attack_events, SUM(transaction_amount_usd) as total_stolen_usd FROM telemetry WHERE is_attack = 1 GROUP BY ip_country ORDER BY total_stolen_usd DESC LIMIT 10;",
                "explanation": "Grouped attack events by source country and aggregated total financial theft in USD, ordered by loss descending (Top 10)."
            }
        return {
            "sql": "SELECT ip_country, COUNT(*) as attack_count, ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM telemetry WHERE is_attack = 1), 2) as pct_of_attacks FROM telemetry WHERE is_attack = 1 GROUP BY ip_country ORDER BY attack_count DESC LIMIT 10;",
            "explanation": "Aggregated attack events by country along with overall percentage distribution across the dataset."
        }
        
    # 2. Datacenter Proxy / ISP
    if any(k in p for k in ["proxy", "datacenter", "isp", "nhà mạng", "ip"]):
        return {
            "sql": "SELECT ip_isp, ip_country, COUNT(*) as attack_count, SUM(transaction_amount_usd) as total_usd FROM telemetry WHERE is_attack = 1 AND is_datacenter_proxy = 1 GROUP BY ip_isp, ip_country ORDER BY attack_count DESC LIMIT 10;",
            "explanation": "Identified Datacenter Proxy ISPs with the highest concentration of malicious exploit requests."
        }
        
    # 3. Top exploited users / accounts
    if any(k in p for k in ["user", "users", "người dùng", "tài khoản", "account", "accounts"]):
        return {
            "sql": "SELECT user_id, COUNT(*) as exploit_attempts, SUM(transaction_amount_usd) as drained_usd, MIN(timestamp) as first_seen FROM telemetry WHERE is_attack = 1 GROUP BY user_id ORDER BY exploit_attempts DESC LIMIT 10;",
            "explanation": "Analyzed account abuse frequency by grouping attack events per user ID with cumulative financial impact."
        }
        
    # 4. Latency / RTT
    if any(k in p for k in ["độ trễ", "latency", "rtt", "thời gian phản hồi", "response time"]):
        return {
            "sql": "SELECT api_endpoint, is_attack, COUNT(*) as req_count, ROUND(AVG(network_rtt_ms), 2) as avg_rtt_ms, ROUND(MAX(network_rtt_ms), 2) as max_rtt_ms FROM telemetry GROUP BY api_endpoint, is_attack ORDER BY avg_rtt_ms DESC;",
            "explanation": "Compared average and peak network round-trip time (RTT) between benign traffic and attack requests across endpoints."
        }
        
    # 5. Attack Types breakdown
    if any(k in p for k in ["loại", "loại hình", "attack type", "phân loại", "chiến thuật", "types", "tactics"]):
        return {
            "sql": "SELECT attack_type, COUNT(*) as total_events, SUM(transaction_amount_usd) as total_usd, ROUND(AVG(network_rtt_ms), 2) as avg_rtt_ms FROM telemetry GROUP BY attack_type ORDER BY total_events DESC;",
            "explanation": "Categorized overall telemetry traffic across attack techniques and benign customer activity."
        }
        
    # 6. Race Condition / Concurrency / Burst stream
    if any(k in p for k in ["race condition", "đua lệnh", "burst", "concurrency", "đồng thời", "đa luồng", "simultaneous"]):
        return {
            "sql": "SELECT burst_stream_id, COUNT(*) as concurrency_packets, MIN(timestamp) as burst_start, ROUND(AVG(network_rtt_ms), 2) as avg_rtt FROM telemetry WHERE is_attack = 1 AND burst_stream_id != 'NONE' GROUP BY burst_stream_id ORDER BY concurrency_packets DESC LIMIT 10;",
            "explanation": "Traced multi-stream concurrency attacks (Race Condition bursts) with highest simultaneous packet arrival counts."
        }
        
    # 7. Financial exposure / Theft / Voucher drain
    if any(k in p for k in ["tiền", "thất thoát", "chiếm đoạt", "voucher", "drained", "theft", "stolen", "bảo vệ", "exposure"]):
        return {
            "sql": "SELECT api_endpoint, COUNT(*) as exploit_count, SUM(transaction_amount_usd) as unpatched_theft_usd FROM telemetry WHERE is_attack = 1 AND status_code_unpatched = 200 GROUP BY api_endpoint ORDER BY unpatched_theft_usd DESC;",
            "explanation": "Aggregated vulnerable endpoints successfully exploited for balance/voucher drainage prior to patch deployment."
        }
        
    # 8. Benign vs Attack ratio
    if any(k in p for k in ["tỷ lệ", "ratio", "benign", "bình thường", "tổng", "percentage", "breakdown"]):
        return {
            "sql": "SELECT CASE WHEN is_attack = 1 THEN 'ATTACK' ELSE 'BENIGN' END as traffic_type, COUNT(*) as total_records, ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM telemetry), 2) as percentage, ROUND(SUM(transaction_amount_usd), 2) as total_volume_usd FROM telemetry GROUP BY is_attack;",
            "explanation": "Calculated distribution ratio and volume comparison between legitimate customer traffic and adversarial attacks."
        }

    # Default general query
    return {
        "sql": "SELECT event_id, timestamp, user_id, ip_country, ip_isp, api_endpoint, transaction_amount_usd, attack_type FROM telemetry WHERE is_attack = 1 ORDER BY epoch_ms DESC LIMIT 15;",
        "explanation": "Retrieved the 15 most recent adversarial attack events with client IP origin, account ID, and transaction values."
    }

def extract_json_or_sql(raw_response: str) -> Dict[str, str]:
    """Trích xuất an toàn JSON hoặc câu lệnh SQL từ phản hồi của LLM"""
    text = raw_response.strip()
    
    # 1. Thử parse trực tiếp JSON
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "sql" in data:
            return {"sql": data["sql"].strip(), "explanation": data.get("explanation", "").strip()}
    except Exception:
        pass

    # 2. Thử trích xuất khối ```json ... ``` hoặc { ... }
    json_match = re.search(r"\{[\s\S]*?\"sql\"[\s\S]*?\}", text)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            if "sql" in data:
                return {"sql": data["sql"].strip(), "explanation": data.get("explanation", "").strip()}
        except Exception:
            pass

    # 3. Thử trích xuất khối ```sql ... ```
    sql_match = re.search(r"```(?:sql)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if sql_match:
        extracted_sql = sql_match.group(1).strip()
        return {"sql": extracted_sql, "explanation": "Generated from LLM code block."}

    # 4. Nếu bắt đầu bằng SELECT hoặc WITH
    if text.upper().startswith("SELECT") or text.upper().startswith("WITH"):
        clean_sql = text.split(";")[0].strip() + ";"
        return {"sql": clean_sql, "explanation": "Direct SQL generated by LLM."}

    return {"sql": "", "explanation": ""}

async def generate_sql_from_prompt(natural_language_prompt: str, execute: bool = True) -> Dict[str, Any]:
    """
    Sinh câu lệnh SQL chuẩn SQLite từ câu hỏi tự nhiên.
    Nếu có LLM kết nối (Gemini, Groq, OpenAI), sử dụng mô hình AI.
    Nếu không có hoặc lỗi, tự động sử dụng Heuristic Semantic Engine thông minh.
    """
    nl_query = natural_language_prompt.strip()
    if not nl_query:
        return {"success": False, "error": "Query cannot be empty"}

    t0 = time.time()
    llm_status = global_llm_engine.get_status()
    sql_query = ""
    explanation = ""
    model_name = "Heuristic NL2SQL Engine"
    llm_error = None
    llm_called = False
    llm_success = False

    # Lấy thông tin bảng hiện hành để hỗ trợ cả database/csv tùy chỉnh
    db_info = get_active_db_info()
    active_tables = db_info.get("tables", [])
    active_table = "telemetry" if "telemetry" in active_tables else (active_tables[0] if active_tables else "telemetry")

    # 1. Thử sinh qua LLM nếu có cấu hình
    if llm_status["mode"] == "API_CONNECTED":
        llm_called = True
        system_prompt = f"""You are an expert Text-to-SQL AI for SQLite 3.
The active database is '{db_info.get('active_db_name', 'aigis_telemetry.db')}'.
Target Table: '{active_table}'.
Schema details:
{SCHEMA_DOCUMENTATION}

CRITICAL RULES:
1. ONLY generate safe read-only SELECT / WITH queries.
2. Return a strict JSON object with:
   "sql": "<executable SQLite query string>",
   "explanation": "<brief 1-sentence technical explanation of what is calculated>"
3. Do not include extra conversational text outside the JSON.
"""
        user_prompt = f"Convert this question into a SQLite SQL query for table '{active_table}': '{nl_query}'"

        try:
            raw_response = await global_llm_engine.call_llm(system_prompt, user_prompt, temperature=0.1)
            if raw_response:
                parsed = extract_json_or_sql(raw_response)
                sql_query = parsed.get("sql", "").strip()
                explanation = parsed.get("explanation", "").strip()
                if sql_query:
                    model_name = f"{llm_status['provider'].upper()}: {llm_status['model_name']}"
                    llm_success = True
            
            if not sql_query and global_llm_engine.last_call_error:
                llm_error = global_llm_engine.last_call_error
        except Exception as e:
            llm_error = str(e)

    # 2. Fallback sang Heuristic Engine nếu LLM không trả về hoặc lỗi
    if not sql_query:
        heuristic_res = heuristic_nl2sql(nl_query)
        sql_query = heuristic_res["sql"]
        explanation = heuristic_res["explanation"]
        model_name = "Autonomous Heuristic NL2SQL Engine"

    # 3. Thực thi truy vấn nếu được yêu cầu
    query_result = {}
    if execute:
        query_result = execute_raw_sql(sql_query, max_limit=50)

    elapsed = time.time() - t0

    return {
        "success": True,
        "nl_query": nl_query,
        "sql_query": sql_query,
        "explanation": explanation,
        "model_used": model_name,
        "llm_called": llm_called,
        "llm_success": llm_success,
        "llm_error": llm_error,
        "generation_time_ms": round(elapsed * 1000, 2),
        "execution": query_result if execute else None
    }
