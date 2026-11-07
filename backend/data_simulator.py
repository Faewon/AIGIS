import os
import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, Any, Generator

DATASETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datasets")
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(DATASETS_DIR, "aigis_simulated_traffic_1m.csv")
META_PATH = os.path.join(DATASETS_DIR, "aigis_simulated_traffic_1m_meta.json")

# ==============================================================================
# REALISTIC SECURITY & FINTECH TELEMETRY POOLS
# ==============================================================================

LEGIT_ISPS = [
    ("VNPT Corporation", "VN", False),
    ("Viettel Group", "VN", False),
    ("FPT Telecom", "VN", False),
    ("MobiFone Network", "VN", False),
    ("Singtel Broadband", "SG", False),
    ("Comcast Cable", "US", False),
    ("AT&T Internet", "US", False),
    ("NTT Communications", "JP", False)
]

DATACENTER_ISPS = [
    ("Amazon Web Services (us-east-1)", "US", True),
    ("DigitalOcean Cloud (sgp1)", "SG", True),
    ("Hetzner Online GmbH", "DE", True),
    ("OVH SAS Datacenter", "FR", True),
    ("Linode / Akamai", "US", True),
    ("Choopa / Vultr Cloud", "JP", True)
]

USER_AGENTS_LEGIT = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "desktop", "Windows 11", "b323893a743a60a7e6b5277873eb64f2", "HTTP/2.0"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15", "desktop", "macOS 14", "2d23b2fc037c864b41b3abc4023a8817", "HTTP/2.0"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", "mobile", "iOS 17.4", "e7d705a3286e19ea42f587b344ee6865", "HTTP/3"),
    ("Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36", "mobile", "Android 14", "9e1c2e6488d7be08fb4a1a5b822bb2b9", "HTTP/2.0")
]

USER_AGENTS_BOT = [
    ("python-httpx/0.27.0 (AsyncEngine; Cerebrus-Burst)", "bot_worker", "Linux x86_64", "51c64c77e60f3980eea90869b68c58a8", "HTTP/1.1"),
    ("Go-http-client/2.0 (ConcurrencyPool/15-Threads)", "bot_worker", "Linux x86_64", "2a9f1f0a827419842bfcd93a65c2b047", "HTTP/1.1"),
    ("curl/8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0", "bot_worker", "Linux x86_64", "0c7e2b1e194ea746409890a8a65f904e", "HTTP/1.1"),
    ("CerebrusAdversarialAgent/1.0 (Automated Wargame Exploit Engine)", "bot_worker", "Linux x86_64", "673467b7e1194ea746409890a8a65f90", "HTTP/1.1")
]

ENDPOINTS = [
    ("/api/v1/voucher/claim", "POST"),
    ("/api/v1/checkout/confirm", "POST"),
    ("/api/v1/catalog/product", "GET"),
    ("/api/v1/cart/items", "GET"),
    ("/api/v1/wallet/balance", "GET")
]

KYC_LEVELS = ["UNVERIFIED", "TIER_1_BASIC", "TIER_2_VERIFIED", "VIP_ENTERPRISE"]

# ==============================================================================
# GENERATOR ENGINE FOR 1,000,000 ROWS
# ==============================================================================

def generate_million_row_dataset(
    total_rows: int = 1_000_000,
    attack_ratio: float = 0.035,
    burst_streams_size: int = 15,
    chunk_size: int = 50_000,
    progress_callback = None
) -> Dict[str, Any]:
    """
    Tạo ra 1,000,000 dòng dữ liệu mô phỏng an ninh mạng & giao dịch tài chính cực kỳ chi tiết.
    Sử dụng cơ chế ghi đệm theo khối (Streaming Chunks) để tiết kiệm RAM và tốc độ cao (< 10s).
    """
    os.makedirs(DATASETS_DIR, exist_ok=True)
    t_start = time.time()

    headers = [
        "event_id", "timestamp", "epoch_ms", "user_id", "session_id",
        "account_age_days", "kyc_level", "credit_score", "client_ip", "ip_country",
        "ip_isp", "is_datacenter_proxy", "user_agent", "device_type", "os_platform",
        "tls_ja3_hash", "http_protocol", "http_method", "api_endpoint", "has_idempotency_key",
        "burst_stream_id", "burst_concurrency_rank", "network_rtt_ms", "server_latency_ms",
        "transaction_amount_usd", "status_code_unpatched", "status_code_patched", "is_attack", "attack_type"
    ]

    base_time = datetime(2026, 10, 25, 12, 0, 0)
    current_time_offset_ms = 0

    stats = {
        "total_rows": total_rows,
        "benign_rows": 0,
        "attack_rows": 0,
        "attacks_by_type": {
            "RACE_CONDITION_BURST": 0,
            "CREDENTIAL_STUFFING": 0,
            "SHADOW_API_PROBE": 0
        },
        "unpatched_total_drained_usd": 0.0,
        "patched_total_saved_usd": 0.0,
        "csv_path": os.path.relpath(CSV_PATH, PROJECT_ROOT),
        "meta_path": os.path.relpath(META_PATH, PROJECT_ROOT),
        # attack_ratio is the probability that a *batch* is an attack burst; each burst
        # writes several rows, so the attack share of rows is much higher than attack_ratio.
        "attack_ratio_param_per_batch": attack_ratio
    }

    sample_preview = []
    total_written = 0
    burst_counter = 0

    with open(CSV_PATH, "w", encoding="utf-8", newline="") as f:
        f.write(",".join(headers) + "\n")

        chunk_lines = []

        while total_written < total_rows:
            # Xác định đây là lượt user bình thường hay đợt tấn công bùng nổ
            is_attack_batch = random.random() < attack_ratio

            if is_attack_batch and (total_written + burst_streams_size <= total_rows):
                # ==============================================================
                # NHÓM TẤN CÔNG ĐỐI KHÁNG (ADVERSARIAL ATTACK CLUSTER)
                # ==============================================================
                attack_type = random.choices(
                    ["RACE_CONDITION_BURST", "CREDENTIAL_STUFFING", "SHADOW_API_PROBE"],
                    weights=[0.70, 0.20, 0.10],
                    k=1
                )[0]

                burst_id = f"BURST-20261025-{burst_counter:06d}"
                burst_counter += 1
                attacker_id = f"usr_botnet_cerebrus_{random.randint(1, 999):03d}"
                attacker_session = f"sess_bot_{random.randint(100000, 999999)}"
                isp_info = random.choice(DATACENTER_ISPS)
                bot_ua = random.choice(USER_AGENTS_BOT)
                client_ip = f"{random.randint(13, 203)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

                # Thời điểm bắt đầu đợt burst (cùng 1 mili-giây)
                burst_epoch_ms = int(base_time.timestamp() * 1000) + current_time_offset_ms
                burst_timestamp_str = (base_time + timedelta(milliseconds=current_time_offset_ms)).strftime("%Y-%m-%d %H:%M:%S.%f")

                current_burst_size = burst_streams_size if attack_type == "RACE_CONDITION_BURST" else random.randint(3, 8)

                for rank in range(1, current_burst_size + 1):
                    event_id = f"EVT-AIGIS-{total_written + 1:08d}"
                    endpoint = "/api/v1/voucher/claim" if attack_type == "RACE_CONDITION_BURST" else ("/api/v1/auth/login" if attack_type == "CREDENTIAL_STUFFING" else "/api/v1/internal/grant_credit")
                    method = "POST"
                    has_idempotency = 0
                    amount = 500.0 if endpoint == "/api/v1/voucher/claim" else 0.0

                    # Cơ chế Unpatched vs Patched
                    if attack_type == "RACE_CONDITION_BURST":
                        # Chưa vá: cả 15 requests đều 200 OK (rút trộm)
                        status_unpatched = 200
                        # Đã vá: chỉ request đầu tiên 200, các request sau bị 429
                        status_patched = 200 if rank == 1 else 429
                        stats["unpatched_total_drained_usd"] += amount
                        if rank > 1:
                            stats["patched_total_saved_usd"] += amount
                    elif attack_type == "CREDENTIAL_STUFFING":
                        status_unpatched = 401
                        status_patched = 429  # Aegis IP Rate limiter chặn
                    else:
                        status_unpatched = 403
                        status_patched = 404

                    row = [
                        event_id,
                        burst_timestamp_str,
                        str(burst_epoch_ms),
                        attacker_id,
                        attacker_session,
                        str(random.randint(0, 2)),          # account age 0-2 ngày
                        "UNVERIFIED",
                        str(random.randint(310, 480)),      # credit score thấp
                        client_ip,
                        isp_info[1],                        # country
                        f'"{isp_info[0]}"',
                        "1",                                # is_datacenter_proxy
                        f'"{bot_ua[0]}"',                   # user_agent
                        bot_ua[1],                          # device_type
                        bot_ua[2],                          # os_platform
                        bot_ua[3],                          # tls_ja3
                        bot_ua[4],                          # http_protocol
                        method,
                        endpoint,
                        str(has_idempotency),
                        burst_id,
                        f"{rank}/{current_burst_size}",
                        f"{random.uniform(3.5, 9.8):.2f}",  # bot RTT cực nhanh
                        f"{random.uniform(18.0, 24.0):.2f}",# server execution latency
                        f"{amount:.2f}",
                        str(status_unpatched),
                        str(status_patched),
                        "1",
                        attack_type
                    ]

                    chunk_lines.append(",".join(row) + "\n")
                    total_written += 1
                    stats["attack_rows"] += 1
                    stats["attacks_by_type"][attack_type] += 1

                    if len(sample_preview) < 25 and attack_type == "RACE_CONDITION_BURST":
                        sample_preview.append(dict(zip(headers, [x.strip('"') for x in row])))

                    if total_written >= total_rows:
                        break

                current_time_offset_ms += random.randint(150, 450)

            else:
                # ==============================================================
                # NGƯỜI DÙNG BÌNH THƯỜNG (LEGITIMATE CUSTOMERS - BENIGN)
                # ==============================================================
                event_id = f"EVT-AIGIS-{total_written + 1:08d}"
                legit_id = f"usr_customer_{random.randint(1, 80000):05d}"
                session_id = f"sess_live_{random.randint(1000000, 9999999)}"
                isp_info = random.choice(LEGIT_ISPS)
                legit_ua = random.choice(USER_AGENTS_LEGIT)
                client_ip = f"{random.choice([14, 27, 42, 113, 171])}.{random.randint(128, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

                current_time_offset_ms += random.randint(2, 25)
                row_epoch_ms = int(base_time.timestamp() * 1000) + current_time_offset_ms
                row_timestamp_str = (base_time + timedelta(milliseconds=current_time_offset_ms)).strftime("%Y-%m-%d %H:%M:%S.%f")

                endpoint_info = random.choice(ENDPOINTS)
                endpoint = endpoint_info[0]
                method = endpoint_info[1]
                has_idempotency = 1 if endpoint == "/api/v1/voucher/claim" else 0
                amount = 500.0 if endpoint == "/api/v1/voucher/claim" else (random.uniform(15.0, 350.0) if endpoint == "/api/v1/checkout/confirm" else 0.0)

                status_code = 200

                row = [
                    event_id,
                    row_timestamp_str,
                    str(row_epoch_ms),
                    legit_id,
                    session_id,
                    str(random.randint(30, 1800)),      # account age 1-5 năm
                    random.choice(KYC_LEVELS),
                    str(random.randint(620, 840)),      # credit score cao
                    client_ip,
                    isp_info[1],
                    f'"{isp_info[0]}"',
                    "0",                                # residential
                    f'"{legit_ua[0]}"',
                    legit_ua[1],
                    legit_ua[2],
                    legit_ua[3],
                    legit_ua[4],
                    method,
                    endpoint,
                    str(has_idempotency),
                    "NONE",
                    "1/1",
                    f"{random.uniform(18.0, 48.0):.2f}",# network RTT
                    f"{random.uniform(12.0, 28.0):.2f}",# server latency
                    f"{amount:.2f}",
                    str(status_code),
                    str(status_code),
                    "0",
                    "BENIGN"
                ]

                chunk_lines.append(",".join(row) + "\n")
                total_written += 1
                stats["benign_rows"] += 1

                if len(sample_preview) < 15:
                    sample_preview.append(dict(zip(headers, [x.strip('"') for x in row])))

            # Ghi ra đĩa mỗi chunk_size dòng để tối ưu RAM
            if len(chunk_lines) >= chunk_size:
                f.writelines(chunk_lines)
                chunk_lines.clear()
                if progress_callback:
                    progress_callback(total_written, total_rows)

        # Ghi nốt phần dư còn lại
        if chunk_lines:
            f.writelines(chunk_lines)
            chunk_lines.clear()

    t_elapsed = time.time() - t_start
    file_size_mb = os.path.getsize(CSV_PATH) / (1024 * 1024)

    stats["generation_time_sec"] = round(t_elapsed, 2)
    stats["file_size_mb"] = round(file_size_mb, 2)
    stats["sample_preview"] = sample_preview
    stats["columns_count"] = len(headers)
    stats["columns"] = headers
    stats["attack_row_pct"] = round(stats["attack_rows"] / max(1, total_written) * 100, 2)

    with open(META_PATH, "w", encoding="utf-8") as meta_f:
        json.dump(stats, meta_f, indent=2, ensure_ascii=False)

    return stats

def get_dataset_metadata() -> Dict[str, Any]:
    """Đọc thông tin tóm tắt của dataset đã sinh"""
    if os.path.exists(META_PATH):
        try:
            with open(META_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "total_rows": 0,
        "status": "NOT_GENERATED",
        "csv_path": CSV_PATH,
        "sample_preview": []
    }
