"""
AIGIS Real-Time Streaming Telemetry Engine (Production-Grade)
- Continuous Synthetic Telemetry Ingestion (10 - 50 tx/s)
- Realistic Traffic Composition: 99% Benign, 1% Logic Exploits (TOCTOU, BOLA, Tampering, State Bypass)
- FIFO Rolling Buffer: Maintains fixed 1,000,000 active records in SQLite 3 WAL
- Thread-safe memory buffer & throttling for sub-second frontend live polling
"""

import os
import sys
import time
import uuid
import random
import sqlite3
import threading
from collections import deque
from typing import Dict, Any, List, Optional

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
DB_PATH = os.path.join(DATASETS_DIR, "aigis_telemetry.db")

TARGET_ROW_LIMIT = 1_000_000

# Reusable sample pools for realistic generation
COUNTRIES = ["VN", "SG", "US", "JP", "KR", "DE", "GB", "TH", "MY", "ID"]
ISPS = ["Viettel Telecom", "VNPT", "FPT Telecom", "Singtel", "AWS EC2 Cloud", "Cloudflare", "DigitalOcean", "GCP Compute"]
DEVICES = ["mobile_ios", "mobile_android", "desktop_chrome", "desktop_firefox", "desktop_safari"]
PLATFORMS = ["iOS 17.4", "Android 14", "Windows 11", "macOS Sonoma", "Linux Ubuntu"]
ENDPOINTS = [
    "/api/v1/payment/checkout",
    "/api/v1/wallet/transfer",
    "/api/v1/voucher/claim",
    "/api/v1/card/verify",
    "/api/v1/account/withdraw"
]
METHODS = ["POST", "POST", "POST", "GET", "PUT"]
ATTACK_TYPES = [
    "TOCTOU_RACE_CONDITION",
    "BOLA_IDOR",
    "NEGATIVE_AMOUNT_TAMPERING",
    "STEP_SKIPPING_STATE_BYPASS"
]


class LiveStreamEngine:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.is_running = False
        self.is_paused = False
        self.tps = 10  # Transactions per second
        self.attack_ratio = 0.01  # 1% attack, 99% benign
        
        # Thread control
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        # In-memory recent events buffer (for sub-second UI updates)
        self.recent_events = deque(maxlen=50)
        
        # Cumulative telemetry metrics
        self.metrics = {
            "total_streamed": 0,
            "benign_count": 0,
            "attack_count": 0,
            "stolen_prevented_usd": 0.0,
            "start_time": time.time(),
            "last_batch_time": time.time(),
            "current_tps": 0.0,
            "rolling_deletions": 0
        }

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -64000")
        return conn

    def _generate_event(self) -> Dict[str, Any]:
        is_attack = 1 if (random.random() < self.attack_ratio) else 0
        now_ms = int(time.time() * 1000)
        event_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now_ms / 1000.0)) + f".{now_ms % 1000:03d}"
        
        user_num = random.randint(1, 1413)
        user_id = f"USR_VN_{user_num:05d}"
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        event_id = f"evt_{uuid.uuid4().hex[:14]}"
        
        country = random.choice(COUNTRIES)
        isp = random.choice(ISPS)
        device = random.choice(DEVICES)
        platform = random.choice(PLATFORMS)
        endpoint = random.choice(ENDPOINTS)
        method = "POST"
        
        if is_attack:
            attack_type = random.choice(ATTACK_TYPES)
            is_proxy = 1 if "Cloud" in isp or "DigitalOcean" in isp or random.random() < 0.6 else 0
            
            if attack_type == "TOCTOU_RACE_CONDITION":
                amount = round(random.uniform(1500.0, 10000.0), 2)
                burst_id = f"burst_toctou_{uuid.uuid4().hex[:8]}"
                burst_rank = f"{random.randint(1, 15)}/15"
                status_unpatched = 200
                status_patched = 429
                net_rtt = round(random.uniform(4.0, 18.0), 2)
                srv_lat = round(random.uniform(1.0, 2.5), 2)
            elif attack_type == "BOLA_IDOR":
                amount = round(random.uniform(800.0, 5000.0), 2)
                burst_id = ""
                burst_rank = ""
                status_unpatched = 200
                status_patched = 403
                net_rtt = round(random.uniform(25.0, 90.0), 2)
                srv_lat = round(random.uniform(1.2, 3.0), 2)
            elif attack_type == "NEGATIVE_AMOUNT_TAMPERING":
                amount = -round(random.uniform(500.0, 7500.0), 2)
                burst_id = ""
                burst_rank = ""
                status_unpatched = 200
                status_patched = 422
                net_rtt = round(random.uniform(30.0, 80.0), 2)
                srv_lat = round(random.uniform(0.8, 2.0), 2)
            else: # STEP_SKIPPING_STATE_BYPASS
                amount = round(random.uniform(1000.0, 6000.0), 2)
                burst_id = ""
                burst_rank = ""
                status_unpatched = 200
                status_patched = 400
                net_rtt = round(random.uniform(20.0, 60.0), 2)
                srv_lat = round(random.uniform(1.0, 2.2), 2)
        else:
            attack_type = "BENIGN"
            is_proxy = 0
            amount = round(random.uniform(5.0, 450.0), 2)
            burst_id = ""
            burst_rank = ""
            status_unpatched = 200
            status_patched = 200
            net_rtt = round(random.uniform(20.0, 75.0), 2)
            srv_lat = round(random.uniform(1.5, 4.5), 2)

        return {
            "event_id": event_id,
            "timestamp": event_time_str,
            "epoch_ms": now_ms,
            "user_id": user_id,
            "session_id": session_id,
            "account_age_days": random.randint(15, 1200),
            "kyc_level": random.choice(["TIER_1_BASIC", "TIER_2_VERIFIED", "TIER_3_ENTERPRISE"]),
            "credit_score": random.randint(580, 850),
            "client_ip": f"{random.randint(14, 210)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "ip_country": country,
            "ip_isp": isp,
            "is_datacenter_proxy": is_proxy,
            "user_agent": f"Mozilla/5.0 ({platform}) AppleWebKit/537.36",
            "device_type": device,
            "os_platform": platform,
            "tls_ja3_hash": f"ja3_{uuid.uuid4().hex[:10]}",
            "http_protocol": "HTTP/2",
            "http_method": method,
            "api_endpoint": endpoint,
            "has_idempotency_key": 1 if not is_attack else random.choice([0, 1]),
            "burst_stream_id": burst_id,
            "burst_concurrency_rank": burst_rank,
            "network_rtt_ms": net_rtt,
            "server_latency_ms": srv_lat,
            "transaction_amount_usd": amount,
            "status_code_unpatched": status_unpatched,
            "status_code_patched": status_patched,
            "is_attack": is_attack,
            "attack_type": attack_type
        }

    def _flush_batch(self, events: List[Dict[str, Any]]):
        if not events:
            return
        
        batch_len = len(events)
        conn = self._get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("BEGIN IMMEDIATE TRANSACTION")
            
            # 1. Insert new generated events
            insert_sql = """
                INSERT INTO telemetry (
                    event_id, timestamp, epoch_ms, user_id, session_id, account_age_days,
                    kyc_level, credit_score, client_ip, ip_country, ip_isp, is_datacenter_proxy,
                    user_agent, device_type, os_platform, tls_ja3_hash, http_protocol, http_method,
                    api_endpoint, has_idempotency_key, burst_stream_id, burst_concurrency_rank,
                    network_rtt_ms, server_latency_ms, transaction_amount_usd, status_code_unpatched,
                    status_code_patched, is_attack, attack_type
                ) VALUES (
                    :event_id, :timestamp, :epoch_ms, :user_id, :session_id, :account_age_days,
                    :kyc_level, :credit_score, :client_ip, :ip_country, :ip_isp, :is_datacenter_proxy,
                    :user_agent, :device_type, :os_platform, :tls_ja3_hash, :http_protocol, :http_method,
                    :api_endpoint, :has_idempotency_key, :burst_stream_id, :burst_concurrency_rank,
                    :network_rtt_ms, :server_latency_ms, :transaction_amount_usd, :status_code_unpatched,
                    :status_code_patched, :is_attack, :attack_type
                )
            """
            cur.executemany(insert_sql, events)
            
            # 2. FIFO Rolling Deletion: Keep exact 1,000,000 rows
            # Delete the oldest batch_len rows
            cur.execute("DELETE FROM telemetry WHERE rowid IN (SELECT rowid FROM telemetry ORDER BY epoch_ms ASC LIMIT ?)", (batch_len,))
            
            conn.commit()
            
            # 3. Update thread-safe in-memory metrics
            with self._lock:
                for ev in events:
                    self.recent_events.appendleft(ev)
                    self.metrics["total_streamed"] += 1
                    if ev["is_attack"] == 1:
                        self.metrics["attack_count"] += 1
                        prevented = abs(ev["transaction_amount_usd"])
                        self.metrics["stolen_prevented_usd"] += prevented
                    else:
                        self.metrics["benign_count"] += 1
                
                self.metrics["rolling_deletions"] += batch_len
                self.metrics["last_batch_time"] = time.time()
                
        except Exception as e:
            conn.rollback()
            print(f"[LiveStreamEngine] Error flushing batch: {e}", file=sys.stderr)
        finally:
            conn.close()

    def _worker_loop(self):
        """Worker thread: Batches events every 2.0 seconds to minimize SQLite write-locks"""
        print(f"[LiveStreamEngine] Background stream loop started at {self.tps} TPS (Ratio: 99% Benign, 1% Attack, 2s Batch)")
        batch = []
        last_flush = time.time()
        
        while not self._stop_event.is_set():
            if self.is_paused:
                time.sleep(0.2)
                continue
            
            # Generate event
            ev = self._generate_event()
            batch.append(ev)
            
            now = time.time()
            # Flush when 2.0s elapsed or batch reaches 2 * TPS
            if len(batch) >= (2 * self.tps) or (now - last_flush) >= 2.0:
                self._flush_batch(batch)
                batch = []
                last_flush = now
            
            # Sleep to pace transaction rate
            time.sleep(1.0 / max(1, self.tps))
            
        # Final flush before exit
        if batch:
            self._flush_batch(batch)
        print("[LiveStreamEngine] Background stream loop gracefully stopped.")

    def start(self, tps: int = 10, attack_ratio: float = 0.01):
        if self.is_running:
            return {"status": "already_running", "tps": self.tps}
        
        self.tps = tps
        self.attack_ratio = attack_ratio
        self.is_running = True
        self.is_paused = False
        self._stop_event.clear()
        
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()
        
        return {
            "status": "started",
            "tps": self.tps,
            "attack_ratio": self.attack_ratio,
            "rolling_limit": TARGET_ROW_LIMIT
        }

    def pause(self):
        self.is_paused = True
        return {"status": "paused", "is_paused": True}

    def resume(self):
        self.is_paused = False
        return {"status": "resumed", "is_paused": False}

    def stop(self):
        if not self.is_running:
            return {"status": "not_running"}
        
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        self.is_running = False
        self.is_paused = False
        return {"status": "stopped"}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = time.time() - self.metrics["start_time"]
            calc_tps = round(self.metrics["total_streamed"] / max(1.0, elapsed), 1) if self.is_running and not self.is_paused else 0.0
            
            return {
                "is_running": self.is_running,
                "is_paused": self.is_paused,
                "configured_tps": self.tps,
                "current_tps": calc_tps,
                "attack_ratio": self.attack_ratio,
                "target_row_limit": TARGET_ROW_LIMIT,
                "total_streamed": self.metrics["total_streamed"],
                "benign_count": self.metrics["benign_count"],
                "attack_count": self.metrics["attack_count"],
                "stolen_prevented_usd": round(self.metrics["stolen_prevented_usd"], 2),
                "rolling_deletions": self.metrics["rolling_deletions"],
                "recent_buffer_size": len(self.recent_events)
            }

    def get_events(self, limit: int = 15) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent_events)[:limit]


# Global engine singleton
stream_engine = LiveStreamEngine()
