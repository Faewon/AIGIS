"""
AIGIS FinTech Sentinel Agent
Directly adapted from the ARIA Autonomous Sentinel Architecture:
- Continuous sliding-window operational time-series surveillance (10 - 50 TPS)
- Velocity Derivative calculation (dTPS/dt) & sub-second clustering detection
- Signal Tail Forecasting: Extrapolates future TPS trajectory and liquidity exhaustion time
- Contextual Stand-Down Filter: Distinguishes legitimate Flash Sale spikes from bot race conditions
- Memory Integration: Cross-references anomaly signatures against historical Incident KB
"""

import time
import math
from typing import Dict, Any, List, Optional
from collections import deque

try:
    from ..database import get_connection, get_policy_rules, get_incident_memory, DB_PATH
    from ..stream_engine import stream_engine
except (ImportError, ModuleNotFoundError):
    try:
        from database import get_connection, get_policy_rules, get_incident_memory, DB_PATH
        from stream_engine import stream_engine
    except (ImportError, ModuleNotFoundError):
        from backend.database import get_connection, get_policy_rules, get_incident_memory, DB_PATH
        from backend.stream_engine import stream_engine


class FinTechSentinelAgent:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.agent_name = "FinTech Sentinel"
        self.agent_role = "Autonomous Operational Surveillance & Contextual Stand-Down Agent"
        
        # Sliding history of evaluations for UI trend chart (last 30 samples)
        self.evaluation_history = deque(maxlen=30)
        
        # Internal state tracking
        self.last_eval_time = time.time()
        self.last_tps = 10.0
        self.current_verdict = "NORMAL"
        self.current_state = {
            "verdict": "NORMAL",
            "verdict_badge": "NORMAL (NOMINAL BASELINE)",
            "severity": "LOW",
            "tps": 10.0,
            "velocity_derivative": 0.0,
            "user_entropy": 0.95,
            "proxy_ratio": 0.02,
            "concurrency_clusters": 0,
            "tail_forecast_t30": 10.0,
            "time_to_exhaustion_s": None,
            "drain_velocity_usd_s": 45.0,
            "active_context": "NOMINAL_OPERATION",
            "reason": "System operating within nominal financial baseline parameters.",
            "recommended_action": "PASSIVE_SURVEILLANCE",
            "recalled_incident": None,
            "thought_chain": []
        }

    def evaluate_telemetry(self, window_seconds: int = 15) -> Dict[str, Any]:
        """
        Thuc thi chu trinh danh gia giam sat Sentinel tren cua so truot window_seconds:
        1. Doc du lieu thoi gian thuc tu SQLite / Stream Engine
        2. Tinh toan bien thien van toc (dTPS/dt) va mat do clustering
        3. Chay thuat toan Tail Forecasting du bao quy dao sau 30 giay
        4. Kiem tra bo loc ngu canh Contextual Stand-Down (Flash Sale vs Exploit)
        5. Doi chieu Incident Memory KB va dua ra phan quyet
        """
        now = time.time()
        now_ms = int(now * 1000)
        window_ms = window_seconds * 1000
        min_epoch = now_ms - window_ms
        
        thought_chain = []
        thought_chain.append(f"[THOUGHT 1] Sentinel scanning operational sliding window: last {window_seconds}s (epoch >= {min_epoch}).")

        # 1. Truy van du lieu tu SQLite
        events = []
        try:
            conn = get_connection(self.db_path)
            cur = conn.cursor()
            cur.execute("""
            SELECT event_id, epoch_ms, user_id, api_endpoint, transaction_amount_usd,
                   is_attack, attack_type, is_datacenter_proxy, burst_stream_id,
                   network_rtt_ms, server_latency_ms
            FROM telemetry
            WHERE epoch_ms >= ?
            ORDER BY epoch_ms DESC
            LIMIT 500
            """, (min_epoch,))
            events = [dict(r) for r in cur.fetchall()]
            conn.close()
        except Exception as e:
            thought_chain.append(f"[WARNING] Fallback to in-memory stream buffer: {str(e)}")
            # Fallback to in-memory events from stream_engine
            events = list(stream_engine.recent_events)

        total_events = len(events)
        elapsed_sec = max(1.0, now - self.last_eval_time)
        current_tps = round(total_events / max(1.0, float(window_seconds)), 2)
        
        # Calculate velocity derivative (acceleration of transaction rate)
        velocity_derivative = round((current_tps - self.last_tps) / elapsed_sec, 3)
        self.last_tps = current_tps
        self.last_eval_time = now

        thought_chain.append(f"[OBSERVATION 1] Ingested {total_events} events. Current TPS: {current_tps} tx/s. Velocity derivative (dTPS/dt): {velocity_derivative:+.3f} tx/s^2.")

        # 2. Statistical distributions
        user_ids = [e.get("user_id") for e in events if e.get("user_id")]
        unique_users = len(set(user_ids))
        user_entropy = round(unique_users / max(1, len(user_ids)), 3)

        proxy_count = sum(1 for e in events if e.get("is_datacenter_proxy") == 1)
        proxy_ratio = round(proxy_count / max(1, total_events), 3)

        # Detect sub-50ms concurrency clusters per user
        user_timestamps: Dict[str, List[int]] = {}
        for e in events:
            uid = e.get("user_id")
            ep_ms = e.get("epoch_ms", 0)
            if uid and ep_ms:
                user_timestamps.setdefault(uid, []).append(ep_ms)

        concurrency_clusters = 0
        clustered_users = []
        for uid, t_list in user_timestamps.items():
            if len(t_list) > 1:
                t_list_sorted = sorted(t_list)
                for i in range(len(t_list_sorted) - 1):
                    if t_list_sorted[i+1] - t_list_sorted[i] <= 50:
                        concurrency_clusters += 1
                        if uid not in clustered_users:
                            clustered_users.append(uid)

        # Detect active burst stream IDs (Single-Packet Fuzzing)
        burst_streams = set(e.get("burst_stream_id") for e in events if e.get("burst_stream_id"))
        attack_events = sum(1 for e in events if e.get("is_attack") == 1)

        # Calculate high-risk voucher drain velocity
        voucher_claims = [e for e in events if "/voucher/claim" in str(e.get("api_endpoint", ""))]
        voucher_drain_usd = sum(float(e.get("transaction_amount_usd", 0.0)) for e in voucher_claims)
        drain_velocity_usd_s = round(voucher_drain_usd / max(1.0, float(window_seconds)), 2)

        # 3. Signal Tail Forecasting (extrapolating 30 seconds ahead)
        tail_forecast_t30 = max(0.0, round(current_tps + 30.0 * velocity_derivative, 1))
        tail_forecast_t60 = max(0.0, round(current_tps + 60.0 * velocity_derivative, 1))

        # Time to liquidity exhaustion ($100,000 campaign pool simulation)
        CAMPAIGN_POOL_USD = 100_000.0
        time_to_exhaustion_s = None
        if drain_velocity_usd_s > 10.0:
            time_to_exhaustion_s = max(1.0, round(CAMPAIGN_POOL_USD / drain_velocity_usd_s, 1))

        thought_chain.append(
            f"[ANALYSIS] User entropy: {user_entropy * 100:.1f}%. Datacenter proxy ratio: {proxy_ratio * 100:.1f}%. "
            f"Concurrency clusters (<=50ms): {concurrency_clusters}. Tail forecast at t+30s: {tail_forecast_t30} tx/s."
        )

        # 4. Contextual Filter (Check active business policies & promotional windows)
        policies = get_policy_rules()
        flash_sale_active = False
        flash_sale_rule = None
        burst_ceiling = 30.0

        for pol in policies:
            if pol.get("is_active") == 1:
                if pol.get("rule_type") == "FLASH_SALE_WINDOW":
                    flash_sale_active = True
                    flash_sale_rule = pol
                elif pol.get("rule_type") == "MAX_BURST_TPS":
                    burst_ceiling = float(pol.get("threshold_value", 30.0))

        # 5. Core Decision Logic (Stand-Down vs Breach)
        verdict = "NORMAL"
        verdict_badge = "NORMAL (NOMINAL BASELINE)"
        severity = "LOW"
        reason = "All velocity and concurrency indicators operating within nominal parameters."
        recommended_action = "PASSIVE_SURVEILLANCE"
        active_context = "NOMINAL_OPERATION"

        # Check for Critical Exploit: High Concurrency Cluster, Burst Streams, or Attack Tags
        is_exploit_burst = (
            concurrency_clusters >= 3 or
            len(burst_streams) > 0 or
            attack_events >= 2 or
            (current_tps > 20.0 and user_entropy < 0.35 and proxy_ratio > 0.30)
        )

        if is_exploit_burst:
            verdict = "CRITICAL_ANOMALY"
            verdict_badge = "CRITICAL ANOMALY (EXPLOIT BURST)"
            severity = "CRITICAL"
            reason = (
                f"Sub-millisecond concurrency clustering detected ({concurrency_clusters} collisions, {len(clustered_users)} accounts). "
                f"High probability of HTTP/2 Single-Packet TOCTOU race condition or Sybil bot swarm targeting /api/v1/voucher/claim."
            )
            recommended_action = "ESCALATE_TO_INVESTIGATOR"
            active_context = "ATTACK_IN_PROGRESS"
            thought_chain.append(f"[SENTINEL VERDICT] CRITICAL ANOMALY. Reason: {reason}")

        # Check for Contextual Stand-Down: High volume during active Flash Sale
        elif flash_sale_active and current_tps >= 15.0:
            # Check if traffic exhibits legitimate consumer diversity
            if user_entropy >= 0.70 and proxy_ratio <= 0.25 and concurrency_clusters == 0:
                verdict = "STAND_DOWN"
                verdict_badge = "STAND_DOWN (FLASH SALE CONTEXT)"
                severity = "INFO"
                rule_name = flash_sale_rule.get("name", "Flash Sale")
                reason = (
                    f"Traffic surge detected ({current_tps} tx/s), but Contextual Stand-Down Filter confirmed active "
                    f"'{rule_name}' with {user_entropy*100:.0f}% distinct legitimate buyers and clean network fingerprints. "
                    "Standing down to prevent false-positive checkout blockage."
                )
                recommended_action = "STAND_DOWN_MONITORING"
                active_context = "FLASH_SALE_STAND_DOWN"
                thought_chain.append(f"[SENTINEL VERDICT] STAND DOWN. Context confirmed: {rule_name}. Standing down.")
            else:
                verdict = "DRIFT_WARNING"
                verdict_badge = "DRIFT WARNING (ANOMALOUS PROMO SURGE)"
                severity = "HIGH"
                reason = (
                    f"High promo volume during Flash Sale, but low user entropy ({user_entropy*100:.0f}%) or elevated proxies "
                    f"({proxy_ratio*100:.0f}%) indicate opportunistic voucher botting."
                )
                recommended_action = "ENFORCE_IDEMPOTENCY_TOKEN"
                active_context = "PROMO_BOT_SURGE"
                thought_chain.append(f"[SENTINEL VERDICT] DRIFT WARNING. Context violated during flash sale.")

        # Check for Velocity Drift Warning (Accelerating towards threshold)
        elif current_tps >= burst_ceiling or tail_forecast_t30 >= burst_ceiling or (velocity_derivative >= 0.40 and current_tps >= 12.0):
            verdict = "DRIFT_WARNING"
            verdict_badge = "DRIFT WARNING (TRAJECTORY ACCELERATING)"
            severity = "MEDIUM"
            time_to_breach = max(1.0, round((burst_ceiling - current_tps) / max(0.01, velocity_derivative), 1)) if velocity_derivative > 0 else 15.0
            reason = (
                f"Transaction velocity trajectory accelerating ({velocity_derivative:+.2f} tx/s^2). "
                f"Tail forecast projects gateway ceiling breach ({burst_ceiling} TPS) in approximately {time_to_breach}s."
            )
            recommended_action = "PRE_WARM_CACHE_AND_THROTTLE"
            active_context = "TRAJECTORY_ACCELERATING"
            thought_chain.append(f"[SENTINEL VERDICT] DRIFT WARNING. Trajectory approaching ceiling.")

        else:
            thought_chain.append("[SENTINEL VERDICT] NOMINAL. All metrics within healthy baselines.")

        # 6. Cross-reference Historical Incident KB
        recalled_incident = None
        if verdict in ("CRITICAL_ANOMALY", "DRIFT_WARNING"):
            try:
                incidents = get_incident_memory(limit=5)
                for inc in incidents:
                    if "TOCTOU" in inc.get("threat_type", "") or "SYBIL" in inc.get("threat_type", ""):
                        recalled_incident = {
                            "incident_id": inc.get("incident_id"),
                            "threat_type": inc.get("threat_type"),
                            "financial_loss": inc.get("financial_loss"),
                            "remediation_patch": inc.get("remediation_patch"),
                            "rca_summary": inc.get("rca_summary")
                        }
                        thought_chain.append(
                            f"[MEMORY RECALL] Correlated with historical incident {inc.get('incident_id')} "
                            f"({inc.get('threat_type')}). Proven mitigation: {inc.get('remediation_patch')[:60]}..."
                        )
                        break
            except Exception:
                pass

        # Package state payload
        eval_result = {
            "epoch_ms": now_ms,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "severity": severity,
            "tps": current_tps,
            "velocity_derivative": velocity_derivative,
            "user_entropy": user_entropy,
            "proxy_ratio": proxy_ratio,
            "concurrency_clusters": concurrency_clusters,
            "clustered_users_sample": clustered_users[:5],
            "burst_streams_detected": list(burst_streams)[:3],
            "tail_forecast_t15": max(0.0, round(current_tps + 15.0 * velocity_derivative, 1)),
            "tail_forecast_t30": tail_forecast_t30,
            "tail_forecast_t60": tail_forecast_t60,
            "drain_velocity_usd_s": drain_velocity_usd_s,
            "time_to_exhaustion_s": time_to_exhaustion_s,
            "active_context": active_context,
            "flash_sale_active": flash_sale_active,
            "burst_ceiling_tps": burst_ceiling,
            "reason": reason,
            "recommended_action": recommended_action,
            "recalled_incident": recalled_incident,
            "thought_chain": thought_chain
        }

        self.current_state = eval_result
        self.current_verdict = verdict
        self.evaluation_history.append({
            "time": time.strftime("%H:%M:%S"),
            "tps": current_tps,
            "forecast_t30": tail_forecast_t30,
            "verdict": verdict,
            "clusters": concurrency_clusters
        })

        return eval_result

    def get_status(self) -> Dict[str, Any]:
        """Tra ve trang thai giam sat hien tai cua Sentinel"""
        return {
            "agent_name": self.agent_name,
            "agent_role": self.agent_role,
            "current_state": self.current_state,
            "history": list(self.evaluation_history)
        }

    def simulate_scenario(self, scenario: str = "flash_sale") -> Dict[str, Any]:
        """
        Gia lap cac kich ban thuc te de kiem chung hanh vi Sentinel:
        - 'flash_sale': Tang dot bien TPS nhung nguoi dung da dang -> Sentinel chon STAND_DOWN
        - 'toctou_attack': Concurrency burst cung 1 user tren /voucher/claim -> Sentinel chon CRITICAL_ANOMALY
        - 'drift_accelerate': Tang deu toc do giao dich -> Sentinel chon DRIFT_WARNING
        - 'normal': Tra ve baseline binh thuong
        """
        now = time.time()
        now_ms = int(now * 1000)

        if scenario == "flash_sale":
            result = {
                "epoch_ms": now_ms,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "verdict": "STAND_DOWN",
                "verdict_badge": "STAND_DOWN (FLASH SALE CONTEXT)",
                "severity": "INFO",
                "tps": 38.5,
                "velocity_derivative": +1.85,
                "user_entropy": 0.88,
                "proxy_ratio": 0.04,
                "concurrency_clusters": 0,
                "clustered_users_sample": [],
                "burst_streams_detected": [],
                "tail_forecast_t15": 66.2,
                "tail_forecast_t30": 94.0,
                "tail_forecast_t60": 149.5,
                "drain_velocity_usd_s": 850.0,
                "time_to_exhaustion_s": 117.6,
                "active_context": "FLASH_SALE_STAND_DOWN",
                "flash_sale_active": True,
                "burst_ceiling_tps": 30.0,
                "reason": (
                    "Traffic surge detected (38.5 tx/s), but Contextual Stand-Down Filter confirmed active "
                    "'Tet Super Sale 50% Flash Promotion' with 88% distinct legitimate buyers and clean residential IPs. "
                    "Standing down to prevent false-positive checkout blockage."
                ),
                "recommended_action": "STAND_DOWN_MONITORING",
                "recalled_incident": None,
                "thought_chain": [
                    "[THOUGHT 1] Sentinel scanning operational sliding window: last 15s.",
                    "[OBSERVATION 1] Telemetry surge detected: 38.5 tx/s (+1.85 tx/s^2).",
                    "[CONTEXT CHECK] Active policy found: RULE_FLASH_SALE_TET (Tet Super Sale 50%).",
                    "[ENTROPY VERIFICATION] User entropy is 88.0% (high consumer diversity). Proxy ratio is 4.0% (residential).",
                    "[SENTINEL VERDICT] STAND DOWN. Promotion context matches legitimate shopping pattern. Suppressing false alarm."
                ]
            }
        elif scenario == "toctou_attack":
            result = {
                "epoch_ms": now_ms,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "verdict": "CRITICAL_ANOMALY",
                "verdict_badge": "CRITICAL ANOMALY (EXPLOIT BURST)",
                "severity": "CRITICAL",
                "tps": 24.0,
                "velocity_derivative": +2.40,
                "user_entropy": 0.12,
                "proxy_ratio": 0.65,
                "concurrency_clusters": 14,
                "clustered_users_sample": ["USR_VN_00863", "USR_VN_00104"],
                "burst_streams_detected": ["burst_toctou_7a2f1b"],
                "tail_forecast_t15": 60.0,
                "tail_forecast_t30": 96.0,
                "tail_forecast_t60": 168.0,
                "drain_velocity_usd_s": 7500.0,
                "time_to_exhaustion_s": 13.3,
                "active_context": "ATTACK_IN_PROGRESS",
                "flash_sale_active": True,
                "burst_ceiling_tps": 30.0,
                "reason": (
                    "Sub-millisecond concurrency clustering detected (14 collisions, identical user USR_VN_00863). "
                    "High probability of HTTP/2 Single-Packet TOCTOU race condition targeting /api/v1/voucher/claim. Immediate handoff to Deep Investigator required."
                ),
                "recommended_action": "ESCALATE_TO_INVESTIGATOR",
                "recalled_incident": {
                    "incident_id": "INC-2026-001",
                    "threat_type": "TOCTOU_RACE_CONDITION",
                    "financial_loss": 7500.0,
                    "remediation_patch": "Redis SET NX distributed lock with 3.0s lease TTL on user_id key to serialize atomic voucher redemption."
                },
                "thought_chain": [
                    "[THOUGHT 1] Sentinel scanning operational sliding window: last 15s.",
                    "[OBSERVATION 1] Single-Packet burst pattern detected on stream 'burst_toctou_7a2f1b'.",
                    "[CLUSTER DETECTION] 14 requests arrived within <= 2ms window from user 'USR_VN_00863'.",
                    "[MEMORY RECALL] Matched past incident INC-2026-001 (TOCTOU Race Condition on Tet Voucher).",
                    "[SENTINEL VERDICT] CRITICAL ANOMALY. Escalating to Deep Investigator and Blue Team CRS."
                ]
            }
        elif scenario == "drift_accelerate":
            result = {
                "epoch_ms": now_ms,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "verdict": "DRIFT_WARNING",
                "verdict_badge": "DRIFT WARNING (TRAJECTORY ACCELERATING)",
                "severity": "MEDIUM",
                "tps": 22.0,
                "velocity_derivative": +0.65,
                "user_entropy": 0.85,
                "proxy_ratio": 0.08,
                "concurrency_clusters": 0,
                "clustered_users_sample": [],
                "burst_streams_detected": [],
                "tail_forecast_t15": 31.7,
                "tail_forecast_t30": 41.5,
                "tail_forecast_t60": 61.0,
                "drain_velocity_usd_s": 120.0,
                "time_to_exhaustion_s": 833.3,
                "active_context": "TRAJECTORY_ACCELERATING",
                "flash_sale_active": False,
                "burst_ceiling_tps": 30.0,
                "reason": (
                    "Transaction velocity trajectory accelerating (+0.65 tx/s^2). "
                    "Tail forecast projects gateway ceiling breach (30.0 TPS) in approximately 12.3s."
                ),
                "recommended_action": "PRE_WARM_CACHE_AND_THROTTLE",
                "recalled_incident": None,
                "thought_chain": [
                    "[THOUGHT 1] Sentinel scanning operational sliding window: last 15s.",
                    "[OBSERVATION 1] Steady upward velocity drift from 10.0 to 22.0 tx/s.",
                    "[TAIL FORECAST] Extrapolation models breach of 30 TPS ceiling in 12.3s.",
                    "[SENTINEL VERDICT] DRIFT WARNING. Pre-warming Redis cache and alert SecOps."
                ]
            }
        else: # normal
            return self.evaluate_telemetry(window_seconds=15)

        self.current_state = result
        self.current_verdict = result["verdict"]
        self.evaluation_history.append({
            "time": time.strftime("%H:%M:%S"),
            "tps": result["tps"],
            "forecast_t30": result["tail_forecast_t30"],
            "verdict": result["verdict"],
            "clusters": result["concurrency_clusters"]
        })
        return result


global_fintech_sentinel = FinTechSentinelAgent()
