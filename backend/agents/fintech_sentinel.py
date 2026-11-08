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
from contextlib import closing

from backend.database import get_connection, get_policy_rules, get_incident_memory, DB_PATH, get_active_db_path
from backend.telemetry_analysis import sentinel_window
from backend.evidence import dataset_identity, analysis_context
from backend.stream_engine import stream_engine


class FinTechSentinelAgent:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path
        self.agent_name = "FinTech Sentinel"
        self.agent_role = "Autonomous Operational Surveillance & Contextual Stand-Down Agent"
        
        # Sliding history of evaluations for UI trend chart (last 30 samples)
        self.evaluation_history = deque(maxlen=30)
        self._dataset_key = None
        
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

    def evaluate_telemetry(self, window_seconds: int = 15, events_override: Optional[List[Dict[str, Any]]] = None,
                           policies_override: Optional[List[Dict[str, Any]]] = None,
                           now_override: Optional[float] = None) -> Dict[str, Any]:
        """
        Thuc thi chu trinh danh gia giam sat Sentinel tren cua so truot window_seconds:
        1. Doc du lieu thoi gian thuc tu SQLite / Stream Engine (hoac fixture synthetic)
        2. Tinh toan bien thien van toc (dTPS/dt) va mat do clustering
        3. Chay thuat toan Tail Forecasting du bao quy dao sau 30 giay
        4. Kiem tra bo loc ngu canh Contextual Stand-Down (Flash Sale vs Exploit)
        5. Doi chieu Incident Memory KB va dua ra phan quyet
        """
        now = now_override if now_override is not None else time.time()
        now_ms = int(now * 1000)
        window_ms = window_seconds * 1000
        min_epoch = now_ms - window_ms
        is_simulated = events_override is not None
        coverage_complete = True
        database_path = self.db_path or get_active_db_path()
        identity = dataset_identity(database_path)
        dataset_key = (identity.dataset_id, identity.dataset_revision)
        # Keep derivatives within a dataset; revisions invalidate cached results,
        # but streaming appends should not reset derivatives on every evaluation.
        if self._dataset_key and self._dataset_key != dataset_key:
            self.evaluation_history.clear()
            if self._dataset_key[0] != dataset_key[0]:
                self.last_tps = 0.0
                self.last_eval_time = now - window_seconds
        self._dataset_key = dataset_key
        snapshot = None

        thought_chain = []
        thought_chain.append(f"[THOUGHT 1] Sentinel scanning operational sliding window: last {window_seconds}s (epoch >= {min_epoch}).")

        # 1. Truy van du lieu tu SQLite, hoac dung fixture synthetic cho scenario demo
        events = []
        if events_override is not None:
            events = [dict(e) for e in events_override]
            thought_chain.append("[DATA SOURCE] Synthetic scenario fixture (not live production telemetry).")
        else:
            try:
                snapshot = sentinel_window(database_path, window_seconds, now_ms)
            except Exception as e:
                coverage_complete = False
                thought_chain.append(f"[WARNING] Fallback to in-memory stream buffer: {str(e)}")
                # Fallback to in-memory events from stream_engine
                # Never substitute the default stream for a selected custom dataset.
                events = ([dict(e) for e in stream_engine.get_events(limit=50)
                           if min_epoch <= e.get("epoch_ms", 0) <= now_ms]
                          if dataset_identity(DB_PATH).dataset_id == identity.dataset_id else [])

        total_events = len(events)
        if snapshot:
            total_events = snapshot["total"]
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
        if snapshot:
            user_entropy = snapshot["user_entropy"]
            proxy_ratio = snapshot["proxy_ratio"]

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

        # Detect active burst stream IDs. Ground-truth `is_attack` is intentionally
        # not used for live decisions; it would leak labels into the detector.
        burst_streams = {
            b for b in (e.get("burst_stream_id") for e in events)
            if b and str(b) not in ("NONE", "null", "None", "")
        }
        if snapshot:
            concurrency_clusters = snapshot["concurrency_clusters"]
            clustered_users = snapshot["clustered_users"]
            burst_streams = set(snapshot["burst_streams"])

        # Calculate high-risk voucher drain velocity
        voucher_claims = [e for e in events if "/voucher/claim" in str(e.get("api_endpoint", ""))]
        voucher_drain_usd = sum(float(e.get("transaction_amount_usd", 0.0)) for e in voucher_claims)
        if snapshot:
            voucher_drain_usd = snapshot["drain"]
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
        policies = (policies_override if policies_override is not None else
                    snapshot["policies"] if snapshot else [])
        flash_sale_active = False
        flash_sale_rule = None
        burst_ceiling = 30.0

        def _within_window(pol: Dict[str, Any]) -> bool:
            # A lapsed or not-yet-started promotion must not suppress alerts.
            fmt = "%Y-%m-%d %H:%M:%S"
            try:
                start = pol.get("active_from")
                end = pol.get("active_to")
                if start and now < time.mktime(time.strptime(str(start)[:19], fmt)):
                    return False
                if end and now > time.mktime(time.strptime(str(end)[:19], fmt)):
                    return False
            except (ValueError, OverflowError):
                return False
            return True

        for pol in policies:
            if pol.get("is_active") == 1 and _within_window(pol):
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
            (current_tps > 20.0 and user_entropy < 0.35 and proxy_ratio > 0.30)
        )

        if is_exploit_burst:
            verdict = "CRITICAL_ANOMALY"
            verdict_badge = "CRITICAL ANOMALY (EXPLOIT BURST)"
            severity = "CRITICAL"
            reason = (
                f"Concurrency clustering detected ({concurrency_clusters} inter-arrival gaps <=50ms, "
                f"{len(clustered_users)} accounts). This is a heuristic signal for a possible race-condition "
                f"attempt or bot swarm; it is not proof of a specific HTTP/2 technique."
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

        if (not coverage_complete or not total_events) and verdict in ("NORMAL", "STAND_DOWN"):
            verdict = "INSUFFICIENT_DATA"
            verdict_badge = "INSUFFICIENT DATA"
            severity = "INFO"
            reason = "No complete, nonempty telemetry window is available to establish traffic health."
            recommended_action = "RESTORE_TELEMETRY_ACCESS"

        # 6. Cross-reference Historical Incident KB
        recalled_incident = None
        if verdict in ("CRITICAL_ANOMALY", "DRIFT_WARNING"):
            try:
                incidents = snapshot["incidents"] if snapshot else []
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
            "database_path": database_path,
            "context": (snapshot["context"] if snapshot else analysis_context(
                database_path, window_seconds, now_ms=now_ms, coverage_complete=coverage_complete,
                analyzed_count=total_events,
                source="SYNTHETIC_SCENARIO" if is_simulated else "UNAVAILABLE_OR_PARTIAL_BUFFER").model_dump()),
            "assessment_state": ("INSUFFICIENT_DATA" if not coverage_complete or not total_events else
                                 "SIGNAL_DETECTED" if verdict in ("CRITICAL_ANOMALY", "DRIFT_WARNING") else
                                 "NO_SIGNAL_OBSERVED"),
            "epoch_ms": now_ms,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "is_simulated": is_simulated,
            "data_source": "SYNTHETIC_SCENARIO" if is_simulated else "ACTIVE_DB" if coverage_complete else "STREAM_BUFFER",
            "coverage_complete": coverage_complete,
            "analyzed_event_count": total_events,
            "campaign_pool_usd": CAMPAIGN_POOL_USD,
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
        if snapshot:
            self._dataset_key = (snapshot['context']['dataset_id'], snapshot['context']['dataset_revision'])
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
        current = dataset_identity(self.db_path or get_active_db_path())
        if self._dataset_key != (current.dataset_id, current.dataset_revision):
            self.current_state = {"verdict": "INSUFFICIENT_DATA", "verdict_badge": "NOT ASSESSED",
                                  "assessment_state": "NOT_ASSESSED", "tps": 0.0,
                                  "reason": "Dataset changed or has not been evaluated; run Sentinel evaluation.",
                                  "database_path": current.database_path}
            self.evaluation_history.clear()
        return {
            "agent_name": self.agent_name,
            "agent_role": self.agent_role,
            "current_state": self.current_state,
            "history": list(self.evaluation_history)
        }

    def _build_scenario_events(self, scenario: str, now_ms: int, window_seconds: int = 15):
        """Build deterministic synthetic telemetry for UI scenario demos."""
        events = []
        policies = []
        if scenario == "flash_sale":
            tps = 38.5
            count = int(tps * window_seconds)
            unique_users = max(1, int(count * 0.88))
            proxy_count = int(count * 0.04)
            for i in range(count):
                events.append({
                    "event_id": f"SIM-FLASH-{i:05d}",
                    "epoch_ms": now_ms - int((i / count) * window_seconds * 1000),
                    "user_id": f"USR_FLASH_{i % unique_users:05d}",
                    "api_endpoint": "/api/v1/voucher/claim",
                    "transaction_amount_usd": 50.0,
                    "is_attack": 0,
                    "attack_type": "BENIGN",
                    "is_datacenter_proxy": 1 if i < proxy_count else 0,
                    "burst_stream_id": "NONE",
                    "network_rtt_ms": 12.0,
                    "server_latency_ms": 4.0,
                })
            policies = [
                {"rule_type": "FLASH_SALE_WINDOW", "is_active": 1, "name": "Synthetic Flash Sale", "threshold_value": 30.0},
                {"rule_type": "MAX_BURST_TPS", "is_active": 1, "name": "Synthetic Burst Ceiling", "threshold_value": 30.0},
            ]
        elif scenario == "toctou_attack":
            tps = 24.0
            count = int(tps * window_seconds)
            proxy_count = int(count * 0.65)
            for i in range(count):
                events.append({
                    "event_id": f"SIM-TOCTOU-{i:05d}",
                    "epoch_ms": now_ms - (i * 2),
                    "user_id": "USR_VN_00863" if i < int(count * 0.8) else "USR_VN_00104",
                    "api_endpoint": "/api/v1/voucher/claim",
                    "transaction_amount_usd": 500.0,
                    "is_attack": 1,
                    "attack_type": "TOCTOU_RACE_CONDITION",
                    "is_datacenter_proxy": 1 if i < proxy_count else 0,
                    "burst_stream_id": "burst_toctou_synthetic",
                    "network_rtt_ms": 2.0,
                    "server_latency_ms": 1.0,
                })
            policies = [
                {"rule_type": "FLASH_SALE_WINDOW", "is_active": 1, "name": "Synthetic Flash Sale", "threshold_value": 30.0},
                {"rule_type": "MAX_BURST_TPS", "is_active": 1, "name": "Synthetic Burst Ceiling", "threshold_value": 30.0},
            ]
        elif scenario == "drift_accelerate":
            tps = 22.0
            count = int(tps * window_seconds)
            unique_users = max(1, int(count * 0.85))
            proxy_count = int(count * 0.08)
            for i in range(count):
                events.append({
                    "event_id": f"SIM-DRIFT-{i:05d}",
                    "epoch_ms": now_ms - int((i / count) * window_seconds * 1000),
                    "user_id": f"USR_DRIFT_{i % unique_users:05d}",
                    "api_endpoint": "/api/v1/checkout",
                    "transaction_amount_usd": 20.0,
                    "is_attack": 0,
                    "attack_type": "BENIGN",
                    "is_datacenter_proxy": 1 if i < proxy_count else 0,
                    "burst_stream_id": "NONE",
                    "network_rtt_ms": 20.0,
                    "server_latency_ms": 8.0,
                })
            policies = [
                {"rule_type": "MAX_BURST_TPS", "is_active": 1, "name": "Synthetic Burst Ceiling", "threshold_value": 30.0},
            ]
        return events, policies

    def simulate_scenario(self, scenario: str = "flash_sale") -> Dict[str, Any]:
        """
        Chay mot fixture synthetic qua cung engine danh gia de demo:
        - 'flash_sale': nhieu nguoi dung da dang -> STAND_DOWN
        - 'toctou_attack': burst cung user tren /voucher/claim -> CRITICAL_ANOMALY
        - 'drift_accelerate': TPS tang deu -> DRIFT_WARNING
        - 'normal': doc du lieu that trong DB hien hanh
        """
        if scenario == "normal":
            return self.evaluate_telemetry(window_seconds=15)

        if scenario not in ("flash_sale", "toctou_attack", "drift_accelerate"):
            scenario = "flash_sale"

        window_seconds = 15
        now = time.time()
        now_ms = int(now * 1000)
        events, policies = self._build_scenario_events(scenario, now_ms, window_seconds)

        # Anchor the derivative calculation so the synthetic scenario is reproducible.
        self.last_tps = 10.0
        self.last_eval_time = now - window_seconds

        result = self.evaluate_telemetry(
            window_seconds=window_seconds,
            events_override=events,
            policies_override=policies,
            now_override=now,
        )
        result["scenario"] = scenario
        return result


global_fintech_sentinel = FinTechSentinelAgent()
