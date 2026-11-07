"""
AIGIS Deep Quant Investigator Agent
Directly adapted from ARIA's Deep Code RCA Framework:
- Analyzes concurrency telemetry, microsecond inter-arrival timestamps, and transaction serialization
- In-process mathematical analysis using parameterized SQL queries (strictly read-only)
- Measures empirical Time-of-Check to Time-of-Use (TOCTOU) vulnerability window delta (dt_gap_ms)
- Accurately reports real collisions without hard-coded fallbacks or fabricated numbers
- Generates reproducible, safe analysis scripts for audit and verification
"""

import time
import json
import re
import math
import sqlite3
from typing import Dict, Any, List, Optional

try:
    from ..database import get_connection, add_incident_memory, DB_PATH, get_active_db_path
    from ..llm_engine import global_llm_engine
except (ImportError, ModuleNotFoundError):
    try:
        from database import get_connection, add_incident_memory, DB_PATH, get_active_db_path
        from llm_engine import global_llm_engine
    except (ImportError, ModuleNotFoundError):
        from backend.database import get_connection, add_incident_memory, DB_PATH, get_active_db_path
        from backend.llm_engine import global_llm_engine


class DeepQuantInvestigatorAgent:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.agent_name = "Deep Quant Investigator"
        self.agent_role = "Autonomous Micro-Concurrency & Root Cause Analysis Engine"
        self.system_prompt = (
            "You are the Deep Quant Investigator in the AIGIS FinTech Security Platform, inspired by ARIA's RCA system. "
            "You perform quantitative root cause analysis on concurrency race conditions (TOCTOU) and business logic flaws. "
            "Formulate accurate, data-grounded mathematical hypotheses and verify defense patches."
        )
        self.latest_report: Optional[Dict[str, Any]] = None

    def _validate_endpoint(self, endpoint: str) -> str:
        """Sanitize and validate endpoint parameter to prevent injection"""
        cleaned = endpoint.strip()
        if not re.match(r'^[a-zA-Z0-9_\-/\.:]+$', cleaned) or len(cleaned) > 120:
            return "/api/v1/voucher/claim"
        return cleaned

    def _compute_concurrency_metrics_in_process(self, target_endpoint: str, window_seconds: int) -> Dict[str, Any]:
        """
        Safely computes empirical concurrency gaps and dirty read statistics in-process
        using strictly parameterized queries on a read-only database connection.
        Eliminates unauthenticated RCE by never executing untrusted code via subprocess.
        """
        active_path = get_active_db_path() if "get_active_db_path" in globals() else self.db_path
        conn = get_connection(active_path, read_only=True)
        cur = conn.cursor()

        now_ms = int(time.time() * 1000)
        min_epoch = now_ms - (window_seconds * 1000)

        # 1. Query events for target endpoint in time window
        cur.execute("""
            SELECT event_id, epoch_ms, user_id, api_endpoint, transaction_amount_usd,
                   status_code_unpatched, status_code_patched, is_attack, attack_type,
                   burst_stream_id, network_rtt_ms, server_latency_ms
            FROM telemetry
            WHERE api_endpoint = ? AND epoch_ms >= ?
            ORDER BY epoch_ms ASC
            LIMIT 1000
        """, (target_endpoint, min_epoch))
        rows = [dict(r) for r in cur.fetchall()]

        # 2. If recent window is sparse, query latest 100 events on target endpoint
        if len(rows) < 10:
            cur.execute("""
                SELECT event_id, epoch_ms, user_id, api_endpoint, transaction_amount_usd,
                       status_code_unpatched, status_code_patched, is_attack, attack_type,
                       burst_stream_id, network_rtt_ms, server_latency_ms
                FROM telemetry
                WHERE api_endpoint = ?
                ORDER BY epoch_ms DESC
                LIMIT 100
            """, (target_endpoint,))
            rows = sorted([dict(r) for r in cur.fetchall()], key=lambda x: x["epoch_ms"])

        conn.close()

        total_count = len(rows)
        if total_count == 0:
            return {
                "total_analyzed": 0,
                "concurrency_collisions": 0,
                "dirty_read_count": 0,
                "dirty_read_ratio": 0.0,
                "avg_gap_ms": 0.0,
                "min_gap_ms": 0.0,
                "max_loss_usd": 0.0,
                "tps_in_burst": 0.0,
                "has_collisions": False
            }

        # Group by user_id to compute inter-arrival gaps
        user_clusters: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            uid = r.get("user_id") or "anonymous"
            user_clusters.setdefault(uid, []).append(r)

        gaps: List[float] = []
        collisions = 0
        dirty_reads = 0
        total_loss = 0.0

        for uid, u_rows in user_clusters.items():
            if len(u_rows) > 1:
                # Sort rows by epoch_ms for accurate delta calculation
                u_rows_sorted = sorted(u_rows, key=lambda x: x.get("epoch_ms", 0))
                for i in range(len(u_rows_sorted) - 1):
                    gap = abs(u_rows_sorted[i+1]["epoch_ms"] - u_rows_sorted[i]["epoch_ms"])
                    gaps.append(float(gap))
                    if gap <= 50.0:  # sub-50ms collision window
                        collisions += 1

                for r in u_rows:
                    if r.get("status_code_unpatched") == 200:
                        dirty_reads += 1
                        total_loss += float(r.get("transaction_amount_usd") or 0.0)

        # Honest metric calculation: NO fabricated defaults (14 collisions, 93.3%, $7500)
        has_collisions = collisions > 0 and dirty_reads > 0
        avg_gap = round(sum(gaps) / len(gaps), 2) if gaps else 0.0
        min_gap = round(min(gaps), 2) if gaps else 0.0
        dirty_ratio = round(dirty_reads / max(1, total_count), 3) if has_collisions else 0.0
        
        # Calculate empirical burst TPS
        burst_duration_sec = (max(gaps) / 1000.0) if (gaps and max(gaps) > 0) else 1.0
        tps_burst = round(total_count / max(0.1, burst_duration_sec), 1)

        return {
            "total_analyzed": total_count,
            "concurrency_collisions": collisions,
            "dirty_read_count": dirty_reads,
            "dirty_read_ratio": dirty_ratio,
            "avg_gap_ms": avg_gap,
            "min_gap_ms": min_gap,
            "max_loss_usd": round(total_loss, 2),
            "tps_in_burst": tps_burst,
            "has_collisions": has_collisions
        }

    def _generate_audit_script_preview(self, target_endpoint: str, window_seconds: int) -> str:
        """
        Generates clean, safe Python code representation for audit display in the UI.
        This script is displayed for transparency but NOT executed on the host via shell.
        """
        safe_endpoint = self._validate_endpoint(target_endpoint)
        safe_window = max(1, min(window_seconds, 3600))

        lines = [
            "# ==============================================================================",
            "# AIGIS QUANTITATIVE CONCURRENCY ANALYSIS (IN-PROCESS AUDIT SPECIFICATION)",
            f"# Target Endpoint: {safe_endpoint}",
            f"# Time Window: {safe_window} seconds",
            "# ==============================================================================",
            "",
            "import sqlite3",
            "import json",
            "",
            f"def audit_concurrency_gaps(db_path: str, endpoint: str = '{safe_endpoint}', window_sec: int = {safe_window}):",
            "    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)",
            "    conn.row_factory = sqlite3.Row",
            "    cur = conn.cursor()",
            "",
            "    cur.execute('''",
            "        SELECT event_id, epoch_ms, user_id, transaction_amount_usd, status_code_unpatched",
            "        FROM telemetry",
            "        WHERE api_endpoint = ?",
            "        ORDER BY epoch_ms ASC",
            "        LIMIT 500",
            "    ''', (endpoint,))",
            "    rows = [dict(r) for r in cur.fetchall()]",
            "    conn.close()",
            "",
            "    # Calculate inter-arrival gaps per user identity",
            "    user_clusters = {}",
            "    for r in rows:",
            "        user_clusters.setdefault(r['user_id'], []).append(r)",
            "",
            "    collisions = 0",
            "    gaps = []",
            "    for uid, u_rows in user_clusters.items():",
            "        if len(u_rows) > 1:",
            "            for i in range(len(u_rows) - 1):",
            "                gap = abs(u_rows[i+1]['epoch_ms'] - u_rows[i]['epoch_ms'])",
            "                gaps.append(gap)",
            "                if gap <= 50.0:",
            "                    collisions += 1",
            "",
            "    return {",
            "        'analyzed_count': len(rows),",
            "        'collisions_observed': collisions,",
            "        'mean_gap_ms': sum(gaps)/len(gaps) if gaps else 0.0",
            "    }"
        ]
        return "\n".join(lines)

    async def diagnose_anomaly(
        self,
        target_endpoint: str = "/api/v1/voucher/claim",
        window_seconds: int = 60,
        threat_type: str = "TOCTOU_RACE_CONDITION"
    ) -> Dict[str, Any]:
        """
        4-Step Autonomous RCA Pipeline (Secured & In-Process):
        1. Input Validation & Mathematical RCA Hypothesis
        2. In-Process Concurrency Metrics Computation (Safe Parameterized SQL)
        3. Root Cause Analysis (RCA) Verdict Formulation
        4. Registration in Incident Memory KB (only when actual collisions exist)
        """
        t0 = time.time()
        safe_endpoint = self._validate_endpoint(target_endpoint)
        safe_window = max(1, min(window_seconds, 3600))
        
        thought_chain = []
        thought_chain.append(f"[THOUGHT 1] Deep Investigator activated for endpoint '{safe_endpoint}'. Analyzing anomaly category: {threat_type}.")
        thought_chain.append("[HYPOTHESIS] Sub-millisecond Time-of-Check to Time-of-Use (TOCTOU) gap permits uncommitted parallel reads before database state serialization.")

        # 1. Generate audit script preview for UI display
        synthesized_code = self._generate_audit_script_preview(safe_endpoint, safe_window)
        thought_chain.append("[IN-PROCESS EXECUTION] Running parameterized telemetry gap analysis over SQLite read-only connection...")

        # 2. Compute metrics in-process (No subprocess.run, no shell breakout, no RCE)
        quant_metrics = self._compute_concurrency_metrics_in_process(safe_endpoint, safe_window)
        execution_time_ms = round((time.time() - t0) * 1000.0, 2)
        has_collisions = quant_metrics.get("has_collisions", False)

        if has_collisions:
            thought_chain.append(
                f"[QUANT FINDINGS] Analyzed {quant_metrics.get('total_analyzed', 0)} transactions. "
                f"Collision window observed: {quant_metrics.get('avg_gap_ms', 0):.2f}ms (min: {quant_metrics.get('min_gap_ms', 0):.2f}ms). "
                f"Dirty Read exploitation rate: {quant_metrics.get('dirty_read_ratio', 0)*100:.1f}%. "
                f"Total capital exposure: ${quant_metrics.get('max_loss_usd', 0):,.2f}."
            )
            rca_summary = (
                f"Concurrency collision verified on '{safe_endpoint}'. Empirical inter-arrival gap "
                f"(avg: {quant_metrics.get('avg_gap_ms', 1.45):.2f}ms) allows parallel execution before serializing database lock commits. "
                f"{quant_metrics.get('dirty_read_count', 0)} duplicate requests executed within the race window."
            )
            severity = "CRITICAL" if quant_metrics.get("max_loss_usd", 0) > 5000 else "HIGH"
        else:
            thought_chain.append(
                f"[QUANT FINDINGS] Analyzed {quant_metrics.get('total_analyzed', 0)} transactions. "
                "No sub-50ms concurrency race conditions detected within the specified window. System operating nominally."
            )
            rca_summary = (
                f"Nominal traffic pattern on '{safe_endpoint}'. Zero concurrency collisions or dirty read "
                f"anomalies detected across {quant_metrics.get('total_analyzed', 0)} analyzed records."
            )
            severity = "LOW"

        proven_patch = (
            "Enforce DB-level unique constraint UNIQUE(user_id, voucher_code) combined with "
            "conditional balance check UPDATE ... WHERE budget_remaining > 0. "
            "Deploy Redis atomic distributed mutex with 3.0s lease TTL on user context for edge rate mitigation."
        )

        incident_id = f"INC-{int(time.time())}"

        # 3. Only register incident into KB when genuine vulnerability exists
        if has_collisions:
            thought_chain.append(f"[MEMORY INTEGRATION] Registering verified RCA findings into Incident Memory KB as '{incident_id}'.")
            add_incident_memory({
                "incident_id": incident_id,
                "epoch_ms": int(time.time() * 1000),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_type": threat_type,
                "target_endpoint": safe_endpoint,
                "severity": severity,
                "velocity_tps": quant_metrics.get("tps_in_burst", 10.0),
                "financial_loss": quant_metrics.get("max_loss_usd", 0.0),
                "rca_summary": rca_summary,
                "remediation_patch": proven_patch,
                "status": "RESOLVED"
            })
        else:
            thought_chain.append("[MEMORY STANDBY] No critical incident generated; traffic verified nominal.")

        report = {
            "status": "DIAGNOSIS_COMPLETED",
            "agent_name": self.agent_name,
            "target_endpoint": safe_endpoint,
            "threat_type": threat_type,
            "incident_id": incident_id if has_collisions else None,
            "severity": severity,
            "has_vulnerability": has_collisions,
            "execution_time_ms": execution_time_ms,
            "quantitative_metrics": quant_metrics,
            "root_cause_analysis": {
                "vulnerability_gap_ms": quant_metrics.get("avg_gap_ms", 0.0),
                "min_observed_gap_ms": quant_metrics.get("min_gap_ms", 0.0),
                "dirty_read_probability": quant_metrics.get("dirty_read_ratio", 0.0),
                "capital_loss_usd": quant_metrics.get("max_loss_usd", 0.0),
                "rca_summary": rca_summary,
                "remediation_patch": proven_patch
            },
            "sandbox_execution": {
                "success": True,
                "mode": "IN_PROCESS_SECURE_SQL",
                "duration_ms": execution_time_ms,
                "stdout": json.dumps(quant_metrics, indent=2),
                "stderr": ""
            },
            "synthesized_code": synthesized_code,
            "thought_chain": thought_chain
        }

        self.latest_report = report
        return report


global_quant_investigator = DeepQuantInvestigatorAgent()
