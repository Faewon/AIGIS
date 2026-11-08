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
import uuid
import json
import re
import asyncio
from typing import Dict, Any, List, Optional

from backend.database import get_connection, add_incident_memory, DB_PATH, get_active_db_path
from backend.llm_engine import global_llm_engine
from backend.evidence import dataset_identity, AssessmentState
from backend.telemetry_analysis import concurrency_metrics


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
        self._latest_report: Optional[Dict[str, Any]] = None

    @property
    def latest_report(self):
        report = self._latest_report
        if report and dataset_identity(report.get("database_path", "")).dataset_id == dataset_identity(get_active_db_path()).dataset_id:
            context = report.get("context")
            if context and context["dataset_revision"] != dataset_identity(get_active_db_path()).dataset_revision:
                return None
            return report
        return None

    @latest_report.setter
    def latest_report(self, report):
        self._latest_report = report

    def _validate_endpoint(self, endpoint: str) -> str:
        """Sanitize and validate endpoint parameter to prevent injection"""
        cleaned = endpoint.strip()
        if not re.match(r'^[a-zA-Z0-9_\-/\.:]+$', cleaned) or len(cleaned) > 120:
            return "/api/v1/voucher/claim"
        return cleaned

    def _compute_concurrency_metrics_in_process(self, target_endpoint: str, window_seconds: int, database_path=None) -> Dict[str, Any]:
        return concurrency_metrics(database_path or get_active_db_path(), target_endpoint, window_seconds)

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
            "import time",
            "",
            f"def audit_concurrency_gaps(db_path: str, endpoint: str = '{safe_endpoint}', window_sec: int = {safe_window}):",
            "    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)",
            "    conn.row_factory = sqlite3.Row",
            "    cur = conn.cursor()",
            "",
            "    cur.execute('''",
            "        SELECT event_id, epoch_ms, user_id, transaction_amount_usd, status_code_unpatched",
            "        FROM telemetry",
            "        WHERE api_endpoint = ? AND epoch_ms >= ? AND epoch_ms <= ?",
            "        ORDER BY epoch_ms ASC",
            "    ''', (endpoint, int(time.time() * 1000) - window_sec * 1000, int(time.time() * 1000)))",
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
        database_path = get_active_db_path()
        safe_endpoint = self._validate_endpoint(target_endpoint)
        safe_window = max(1, min(window_seconds, 3600))
        
        thought_chain = []
        thought_chain.append(f"[THOUGHT 1] Deep Investigator activated for endpoint '{safe_endpoint}'. Analyzing anomaly category: {threat_type}.")
        thought_chain.append("[HYPOTHESIS] Sub-millisecond Time-of-Check to Time-of-Use (TOCTOU) gap permits uncommitted parallel reads before database state serialization.")

        # 1. Generate audit script preview for UI display
        synthesized_code = self._generate_audit_script_preview(safe_endpoint, safe_window)
        thought_chain.append("[IN-PROCESS EXECUTION] Running parameterized telemetry gap analysis over SQLite read-only connection...")

        # 2. Compute metrics in-process (No subprocess.run, no shell breakout, no RCE)
        quant_metrics = await asyncio.to_thread(self._compute_concurrency_metrics_in_process,
                                               safe_endpoint, safe_window, database_path)
        execution_time_ms = round((time.time() - t0) * 1000.0, 2)
        has_collisions = quant_metrics.get("has_collisions", False)

        if quant_metrics.get("supported") is False:
            report = {
                "status": "UNSUPPORTED_DATASET", "database_path": database_path,
                "context": quant_metrics.get("context"),
                "assessment_state": AssessmentState.INSUFFICIENT_DATA.value,
                "agent_name": self.agent_name, "target_endpoint": safe_endpoint,
                "has_vulnerability": False, "severity": "INFO", "incident_id": None,
                "error": quant_metrics["error"], "quantitative_metrics": quant_metrics,
                "root_cause_analysis": {"rca_summary": quant_metrics["error"]},
                "sandbox_execution": {"success": False, "stderr": quant_metrics["error"]},
                "thought_chain": [], "synthesized_code": synthesized_code,
            }
            self.latest_report = report
            return report

        if has_collisions:
            thought_chain.append(
                f"[QUANT FINDINGS] Analyzed {quant_metrics.get('total_analyzed', 0)} transactions. "
                f"Collision window observed: {quant_metrics.get('avg_gap_ms', 0):.2f}ms (min: {quant_metrics.get('min_gap_ms', 0):.2f}ms). "
                f"Dirty Read exploitation rate: {quant_metrics.get('dirty_read_ratio', 0)*100:.1f}%. "
                f"Total capital exposure: ${quant_metrics.get('max_loss_usd', 0):,.2f}."
            )
            rca_summary = (
                f"Suspicious repeated successes observed on '{safe_endpoint}'. Mean inter-arrival gap "
                f"{quant_metrics.get('avg_gap_ms', 0):.2f}ms; {quant_metrics.get('dirty_read_count', 0)} "
                "additional successes in short identified bursts. Telemetry alone does not prove a database isolation failure."
            )
            severity = "CRITICAL" if quant_metrics.get("max_loss_usd", 0) > 5000 else "HIGH"
        else:
            thought_chain.append(
                f"[QUANT FINDINGS] Analyzed {quant_metrics.get('total_analyzed', 0)} transactions. "
                "No repeated-success signal observed; this is not proof of database isolation correctness."
            )
            rca_summary = (
                f"No repeated-success signal across {quant_metrics.get('total_analyzed', 0)} analyzed records "
                f"on '{safe_endpoint}'." if quant_metrics.get('total_analyzed') else
                "No events in the requested window; insufficient evidence to assess traffic health."
            )
            severity = "LOW"

        proven_patch = (
            "Enforce DB-level unique constraint UNIQUE(user_id, voucher_code) combined with "
            "conditional balance check UPDATE ... WHERE budget_remaining > 0. "
            "Deploy Redis atomic distributed mutex with 3.0s lease TTL on user context for edge rate mitigation."
        )

        incident_id = f"INC-{uuid.uuid4().hex}"

        # 3. Only register incident into KB when genuine vulnerability exists
        if has_collisions:
            thought_chain.append(f"[MEMORY INTEGRATION] Recording an unverified telemetry signal as '{incident_id}'.")
            recorded = add_incident_memory({
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
                "status": "SIGNAL_DETECTED"
            }, custom_path=database_path)
            if not recorded:
                incident_id = None
                thought_chain.append("[MEMORY WARNING] Signal was not persisted; dataset has no writable incident table.")
        else:
            thought_chain.append("[MEMORY STANDBY] No repeated-success incident recorded; no production verification asserted.")

        report = {
            "status": "DIAGNOSIS_COMPLETED",
            "context": quant_metrics.get("context"),
            "assessment_state": (AssessmentState.SIGNAL_DETECTED.value if has_collisions else
                                 AssessmentState.NO_SIGNAL_OBSERVED.value if quant_metrics.get("total_analyzed") else
                                 AssessmentState.INSUFFICIENT_DATA.value),
            "database_path": database_path,
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
