"""
AIGIS SecOps Work Order Generator Agent
Directly adapted from ARIA's Work Order Generator Architecture:
- Translates Root Cause Analysis (RCA) and Blue Team patches into production engineering tickets
- Configures exact Redis Distributed Lock parameters (SET NX, 3.0s lease TTL, key patterns)
- Formulates multi-phase Canary Rollout matrices (5% -> 25% -> 100%) with SLA health gates
- Enforces automated rollback trigger criteria (P99 latency > 45ms, HTTP 500 > 0.05%)
"""

import time
import uuid
from typing import Dict, Any, List, Optional

from backend.agents.quant_investigator import global_quant_investigator


class SecOpsWorkOrderGenerator:
    def __init__(self):
        self.agent_name = "Work Order Generator"
        self.agent_role = "Autonomous Incident Ticket & Canary Rollout Orchestrator"
        self.current_ticket: Optional[Dict[str, Any]] = None

    def generate_work_order(
        self,
        target_endpoint: str = "/api/v1/voucher/claim",
        threat_type: str = "TOCTOU_RACE_CONDITION",
        inv_report: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Tong hop phieu can thiep ky thuat SecOps Work Order tu ket qua RCA"""
        import re
        now = time.time()
        ticket_id = f"WO-{uuid.uuid4().hex}"

        if not re.fullmatch(r"/[A-Za-z0-9_./:-]{1,120}", target_endpoint or ""):
            target_endpoint = "/api/v1/voucher/claim"
        if not re.fullmatch(r"[A-Z0-9_]{1,80}", threat_type or ""):
            threat_type = "TOCTOU_RACE_CONDITION"

        report = inv_report or global_quant_investigator.latest_report or {}
        from backend.evidence import dataset_identity
        from backend.database import get_active_db_path
        context = report.get("context")
        if (report.get("target_endpoint") != target_endpoint or
            context and context.get("dataset_revision") != dataset_identity(get_active_db_path()).dataset_revision):
            report = {}
        rca = report.get("root_cause_analysis", {}) or {}
        qm = report.get("quantitative_metrics", {}) or {}

        gap_ms = rca.get("vulnerability_gap_ms")
        stolen = rca.get("capital_loss_usd")
        dirty_ratio = rca.get("dirty_read_probability")
        incident_id = report.get("incident_id") or None

        ticket = {
            "ticket_id": ticket_id,
            "context": report.get("context"),
            "assessment_state": report.get("assessment_state", "NOT_ASSESSED"),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "DRAFT_PENDING_APPROVAL",
            "priority": "P0_CRITICAL" if stolen else "UNASSESSED",
            "target_service": "loyalty-checkout-service",
            "target_endpoint": target_endpoint,
            "threat_classification": threat_type,
            "incident_reference": incident_id,
            "quantitative_findings": {
                "vulnerability_gap_ms": gap_ms,
                "dirty_read_rate_pct": round(dirty_ratio * 100, 1) if dirty_ratio is not None else None,
                "stolen_per_burst_usd": stolen,
                "daily_exposure_defended_usd": None,
                "note": "Values are taken from the RCA report; missing measurements are reported as null."
            },
            "middleware_patch_spec": {
                "class_name": "RedisIdempotencyMiddleware",
                "lock_type": "REDIS_SETNX_DISTRIBUTED_MUTEX",
                "lock_key_pattern": "aigis:lock:claim:{user_id}",
                "lease_ttl_sec": 3.0,
                "retry_backoff_ms": 50,
                "max_retries": 3,
                "idempotency_header": "X-Idempotency-Key",
                "failure_action": "HTTP 429 TOO MANY REQUESTS"
            },
            "canary_rollout_matrix": [
                {
                    "stage": 1,
                    "traffic_pct": 5,
                    "window_minutes": 15,
                    "health_gate": "P99 latency overhead <= 2.0ms and 0 false positives",
                    "status": "PENDING"
                },
                {
                    "stage": 2,
                    "traffic_pct": 25,
                    "window_minutes": 30,
                    "health_gate": "HTTP 500 error rate == 0.00% across 5,000 requests",
                    "status": "PENDING"
                },
                {
                    "stage": 3,
                    "traffic_pct": 100,
                    "window_minutes": 0,
                    "health_gate": "Full cluster deployment and zero exploit bypass",
                    "status": "PENDING"
                }
            ],
            "rollback_triggers": [
                "P99 latency degradation exceeds 45ms",
                "HTTP 500 internal server error rate > 0.05%",
                "False positive customer purchase blocking > 0 transactions"
            ],
            "signoff_checklist": {
                "architecture_review": "NOT_ASSESSED",
                "zero_regression_verified": "NOT_VERIFIED_IN_THIS_DEMO",
                "executive_approval": "NOT_APPROVED"
            }
        }

        self.current_ticket = ticket
        return ticket

    def simulate_rollout(self) -> Dict[str, Any]:
        """Preview a canary rollout. This method does not deploy or measure production."""
        if not self.current_ticket:
            self.generate_work_order()

        ticket = self.current_ticket
        for stage in ticket["canary_rollout_matrix"]:
            stage["status"] = "SIMULATED_PENDING_APPROVAL"

        ticket["status"] = "SIMULATED_ROLLOUT_PREVIEW"
        ticket["deployed_at"] = None

        return {
            "success": True,
            "simulated": True,
            "status": "SIMULATED_ROLLOUT_PREVIEW",
            "ticket": ticket,
            "verification_summary": {
                "stage1_canary_5pct": "Not executed; simulation preview only.",
                "stage2_canary_25pct": "Not executed; simulation preview only.",
                "stage3_full_100pct": "Not executed; no production traffic was modified.",
                "total_stolen_prevented_usd": None,
                "regressions_detected": None
            }
        }


global_work_order_generator = SecOpsWorkOrderGenerator()
