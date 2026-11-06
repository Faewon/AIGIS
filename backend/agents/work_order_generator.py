"""
AIGIS SecOps Work Order Generator Agent
Directly adapted from ARIA's Work Order Generator Architecture:
- Translates Root Cause Analysis (RCA) and Blue Team patches into production engineering tickets
- Configures exact Redis Distributed Lock parameters (SET NX, 3.0s lease TTL, key patterns)
- Formulates multi-phase Canary Rollout matrices (5% -> 25% -> 100%) with SLA health gates
- Enforces automated rollback trigger criteria (P99 latency > 45ms, HTTP 500 > 0.05%)
"""

import time
from typing import Dict, Any, List, Optional

try:
    from .quant_investigator import global_quant_investigator
except (ImportError, ModuleNotFoundError):
    try:
        from quant_investigator import global_quant_investigator
    except (ImportError, ModuleNotFoundError):
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
        now = time.time()
        ticket_id = f"WO-2026-{int(now) % 10000:04d}"
        
        report = inv_report or global_quant_investigator.latest_report or {}
        rca = report.get("root_cause_analysis", {})
        qm = report.get("quantitative_metrics", {})

        gap_ms = rca.get("vulnerability_gap_ms", 1.45)
        stolen = rca.get("capital_loss_usd", 7500.0)
        dirty_ratio = rca.get("dirty_read_probability", 0.933)

        ticket = {
            "ticket_id": ticket_id,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "READY_FOR_CANARY",
            "priority": "P0_CRITICAL",
            "target_service": "loyalty-checkout-service",
            "target_endpoint": target_endpoint,
            "threat_classification": threat_type,
            "incident_reference": report.get("incident_id", "INC-2026-001"),
            "quantitative_findings": {
                "vulnerability_gap_ms": gap_ms,
                "dirty_read_rate_pct": round(dirty_ratio * 100, 1),
                "stolen_per_burst_usd": stolen,
                "daily_exposure_defended_usd": 150000.0
            },
            "middleware_patch_spec": {
                "class_name": "RedisIdempotencyMiddleware",
                "lock_type": "REDIS_SETNX_DISTRIBUTED_MUTEX",
                "lock_key_pattern": "lock:voucher:{user_id}",
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
                    "health_gate": "P99 Latency Overhead <= 2.0ms and 0 False Positives",
                    "status": "PENDING"
                },
                {
                    "stage": 2,
                    "traffic_pct": 25,
                    "window_minutes": 30,
                    "health_gate": "HTTP 500 Error Rate == 0.00% across 5,000 requests",
                    "status": "PENDING"
                },
                {
                    "stage": 3,
                    "traffic_pct": 100,
                    "window_minutes": 0,
                    "health_gate": "Full cluster production deployment and zero exploit bypass",
                    "status": "PENDING"
                }
            ],
            "rollback_triggers": [
                "P99 latency degradation exceeds 45ms",
                "HTTP 500 internal server error rate > 0.05%",
                "False positive customer purchase blocking > 0 transactions"
            ],
            "signoff_checklist": {
                "architecture_review": "PASSED (Zero Single Point of Failure via Redis Sentinel/Cluster)",
                "zero_regression_verified": "PASSED (50 simulated authentic customers completed with +1.4ms latency)",
                "executive_approval": "APPROVED BY ARBITER"
            }
        }

        self.current_ticket = ticket
        return ticket

    def simulate_rollout(self) -> Dict[str, Any]:
        """Mo phong qua trinh trien khai canary 3 giai doan khong gay loi (Zero-Regression)"""
        if not self.current_ticket:
            self.generate_work_order()

        ticket = self.current_ticket
        # Advance stages
        for stage in ticket["canary_rollout_matrix"]:
            stage["status"] = "PASSED_VERIFIED"

        ticket["status"] = "DEPLOYED_PRODUCTION"
        ticket["deployed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

        return {
            "success": True,
            "status": "DEPLOYED_PRODUCTION",
            "ticket": ticket,
            "verification_summary": {
                "stage1_canary_5pct": "Passed: 0 errors, latency +1.2ms",
                "stage2_canary_25pct": "Passed: 0 errors, latency +1.4ms",
                "stage3_full_100pct": "Active: 100% traffic protected with Redis Distributed Mutex",
                "total_stolen_prevented_usd": 150000.0,
                "regressions_detected": 0
            }
        }


global_work_order_generator = SecOpsWorkOrderGenerator()
