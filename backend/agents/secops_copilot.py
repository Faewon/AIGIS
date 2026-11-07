"""
AIGIS SecOps Copilot Agent
Directly adapted from ARIA's Operator Q&A Architecture:
- Natural-language conversational interface for SecOps and incident response teams
- Directly reads live operational telemetry, Sentinel drift forecasts, and Incident Memory KB
- Autonomous Investigator Handoff (ask_investigator): When an operator asks deep diagnostic questions,
  Copilot delegates to DeepQuantInvestigator, runs the sandbox RCA, and delivers an executive verdict
- Translates technical vulnerabilities into actionable SecOps Work Orders and mitigation checklists
"""

import time
import json
from typing import Dict, Any, List, Optional

try:
    from ..database import get_connection, get_incident_memory, get_policy_rules, DB_PATH
    from ..llm_engine import global_llm_engine
    from .fintech_sentinel import global_fintech_sentinel
    from .quant_investigator import global_quant_investigator
except (ImportError, ModuleNotFoundError):
    try:
        from database import get_connection, get_incident_memory, get_policy_rules, DB_PATH
        from llm_engine import global_llm_engine
        from fintech_sentinel import global_fintech_sentinel
        from quant_investigator import global_quant_investigator
    except (ImportError, ModuleNotFoundError):
        from backend.database import get_connection, get_incident_memory, get_policy_rules, DB_PATH
        from backend.llm_engine import global_llm_engine
        from backend.agents.fintech_sentinel import global_fintech_sentinel
        from backend.agents.quant_investigator import global_quant_investigator


class SecOpsCopilotAgent:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.agent_name = "AI Assistant"
        self.agent_role = "Autonomous Security Operations Assistant & Handoff Coordinator"
        self.system_prompt = (
            "You are the AI Assistant in the AIGIS FinTech Security Platform, inspired by ARIA's Q&A agent. "
            "You help security operators understand real-time telemetry anomalies, explain Sentinel status, "
            "trigger deep quant investigations in the Python sandbox, and formulate SecOps Work Orders. "
            "Answer clearly and concisely in professional English with Markdown formatting."
        )

    async def answer_query(self, query: str) -> Dict[str, Any]:
        """
        Process operator query and coordinate handoff if needed:
        1. Intent Classification
        2. Real-time telemetry, Sentinel, and Incident Memory KB lookup
        3. Delegation (Handoff) to Deep Quant Investigator if micro-diagnostic needed
        4. Return clean, structured English Markdown response with recommended actions
        """
        q = query.lower().strip()
        t0 = time.time()
        
        handoff_invoked = False
        investigator_data = None
        suggested_actions = []
        reply = ""

        # 1. INTENT: Deep Anomaly Diagnosis / TOCTOU Investigation (Triggers Handoff)
        if any(k in q for k in ["chẩn đoán", "chan doan", "điều tra", "dieu tra", "investigate", "investigation", "rca", "gốc rễ", "goc re", "toctou", "race condition", "xung đột", "xung dot", "dirty read", "diagnose", "diagnosis", "root cause", "exploit"]):
            handoff_invoked = True
            inv_report = await global_quant_investigator.diagnose_anomaly(target_endpoint="/api/v1/voucher/claim")
            investigator_data = inv_report
            rca = inv_report.get("root_cause_analysis", {})
            qm = inv_report.get("quantitative_metrics", {})

            reply = (
                f"**Deep Investigation Results from Deep Quant Investigator (Sandbox Python):**\n\n"
                f"- **Target Endpoint**: `{inv_report.get('target_endpoint')}`\n"
                f"- **Threat Classification**: `{inv_report.get('threat_type')}`\n"
                f"- **Micro Vulnerability Gap**: **{rca.get('vulnerability_gap_ms', 1.45):.2f}ms** (Minimum observed: **{rca.get('min_observed_gap_ms', 0.42):.2f}ms**)\n"
                f"- **Dirty Read Probability**: **{rca.get('dirty_read_probability', 0.933)*100:.1f}%** ({qm.get('dirty_read_count', 14)}/{qm.get('total_analyzed', 15)} burst requests bypassed balance check)\n"
                f"- **Estimated Capital Exposure**: **${rca.get('capital_loss_usd', 7500.0):,.2f}** per burst exploit\n\n"
                f"> **Root Cause Analysis (RCA) Verdict:** {rca.get('rca_summary')}\n\n"
                f"**Verified Defense Patch:** {rca.get('remediation_patch')}"
            )
            suggested_actions = [
                {"label": "Generate Remediation Work Order", "action": "open_work_order"},
                {"label": "Handoff to Aegis Blue Team", "action": "trigger_blue_patch"},
                {"label": "View Executed Sandbox Python Code", "action": "view_investigator_code"}
            ]

        # 2. INTENT: Sentinel Status & System Health
        elif any(k in q for k in ["tấn công", "tan cong", "sentinel", "trạng thái", "trang thai", "sức khỏe", "suc khoe", "health", "drift", "bình thường", "binh thuong", "attack", "status", "normal", "under attack", "posture"]):
            sent_status = global_fintech_sentinel.get_status().get("current_state", {})
            verdict = sent_status.get("verdict", "NORMAL")
            tps = sent_status.get("tps", 10.0)
            fc30 = sent_status.get("tail_forecast_t30", 10.0)
            derivative = sent_status.get("velocity_derivative", 0.0)
            reason = sent_status.get("reason", "")

            # Context evaluation
            reason_en = reason
            if "nominal" in reason.lower():
                reason_en = "System operating within nominal safety thresholds; no micro-concurrency collisions or anomalous exploit patterns detected."
            elif "surge" in reason.lower() and "flash sale" in reason.lower():
                reason_en = "Transaction traffic surging, but Contextual Filter confirms active authorized Flash Sale with dispersed residential IPs. Sentinel standing down to prevent false positive customer blocks."
            elif "concurrency clustering" in reason.lower() or "exploit" in reason.lower():
                reason_en = "Sub-millisecond concurrency collision cluster detected. High probability of active TOCTOU race exploit or Sybil bot attack. Recommending autonomous handoff to Deep Investigator."

            reply = (
                f"**Real-Time Monitoring Report from FinTech Sentinel:**\n\n"
                f"- **Current Sentinel Verdict**: **{sent_status.get('verdict_badge', verdict)}**\n"
                f"- **Real-Time Throughput**: **{tps} tx/s** (Velocity Derivative: `{derivative:+.2f} tx/s^2`)\n"
                f"- **Tail Forecast (t+30s)**: **{fc30} tx/s**\n"
                f"- **User Diversity Entropy**: **{sent_status.get('user_entropy', 0.95)*100:.1f}%**\n"
                f"- **Datacenter Proxy Ratio**: **{sent_status.get('proxy_ratio', 0.02)*100:.1f}%**\n"
                f"- **Sub-50ms Concurrency Collisions**: **{sent_status.get('concurrency_clusters', 0)} collisions**\n\n"
                f"> **Contextual Evaluation:** {reason_en}"
            )
            suggested_actions = [
                {"label": "Inspect Flash Sale Policies", "action": "view_policies"},
                {"label": "Run Deep Diagnostic with Investigator", "action": "run_investigator"},
                {"label": "Open Sentinel Monitor", "action": "open_sentinel_modal"}
            ]

        # 3. INTENT: Incident Memory & Past Failures
        elif any(k in q for k in ["sự cố", "su co", "quá khứ", "qua khu", "lịch sử", "lich su", "incident", "memory", "kb", "cve", "history", "past"]):
            incidents = get_incident_memory(limit=5)
            inc_lines = []
            for inc in incidents:
                inc_lines.append(
                    f"- **{inc.get('incident_id')}** [{inc.get('threat_type')}] — Capital Exposure: **${inc.get('financial_loss', 0):,.2f}** | Status: `{inc.get('status')}`\n"
                    f"  *RCA*: {inc.get('rca_summary')[:100]}...\n"
                    f"  *Patch*: `{inc.get('remediation_patch')[:80]}...`"
                )

            reply = (
                f"**Incident History & Past Remediation in Incident Memory KB ({len(incidents)} records):**\n\n"
                + "\n\n".join(inc_lines) + "\n\n"
                f"The system automatically correlates these historical incidents whenever Sentinel detects telemetry drift to reuse proven defense patches."
            )
            suggested_actions = [
                {"label": "View Incident Memory Details", "action": "open_memory_tab"},
                {"label": "Diagnose Current Vulnerability", "action": "run_investigator"}
            ]

        # 4. INTENT: Policy Rules / Flash Sale
        elif any(k in q for k in ["chính sách", "chinh sach", "quy tắc", "quy tac", "flash sale", "khuyến mãi", "khuyen mai", "policy", "policies", "rule", "rules", "stand-down"]):
            policies = get_policy_rules()
            pol_lines = []
            for p in policies:
                pol_lines.append(
                    f"- **{p.get('rule_id')}** ({p.get('name')}): `{p.get('rule_type')}` on `{p.get('endpoint')}`\n"
                    f"  Threshold: **{p.get('threshold_value')}** | Status: **{'ACTIVE' if p.get('is_active') == 1 else 'DISABLED'}**\n"
                    f"  *Description*: {p.get('description')}"
                )

            reply = (
                f"**Contextual Control Rules & Flash Sale Windows ({len(policies)} rules):**\n\n"
                + "\n\n".join(pol_lines) + "\n\n"
                f"Sentinel utilizes these rules to execute Contextual Stand-Down, preventing false alarms during legitimate promotional flash sale windows."
            )
            suggested_actions = [
                {"label": "Toggle Sentinel Policies", "action": "open_policies_tab"},
                {"label": "Simulate Flash Sale Event", "action": "simulate_flash_sale"}
            ]

        # 5. INTENT: Work Order Generation
        elif any(k in q for k in ["work order", "phiếu", "phieu", "khắc phục", "khac phuc", "canary", "rollout", "lệnh sửa", "lenh sua", "remediation", "patch"]):
            reply = (
                f"**SecOps Technical Intervention Work Order:**\n\n"
                f"- **Work Order ID**: `WO-2026-0814` (Priority: `P0_CRITICAL`)\n"
                f"- **Affected Component**: `/api/v1/voucher/claim` (Loyalty & Checkout Microservice)\n"
                f"- **Proposed Patch**: Redis Distributed Mutex (`lock_ttl = 3.0s`) on key `lock:voucher:{{user_id}}`\n"
                f"- **Canary Rollout Specification**:\n"
                f"  1. Stage 1: 5% canary traffic for 15 minutes (Latency delta <= 2ms, 0 False Positives)\n"
                f"  2. Stage 2: 25% traffic allocation if HTTP 500 error rate = 0.00%\n"
                f"  3. Stage 3: 100% full production cluster deployment\n"
                f"- **Automated Rollback Criteria**: P99 latency exceeds 45ms or HTTP 500 error rate > 0.05%."
            )
            suggested_actions = [
                {"label": "Open Work Order View", "action": "open_work_order"},
                {"label": "Run Zero-Regression Test", "action": "trigger_regression_test"}
            ]

        # 6. Default / Fallback Response
        else:
            llm_status = global_llm_engine.get_status()
            if llm_status.get("mode") == "API_CONNECTED":
                try:
                    sent_status = global_fintech_sentinel.get_status().get("current_state", {})
                    context = (
                        f"Current Sentinel verdict: {sent_status.get('verdict')}, TPS: {sent_status.get('tps')}. "
                        "You are AIGIS AI Assistant. Answer concisely in professional English with Markdown formatting."
                    )
                    reply = await global_llm_engine.call_llm(self.system_prompt, f"Context: {context}\n\nUser Question: {query}")
                except Exception:
                    pass

            if not reply:
                reply = (
                    f"I am the **AI Assistant** for the AIGIS FinTech platform. I can assist you with:\n\n"
                    f"1. **System Health & Anomaly Check**: Ask *'Is the system under attack?'* to inspect Sentinel's verdict.\n"
                    f"2. **Root Cause Analysis (RCA)**: Ask *'Diagnose TOCTOU vulnerability'* to trigger autonomous Python sandbox computation.\n"
                    f"3. **Incident Memory KB**: Ask *'Show incident history'* to retrieve past exploit signatures and verified patches.\n"
                    f"4. **Flash Sale Policies**: Ask *'View policy rules'* to review Contextual Stand-Down filters.\n"
                    f"5. **SecOps Work Order**: Ask *'Generate Work Order'* to review the 3-stage canary rollout plan."
                )
            suggested_actions = [
                {"label": "Is the system under attack?", "action": "ask_system_health"},
                {"label": "Diagnose TOCTOU vulnerability", "action": "ask_investigate_toctou"},
                {"label": "View Incident Memory history", "action": "ask_view_history"}
            ]

        elapsed_ms = round((time.time() - t0) * 1000.0, 1)

        return {
            "query": query,
            "reply": reply,
            "handoff_invoked": handoff_invoked,
            "investigator_data": investigator_data,
            "suggested_actions": suggested_actions,
            "latency_ms": elapsed_ms
        }


global_secops_copilot = SecOpsCopilotAgent()
