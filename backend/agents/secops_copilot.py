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
        self.agent_name = "SecOps Copilot"
        self.agent_role = "Autonomous Security Operations Copilot & Handoff Coordinator"
        self.system_prompt = (
            "You are the SecOps Copilot in the AIGIS FinTech Security Platform, inspired by ARIA's Q&A agent. "
            "You help security operations teams understand system health, telemetry drift, past incident memory, "
            "and business logic vulnerabilities. When questions require deep mathematical diagnosis, you autonomously "
            "hand off the task to the Deep Quant Investigator and explain the findings in crisp, executive Vietnamese with full diacritics."
        )

    async def answer_query(self, query: str) -> Dict[str, Any]:
        """
        Xử lý câu hỏi của Operator và điều phối handoff nếu cần thiết:
        1. Nhận diện ý định (Intent Classification)
        2. Truy vấn thông tin thời gian thực từ Sentinel, KB và Telemetry
        3. Ủy quyền (Handoff) cho Deep Quant Investigator nếu cần chẩn đoán vi mô
        4. Trả về phản hồi trực quan bằng Tiếng Việt có dấu đầy đủ và gợi ý hành động
        """
        q = query.lower().strip()
        t0 = time.time()
        
        handoff_invoked = False
        investigator_data = None
        suggested_actions = []
        reply = ""

        # 1. INTENT: Deep Anomaly Diagnosis / TOCTOU Investigation (Triggers Handoff)
        if any(k in q for k in ["chẩn đoán", "chan doan", "điều tra", "dieu tra", "investigate", "rca", "gốc rễ", "goc re", "toctou", "race condition", "xung đột", "xung dot", "dirty read"]):
            handoff_invoked = True
            inv_report = await global_quant_investigator.diagnose_anomaly(target_endpoint="/api/v1/voucher/claim")
            investigator_data = inv_report
            rca = inv_report.get("root_cause_analysis", {})
            qm = inv_report.get("quantitative_metrics", {})

            reply = (
                f"**Kết quả Điều tra Chuyên sâu từ Deep Quant Investigator (Sandbox Python):**\n\n"
                f"- **Mục tiêu phân tích**: `{inv_report.get('target_endpoint')}`\n"
                f"- **Phân loại lỗ hổng**: `{inv_report.get('threat_type')}`\n"
                f"- **Cửa sổ lỗ hổng vi mô (Vulnerability Gap)**: **{rca.get('vulnerability_gap_ms', 1.45):.2f}ms** (Nhỏ nhất: **{rca.get('min_observed_gap_ms', 0.42):.2f}ms**)\n"
                f"- **Xác suất Dirty Read**: **{rca.get('dirty_read_probability', 0.933)*100:.1f}%** ({qm.get('dirty_read_count', 14)}/{qm.get('total_analyzed', 15)} yêu cầu trong đợt burst vượt qua kiểm tra số dư)\n"
                f"- **Thiệt hại dòng tiền ước tính**: **${rca.get('capital_loss_usd', 7500.0):,.2f}** mỗi đợt tấn công\n\n"
                f"> **Kết luận Nguyên nhân Gốc rễ (RCA):** {rca.get('rca_summary')}\n\n"
                f"**Giải pháp phòng thủ đã xác minh:** {rca.get('remediation_patch')}"
            )
            suggested_actions = [
                {"label": "Lập phiếu Work Order khắc phục", "action": "open_work_order"},
                {"label": "Chuyển Blue Team Aegis vá lỗi", "action": "trigger_blue_patch"},
                {"label": "Xem mã Python đã thực thi", "action": "view_investigator_code"}
            ]

        # 2. INTENT: Sentinel Status & System Health
        elif any(k in q for k in ["tấn công", "tan cong", "sentinel", "trạng thái", "trang thai", "sức khỏe", "suc khoe", "health", "drift", "bình thường", "binh thuong"]):
            sent_status = global_fintech_sentinel.get_status().get("current_state", {})
            verdict = sent_status.get("verdict", "NORMAL")
            tps = sent_status.get("tps", 10.0)
            fc30 = sent_status.get("tail_forecast_t30", 10.0)
            derivative = sent_status.get("velocity_derivative", 0.0)
            reason = sent_status.get("reason", "")

            # Translate reason to proper Vietnamese if in English
            reason_vn = reason
            if "nominal" in reason.lower():
                reason_vn = "Hệ thống đang vận hành trong giới hạn an toàn danh định, không phát hiện xung đột vi mô hay dấu hiệu tấn công bất thường."
            elif "surge" in reason.lower() and "flash sale" in reason.lower():
                reason_vn = "Lưu lượng giao dịch tăng vọt nhưng Bộ lọc Ngữ cảnh xác nhận đang trong khung giờ Flash Sale hợp lệ với người dùng phân tán và IP dân cư sạch. Sentinel đứng yên (Stand-Down) để tránh chặn nhầm khách hàng."
            elif "concurrency clustering" in reason.lower() or "exploit" in reason.lower():
                reason_vn = "Phát hiện cụm giao dịch xung đột dưới mili-giây (sub-millisecond clustering). Nguy cơ cao xảy ra tấn công đua lệnh TOCTOU hoặc Sybil bot. Khuyến nghị ủy quyền cho Deep Investigator xử lý khẩn cấp."

            reply = (
                f"**Báo cáo Giám sát Thời gian thực từ FinTech Sentinel:**\n\n"
                f"- **Phán quyết Sentinel hiện tại**: **{sent_status.get('verdict_badge', verdict)}**\n"
                f"- **Tốc độ giao dịch thời gian thực**: **{tps} tx/s** (Đạo hàm vận tốc: `{derivative:+.2f} tx/s^2`)\n"
                f"- **Dự báo đuôi tín hiệu (t+30s)**: **{fc30} tx/s**\n"
                f"- **Độ đa dạng người dùng (Entropy)**: **{sent_status.get('user_entropy', 0.95)*100:.1f}%**\n"
                f"- **Tỷ lệ Proxy Datacenter**: **{sent_status.get('proxy_ratio', 0.02)*100:.1f}%**\n"
                f"- **Xung đột sub-50ms**: **{sent_status.get('concurrency_clusters', 0)} va chạm**\n\n"
                f"> **Đánh giá ngữ cảnh:** {reason_vn}"
            )
            suggested_actions = [
                {"label": "Kiểm tra chu kỳ Flash Sale", "action": "view_policies"},
                {"label": "Chạy chẩn đoán sâu với Investigator", "action": "run_investigator"},
                {"label": "Mở bảng giám sát Sentinel", "action": "open_sentinel_modal"}
            ]

        # 3. INTENT: Incident Memory & Past Failures
        elif any(k in q for k in ["sự cố", "su co", "quá khứ", "qua khu", "lịch sử", "lich su", "incident", "memory", "kb", "cve"]):
            incidents = get_incident_memory(limit=5)
            inc_lines = []
            for inc in incidents:
                inc_lines.append(
                    f"- **{inc.get('incident_id')}** [{inc.get('threat_type')}] — Thiệt hại: **${inc.get('financial_loss', 0):,.2f}** | Trạng thái: `{inc.get('status')}`\n"
                    f"  *RCA*: {inc.get('rca_summary')[:100]}...\n"
                    f"  *Bản vá*: `{inc.get('remediation_patch')[:80]}...`"
                )

            reply = (
                f"**Lịch sử Sự cố và Bản vá trong Incident Memory KB ({len(incidents)} bản ghi):**\n\n"
                + "\n\n".join(inc_lines) + "\n\n"
                f"Hệ thống tự động đối chiếu các sự cố này khi Sentinel phát hiện bất thường để tái sử dụng giải pháp phòng ngự đã được chứng minh."
            )
            suggested_actions = [
                {"label": "Kiểm tra chi tiết Incident Memory", "action": "open_memory_tab"},
                {"label": "Chẩn đoán lỗ hổng hiện tại", "action": "run_investigator"}
            ]

        # 4. INTENT: Policy Rules / Flash Sale
        elif any(k in q for k in ["chính sách", "chinh sach", "quy tắc", "quy tac", "flash sale", "khuyến mãi", "khuyen mai", "policy", "stand-down"]):
            policies = get_policy_rules()
            pol_lines = []
            for p in policies:
                pol_lines.append(
                    f"- **{p.get('rule_id')}** ({p.get('name')}): `{p.get('rule_type')}` trên `{p.get('endpoint')}`\n"
                    f"  Ngưỡng cho phép: **{p.get('threshold_value')}** | Trạng thái: **{'ACTIVE (ĐANG BẬT)' if p.get('is_active') == 1 else 'DISABLED (TẮT)'}**\n"
                    f"  *Mô tả*: {p.get('description')}"
                )

            reply = (
                f"**Danh mục Quy tắc Kiểm soát Ngữ cảnh & Cửa sổ Flash Sale ({len(policies)} quy tắc):**\n\n"
                + "\n\n".join(pol_lines) + "\n\n"
                f"Sentinel sử dụng các quy tắc này để thực hiện Contextual Stand-Down, không phát báo động giả trong khung giờ Flash Sale hợp lệ."
            )
            suggested_actions = [
                {"label": "Bật/Tắt quy tắc Sentinel", "action": "open_policies_tab"},
                {"label": "Giả lập đợt Flash Sale", "action": "simulate_flash_sale"}
            ]

        # 5. INTENT: Work Order Generation
        elif any(k in q for k in ["work order", "phiếu", "phieu", "khắc phục", "khac phuc", "canary", "rollout", "lệnh sửa", "lenh sua"]):
            reply = (
                f"**Phiếu Điều phối Can thiệp Kỹ thuật (SecOps Work Order):**\n\n"
                f"- **Mã phiếu**: `WO-2026-0814` (Mức độ ưu tiên: `P0_CRITICAL`)\n"
                f"- **Thành phần ảnh hưởng**: `/api/v1/voucher/claim` (Loyalty & Checkout Microservice)\n"
                f"- **Bản vá đề xuất**: Redis Distributed Mutex (`lock_ttl = 3.0s`) trên key `lock:voucher:{{user_id}}`\n"
                f"- **Quy trình Canary Rollout**:\n"
                f"  1. Giai đoạn 1: 5% lưu lượng canary trong 15 phút (Độ trễ tăng thêm <= 2ms, 0 False Positives)\n"
                f"  2. Giai đoạn 2: 25% lưu lượng nếu tỷ lệ lỗi HTTP 500 = 0.00%\n"
                f"  3. Giai đoạn 3: 100% toàn bộ cụm máy chủ production\n"
                f"- **Tiêu chí Rollback tự động**: Độ trễ P99 vượt quá 45ms hoặc tỷ lệ lỗi HTTP 500 > 0.05%."
            )
            suggested_actions = [
                {"label": "Mở giao diện Work Order", "action": "open_work_order"},
                {"label": "Chạy kiểm thử Zero-Regression", "action": "trigger_regression_test"}
            ]

        # 6. Default / Fallback Response
        else:
            llm_status = global_llm_engine.get_status()
            if llm_status.get("mode") == "API_CONNECTED":
                try:
                    sent_status = global_fintech_sentinel.get_status().get("current_state", {})
                    context = (
                        f"Current Sentinel verdict: {sent_status.get('verdict')}, TPS: {sent_status.get('tps')}. "
                        "You are AIGIS SecOps Copilot. Answer concisely in Vietnamese with full accents."
                    )
                    reply = await global_llm_engine.call_llm(self.system_prompt, f"Context: {context}\n\nUser Question: {query}")
                except Exception:
                    pass

            if not reply:
                reply = (
                    f"Tôi là **SecOps Copilot** của nền tảng AIGIS. Tôi có thể hỗ trợ bạn:\n\n"
                    f"1. **Kiểm tra sức khỏe hệ thống**: Hỏi *'Hệ thống có đang bị tấn công không?'* để xem phán quyết Sentinel.\n"
                    f"2. **Chẩn đoán gốc rễ (RCA)**: Hỏi *'Chẩn đoán lỗ hổng TOCTOU'* để tôi ủy quyền cho Deep Quant Investigator lập trình Python tính toán vi mô trong sandbox.\n"
                    f"3. **Lịch sử sự cố**: Hỏi *'Xem lịch sử sự cố trong Incident Memory'* để tra cứu các lỗ hổng và bản vá đã lưu.\n"
                    f"4. **Chính sách Flash Sale**: Hỏi *'Xem quy tắc khuyến mãi'* để kiểm tra bộ lọc Contextual Stand-Down.\n"
                    f"5. **Xuất Work Order**: Hỏi *'Tạo phiếu Work Order khắc phục'* để xem quy trình canary rollout 3 giai đoạn."
                )
            suggested_actions = [
                {"label": "Hệ thống có bị tấn công không?", "action": "ask_system_health"},
                {"label": "Chẩn đoán chuyên sâu lỗ hổng TOCTOU", "action": "ask_investigate_toctou"},
                {"label": "Xem lịch sử Incident Memory", "action": "ask_view_history"}
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
