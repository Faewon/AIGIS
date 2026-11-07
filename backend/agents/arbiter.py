from typing import Dict, Any, Optional
from ..llm_engine import global_llm_engine

class ArenaArbiterAgent:
    """
    Agent 5: Arena Arbiter (Trọng tài Đấu trường & Lập Hồ sơ Tuân thủ)
    Sử dụng ReAct Agent Loop & Dynamic Actuarial Scoring Engine:
    - Thought: So sánh chỉ số tấn công và kết quả phòng thủ của Blue Team.
    - Evaluation: Chấm điểm Dynamic Logic Security Score theo mô hình định lượng đa biến.
    - Exposure Analysis: Quy đổi rủi ro thành dòng tiền thiệt hại được cứu vãn ($150,000/ngày).
    - Synthesis: Biên tập Git Pull Request Diff chuẩn xác.
    """

    def __init__(self):
        self.system_prompt = (
            "You are Agent 5 (Compliance Arbiter) in the AIGIS platform. "
            "You are a neutral cyber insurance auditor and compliance arbiter. "
            "You score security posture using rigorous quantitative formulas, "
            "calculate financial exposure saved, and format Git Pull Requests ready for engineering teams."
        )

    def compute_quantified_security_score(
        self,
        attack_report: Optional[Dict[str, Any]] = None,
        patch_report: Optional[Dict[str, Any]] = None,
        regression_report: Optional[Dict[str, Any]] = None,
        retest_report: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Mô hình Định lượng Điểm An toàn Logic Động (Dynamic Business Logic Risk & Security Scoring):
        Điểm = [Nền tảng Baseline] + [Độ toàn vẹn Luồng Nghiệp vụ * Tỷ lệ Chặn]
               - [Phạt Chặn nhầm Khách thật (False Positive)]
               - [Phạt Suy giảm Độ trễ (Latency Overhead)]
               - [Phạt Rủi ro Kiến trúc Tồn dư (Residual Architecture Risk: Redis SPOF)]
        """
        attack = attack_report or {}
        retest = retest_report or {}
        regression = regression_report or {}
        score_available = bool(attack) and bool(retest)

        burst_count = max(1, int(attack.get("total_burst_count") or attack.get("total_requests") or 1))
        stolen_unpatched = float(attack.get("total_stolen_amount") or 0.0)
        illegal_claims_unpatched = int(attack.get("illegal_claims_count") or 0)

        # 1. Measure unpatched exploit behavior from the sandbox report.
        unpatched_exploit_rate = min(1.0, illegal_claims_unpatched / max(1, burst_count - 1))
        financial_severity_ratio = min(1.0, stolen_unpatched / 10000.0)

        # Demo heuristic: 25-point perimeter baseline + 75-point logic integrity.
        # This is a demo scoring model, not a certified risk assessment.
        base_hygiene = 25.0
        logic_component_initial = round(75.0 * (1.0 - unpatched_exploit_rate), 1)
        financial_deduction = round(10.0 * financial_severity_ratio, 1)

        initial_score = round(max(5.0, base_hygiene + logic_component_initial - financial_deduction), 1)

        # 2. Measure patch effectiveness from the retest report.
        retest_burst = max(1, int(retest.get("total_burst_count") or retest.get("total_requests") or burst_count))
        retest_blocked = int(retest.get("blocked_requests") or 0)
        expected_blocks = max(1, retest_burst - 1)
        mitigation_rate = min(1.0, max(0.0, retest_blocked / expected_blocks)) if retest else 0.0

        # 3. Measure false positives from the regression report.
        sample_users = int(regression.get("sample_users_tested") or 0)
        approved_users = int(regression.get("legitimate_requests_approved") or 0)
        if sample_users > 0:
            fp_rate = max(0.0, (sample_users - approved_users) / sample_users)
            fp_penalty = round(fp_rate * 100.0 * 5.0, 1)
        else:
            fp_rate = None
            fp_penalty = 0.0

        # 4. Measure latency overhead; do not invent a default when absent.
        latency_raw = regression.get("latency_overhead_ms")
        latency_ms = float(latency_raw) if latency_raw is not None else None
        latency_penalty = max(0.0, round((latency_ms - 3.0) * 1.5, 1)) if latency_ms is not None else 0.0

        # 5. Residual architecture risk is not measured by this demo.
        resilience_penalty = 0.0

        logic_component_patched = round(75.0 * mitigation_rate, 1)
        raw_patched = base_hygiene + logic_component_patched - fp_penalty - latency_penalty - resilience_penalty
        patched_score = round(max(5.0, min(99.0, raw_patched)), 1)

        if patched_score >= 90.0:
            posture_rating = "HARDENED (DEMO SCORE)"
            badge_color = "text-emerald-700 bg-emerald-50 border-emerald-300"
        elif patched_score >= 70.0:
            posture_rating = "ADEQUATELY PROTECTED (DEMO SCORE)"
            badge_color = "text-blue-700 bg-blue-50 border-blue-300"
        else:
            posture_rating = "CRITICAL LOGIC RISK (DEMO SCORE)"
            badge_color = "text-rose-700 bg-rose-50 border-rose-300"

        latency_text = f"+{latency_ms:.2f}ms measured" if latency_ms is not None else "not measured"
        fp_text = f"FP Rate: {fp_rate*100:.2f}%" if fp_rate is not None else "FP rate not measured"

        return {
            "score_available": score_available,
            "score_model": "DEMO_HEURISTIC_NOT_CERTIFIED",
            "initial_score": initial_score if score_available else None,
            "patched_score": patched_score if score_available else None,
            "score_delta": round(patched_score - initial_score, 1) if score_available else None,
            "posture_rating": posture_rating if score_available else "NOT ASSESSED",
            "badge_color": badge_color,
            "unpatched_exploit_rate": unpatched_exploit_rate,
            "mitigation_rate": mitigation_rate,
            "fp_penalty": fp_penalty,
            "latency_penalty": latency_penalty,
            "resilience_penalty": resilience_penalty,
            "breakdown": {
                "base_platform_hygiene": f"+{base_hygiene:.1f} pts (demo perimeter baseline assumption)",
                "unpatched_logic_integrity": f"+{logic_component_initial:.1f} / 75.0 pts (measured exploit rate: {unpatched_exploit_rate*100:.1f}%)",
                "financial_exposure_penalty": f"-{financial_deduction:.1f} pts (${stolen_unpatched:,.2f} measured unpatched loss)",
                "patched_logic_mitigation": f"+{logic_component_patched:.1f} / 75.0 pts (blocked {retest_blocked}/{expected_blocks} retest streams)",
                "false_positive_penalty": f"-{fp_penalty:.1f} pts ({fp_text})",
                "latency_sla_penalty": f"-{latency_penalty:.1f} pts ({latency_text} vs 3.0ms demo target)",
                "architectural_resilience_penalty": f"-{resilience_penalty:.1f} pts (not measured in this demo)"
            },
            "formula": "Demo score = Base(25.0) + LogicState(75.0 * MitigationRate) - P_FP - P_Latency - P_Resilience"
        }

    async def generate_dossier(
        self,
        attack_report: Dict[str, Any],
        patch_report: Dict[str, Any],
        regression_report: Dict[str, Any],
        retest_report: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        attack = attack_report or {}
        retest = retest_report or {}
        regression = regression_report or {}

        attack_stolen = float(attack.get("total_stolen_amount") or 0.0)
        retest_stolen = float(retest.get("total_stolen_amount") or 0.0)
        capital_preserved = max(0.0, attack_stolen - retest_stolen)

        scoring = self.compute_quantified_security_score(
            attack_report=attack_report,
            patch_report=patch_report,
            regression_report=regression_report,
            retest_report=retest_report
        )
        initial_score = scoring["initial_score"]
        patched_score = scoring["patched_score"]
        score_before_text = initial_score if initial_score is not None else "N/A"
        score_after_text = patched_score if patched_score is not None else "N/A"

        retest_neutralized = retest.get("status") == "EXPLOIT_NEUTRALIZED"
        compliance_status = "VERIFIED_IN_MOCK_TARGET" if retest_neutralized else "NOT_VERIFIED"

        thought_chain = []
        thought_chain.append("[THOUGHT 1] Collecting multi-agent artifacts: recon, sandbox attack, patch, retest, and regression reports.")
        thought_chain.append(
            f"[QUANTITATIVE AUDIT] Demo security score: {score_before_text} -> {score_after_text} / 100. "
            f"Measured unpatched loss: ${attack_stolen:,.2f}; retest loss: ${retest_stolen:,.2f}."
        )
        thought_chain.append(
            f"[FINANCIAL QUANTIFICATION] Measured capital preserved in this retest event: ${capital_preserved:,.2f}. "
            "No daily-loss projection is asserted by this demo."
        )
        thought_chain.append(
            f"[POST-DEFENSE AUDIT] Mitigation rate {scoring['mitigation_rate']*100:.1f}%; "
            f"regression penalty {scoring['fp_penalty']:.1f}; latency penalty {scoring['latency_penalty']:.1f}."
        )
        thought_chain.append(
            f"[DYNAMIC POSTURE] Rating: {scoring['posture_rating']}. "
            "Scores are heuristic demo outputs, not a certification or audit result."
        )

        llm_status = global_llm_engine.get_status()

        git_diff = """diff --git a/app/middleware/idempotency.py b/app/middleware/idempotency.py
new file mode 100644
index 0000000..8a91b2c
--- /dev/null
+++ b/app/middleware/idempotency.py
@@ -0,0 +1,35 @@
+# Auto-generated reference patch (demo; review before production use)
+# Fixes: concurrent business-logic race on /api/v1/voucher/claim
+from fastapi import Request
+from fastapi.responses import JSONResponse
+import os
+import secrets
+import redis.asyncio as aioredis
+
+REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
+redis_client = aioredis.from_url(REDIS_URL)
+
+_RELEASE_LOCK_LUA = 'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) end return 0'
+
+async def idempotency_guard_middleware(request: Request, call_next):
+    if request.url.path == "/api/v1/voucher/claim" and request.method == "POST":
+        user_id = getattr(request.state, "user_id", None)
+        if not user_id:
+            return JSONResponse(status_code=401, content={"error": "Unauthenticated"})
+        lock_key = f"aigis:lock:claim:{user_id}"
+        lock_value = secrets.token_hex(16)
+        acquired = await redis_client.set(lock_key, lock_value, nx=True, ex=3)
+        if not acquired:
+            return JSONResponse(
+                status_code=429,
+                content={"error": "Too Many Requests: concurrent execution prevented by AIGIS Guard."}
+            )
+        try:
+            return await call_next(request)
+        finally:
+            await redis_client.eval(_RELEASE_LOCK_LUA, 1, lock_key, lock_value)
+    return await call_next(request)
+"""

        compliance_matrix = [
            {
                "framework": "PCI-DSS v4.0",
                "clause": "Not assessed",
                "name": "Business logic security (demo mapping)",
                "status": compliance_status,
                "badge": "DEMO",
                "detail": "AIGIS is a simulation demo and did not perform a PCI-DSS assessment."
            },
            {
                "framework": "OWASP API Top 10",
                "clause": "API6:2023",
                "name": "Unrestricted Access to Sensitive Business Flows",
                "status": compliance_status,
                "badge": "DEMO",
                "detail": "Heuristic mitigation was verified only against the in-process mock target."
            },
            {
                "framework": "SBV (State Bank of Vietnam)",
                "clause": "Not assessed",
                "name": "Core Banking Transaction Integrity",
                "status": "NOT_ASSESSED",
                "badge": "DEMO",
                "detail": "No regulatory assessment was performed."
            },
            {
                "framework": "NIST SP 800-53 Rev 5",
                "clause": "Not assessed",
                "name": "Denial of Service / Resource Exhaustion Protection",
                "status": "NOT_ASSESSED",
                "badge": "DEMO",
                "detail": "No NIST control assessment was performed."
            }
        ]

        total_requests = int(retest.get("total_requests") or attack.get("total_requests") or 0)
        blocked_requests = int(retest.get("blocked_requests") or 0)
        successful_requests = int(retest.get("successful_requests") or 0)

        transaction_graph = {
            "flow_name": "Measured retest pipeline (mock target)",
            "nodes": [
                {"id": "G1", "label": f"Incoming Burst ({total_requests} requests)", "type": "traffic", "status": "ATTACK"},
                {"id": "G2", "label": "State & Token Ingestion Gate", "type": "gateway", "status": "INSPECTED"},
                {"id": "G3", "label": "Aegis Atomic Lock (mock runtime)", "type": "defense", "status": "LOCKED"},
                {"id": "G4", "label": f"{successful_requests} claim(s) allowed", "type": "outcome_legit", "status": "CLEARED"},
                {"id": "G5", "label": f"{blocked_requests} claim(s) blocked", "type": "outcome_blocked", "status": "PROTECTED"}
            ],
            "capital_preserved_usd": round(capital_preserved, 2)
        }

        thought_chain.append(
            f"[COMPLIANCE DOSSIER] Demo package sealed. Score: {score_before_text} -> {score_after_text} / 100. "
            "Compliance entries are demo mappings, not audit results."
        )

        return {
            "agent": "Compliance Arbiter",
            "agent_role": "Agent 5: Compliance Arbiter (Demo Scoring & PR Handover)",
            "model_engine": f"{llm_status['provider']} ({llm_status['model_name']})",
            "status": "DOSSIER_FINALIZED",
            "thought_chain": thought_chain,
            "security_score_before": initial_score,
            "security_score_after": patched_score,
            "initial_score": initial_score,
            "patched_score": patched_score,
            "score_breakdown": scoring,
            "git_pull_request_diff": git_diff,
            "risk_classification": (
                "CRITICAL_BLV_RESOLVED" if retest_neutralized else
                ("CRITICAL_BLV_UNRESOLVED" if attack else "NOT_ASSESSED")
            ),
            "compliance_matrix": compliance_matrix,
            "compliance_scope": "DEMO_ONLY",
            "transaction_graph": transaction_graph,
            "financial_exposure_saved": round(capital_preserved, 2),
            "financial_exposure_period": "per_retest_event",
            "financial_exposure_currency": "USD",
            "git_pull_request": {
                "pr_number": 142,
                "simulated": True,
                "title": "fix(security): Add distributed lock on /voucher/claim to prevent concurrent claims",
                "branch": "aigis/auto-patch-blv-race-condition",
                "diff": git_diff,
                "commit_message": f"Demo patch generated by AIGIS. Heuristic score: {score_before_text} -> {score_after_text}/100."
            },
            "executive_summary": (
                f"The AIGIS demo completed a measured attack/retest cycle. The unpatched run lost "
                f"${attack_stolen:,.2f}; the retest run lost ${retest_stolen:,.2f}, preserving "
                f"${capital_preserved:,.2f} in this event. Heuristic demo score: {score_before_text} -> "
                f"{score_after_text}/100. This is not a production certification."
            )
        }
