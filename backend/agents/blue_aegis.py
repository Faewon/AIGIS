import asyncio
import time
from typing import Dict, Any
from ..mock_target.store import mock_store
from ..llm_engine import global_llm_engine

class BlueAegisAgent:
    """
    Agent 4: Blue Team Synthesizer — "Aegis" (CRS Autonomous Self-Healing)
    Sử dụng ReAct Agent Loop:
    - Thought: Phân tích báo cáo thiệt hại từ Sandbox Runner ($7,500 bị đánh cắp).
    - RCA: Định vị cửa sổ Time-of-Check to Time-of-Use (TOCTOU).
    - Synthesis: Tự động lập trình Middleware phòng vệ (Redis Distributed Lock / Idempotency Key).
    - Verification: Chạy kiểm thử hồi quy (Zero-Regression Test) trên 50 người dùng bình thường.
    """

    def __init__(self):
        self.system_prompt = (
            "You are Agent 4 (Auto-Remediator) in the AIGIS platform. "
            "You are a principal security architect specializing in automated program repair, "
            "distributed locking, race condition mitigation, and zero-regression verification. "
            "Generate clean, production-grade FastAPI/ASGI middleware using distributed atomic locks."
        )

    async def analyze_and_synthesize_patch(self, sandbox_report: Dict[str, Any]) -> Dict[str, Any]:
        stolen = float(sandbox_report.get("total_stolen_amount") or 0.0)
        requests_count = int(sandbox_report.get("successful_requests") or 0)
        total_requests = int(sandbox_report.get("total_requests") or sandbox_report.get("total_burst_count") or 0)

        thought_chain = []
        thought_chain.append(
            f"[THOUGHT 1] Ingested Sandbox report: {requests_count}/{total_requests} requests succeeded, "
            f"measured unauthorized value ${stolen:,.2f}."
        )
        thought_chain.append("[ROOT CAUSE ANALYSIS] Observed a Time-of-Check to Time-of-Use (TOCTOU) pattern: concurrent requests can pass the quota check before the first commit.")
        thought_chain.append("[DEFENSIVE STRATEGY] Synthesizing an idempotency/locking middleware template using Redis SET NX with a short lease TTL.")

        llm_status = global_llm_engine.get_status()
        patch_code = ""

        # Nếu LLM được kết nối, yêu cầu LLM viết bản vá
        if llm_status["mode"] == "API_CONNECTED":
            thought_chain.append(f"[ACTION] Prompting {llm_status['provider']} ({llm_status['model_name']}) to synthesize FastAPI Idempotency Guard middleware...")
            prompt = (
                f"Write a Python FastAPI middleware class `RedisIdempotencyMiddleware` that intercepts requests to '/api/v1/voucher/claim'.\n"
                "It must check an atomic distributed lock on `user_id` using Redis SET NX logic.\n"
                "If already locked, immediately return HTTP 429 Too Many Requests.\n"
                "Return ONLY the executable Python code."
            )
            llm_patch = await global_llm_engine.call_llm(self.system_prompt, prompt)
            if "class" in llm_patch and "middleware" in llm_patch.lower():
                if "```python" in llm_patch:
                    patch_code = llm_patch.split("```python")[1].split("```")[0].strip()
                elif "```" in llm_patch:
                    patch_code = llm_patch.split("```")[1].split("```")[0].strip()
                else:
                    patch_code = llm_patch.strip()
                thought_chain.append(f"[LLM SYNTHESIS] Defense patch autonomously synthesized by {llm_status['model_name']}.")

        if not patch_code:
            thought_chain.append("[AUTONOMOUS SYNTHESIS] Synthesizing high-performance Redis Distributed Lock Middleware.")
            patch_code = """# ==============================================================================
# AIGIS BLUE TEAM (AEGIS) — REFERENCE IDEMPOTENCY GUARD MIDDLEWARE
# This is a template shown in the UI; it is not executed by the demo server.
# Requires an upstream authentication middleware that sets request.state.user_id.
# ==============================================================================

from fastapi import Request
from fastapi.responses import JSONResponse
import os
import secrets
import redis.asyncio as aioredis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = aioredis.from_url(REDIS_URL)

_RELEASE_LOCK_LUA = '''
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
end
return 0
'''

class RedisIdempotencyMiddleware:
    def __init__(self, app, lock_ttl_sec: float = 3.0):
        self.app = app
        self.lock_ttl_sec = lock_ttl_sec

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/api/v1/voucher/claim" and scope["method"] == "POST":
            # In a real ASGI app, read the authenticated identity established by
            # earlier middleware; never trust a client-supplied X-User-ID header.
            state = scope.get("state") or {}
            user_id = state.get("user_id")
            if not user_id:
                response = JSONResponse(status_code=401, content={"success": False, "error": "Unauthenticated"})
                await response(scope, receive, send)
                return

            lock_key = f"aigis:lock:claim:{user_id}"
            lock_value = secrets.token_hex(16)
            acquired = await redis_client.set(lock_key, lock_value, nx=True, ex=self.lock_ttl_sec)
            if not acquired:
                response = JSONResponse(
                    status_code=429,
                    content={
                        "success": False,
                        "error": "Too Many Requests: Concurrent claim blocked by Aegis Idempotency Guard.",
                        "blocked_by": "Aegis_Blue_Team_Patch"
                    }
                )
                await response(scope, receive, send)
                return
            try:
                await self.app(scope, receive, send)
            finally:
                await redis_client.eval(_RELEASE_LOCK_LUA, 1, lock_key, lock_value)
            return

        await self.app(scope, receive, send)
"""

        thought_chain.append("[DEPLOYMENT] Hot-reloading patch into Sandbox Runtime memory. Activating protection filter...")
        # Bật cờ vá lỗi trong store
        mock_store.patch_enabled = True
        thought_chain.append("[STATUS] Runtime protection ACTIVE. Preparing zero-regression customer baseline test.")

        vulnerable_code = """# ==============================================================================
# VULNERABLE PRODUCTION ENDPOINT (BEFORE REMEDIATION)
# File: /app/controllers/voucher_controller.py
# Vulnerability: Concurrency Time-of-Check to Time-of-Use (TOCTOU)
# ==============================================================================

@app.post("/api/v1/voucher/claim")
async def claim_voucher(request: Request, user_id: str, voucher_code: str):
    # STEP 1: Time-of-Check (No Atomic Lock or Mutex)
    claims = await db.fetch_val(
        "SELECT COUNT(*) FROM voucher_claims WHERE user_id = :u AND code = :c",
        values={"u": user_id, "c": voucher_code}
    )
    if claims >= 1:
        return {"success": False, "error": "Voucher quota already reached"}

    # [CRITICAL TOCTOU EXPLOIT WINDOW]
    # Concurrent requests can enter this read/write gap simultaneously.

    # STEP 2: Time-of-Use (Delayed balance update)
    await db.execute(
        "INSERT INTO voucher_claims (user_id, code, claimed_at) VALUES (:u, :c, NOW())",
        values={"u": user_id, "c": voucher_code}
    )
    return {"success": True, "payout": 500.00}
"""

        root_cause = (
            "VULNERABILITY: Concurrency Time-of-Check to Time-of-Use (TOCTOU) Race Condition.\n"
            "ROOT CAUSE: The mock target verifies a user's quota (read) and updates the claim state (write) "
            "in separate steps without a per-user atomic guard. Concurrent requests can all observe the pre-commit "
            "state; the measured number of successful duplicate claims is reported by the sandbox rather than assumed."
        )

        return {
            "agent": "Auto-Remediator",
            "agent_role": "Agent 4: Auto-Remediator (Distributed Lock Patch Synthesis)",
            "model_engine": f"{llm_status['provider']} ({llm_status['model_name']})",
            "status": "SIMULATED_PATCH_DEPLOYED",
            "thought_chain": thought_chain,
            "root_cause_analysis": root_cause,
            "patch_strategy": "REDIS_DISTRIBUTED_LOCK_AND_IDEMPOTENCY_GUARD",
            "patch_code": patch_code,
            "vulnerable_code": vulnerable_code,
            "remediation_status": "Patch flag enabled in the in-process mock target; no production system was modified.",
            "next_step": "Trigger exploit re-test and execute the zero-regression benchmark."
        }

    async def run_zero_regression_test(self, sample_users: int = 50) -> Dict[str, Any]:
        """
        Measure legitimate-user behavior with and without the patch enabled.
        No hard-coded latency or false-positive numbers are used.
        """
        sample_users = max(1, min(int(sample_users), 500))
        mock_store.reset(preserve_patches=True)
        original_enabled = mock_store.patch_enabled
        original_modules = dict(mock_store.patch_modules)

        async def measure(prefix: str, patch_enabled: bool):
            mock_store.set_all_patches(patch_enabled)
            latencies = []
            approved = 0
            for i in range(sample_users):
                user_id = f"{prefix}_{i+1:03d}"
                t0 = time.time()
                res = await mock_store.claim_voucher(user_id=user_id, voucher_code="TET2026_NORMAL", amount=10.0)
                latencies.append((time.time() - t0) * 1000.0)
                if res.get("status_code") == 200:
                    approved += 1
            avg = sum(latencies) / len(latencies) if latencies else 0.0
            return approved, avg

        try:
            baseline_approved, baseline_avg = await measure("usr_legit_baseline", False)
            patched_approved, patched_avg = await measure("usr_legit_patched", True)
        finally:
            mock_store.patch_enabled = original_enabled
            mock_store.patch_modules = original_modules

        false_positive_rate = round((sample_users - patched_approved) / sample_users * 100.0, 2)
        overhead_ms = round(patched_avg - baseline_avg, 2)
        passed = patched_approved == sample_users and overhead_ms <= 2.0

        return {
            "agent": "Auto-Remediator",
            "status": "ZERO_REGRESSION_VERIFIED" if passed else "REGRESSION_DETECTED",
            "sample_users_tested": sample_users,
            "legitimate_requests_approved": patched_approved,
            "baseline_requests_approved": baseline_approved,
            "false_positive_rate": f"{false_positive_rate:.2f}%",
            "baseline_latency_ms": round(baseline_avg, 2),
            "patched_latency_ms": round(patched_avg, 2),
            "total_latency_ms": round(patched_avg, 2),
            "latency_overhead_ms": overhead_ms,
            "verdict": (
                "PASSED — legitimate requests were approved and measured latency overhead stayed within the 2.0ms target."
                if passed else
                "FAILED — legitimate requests were rejected or measured latency overhead exceeded the 2.0ms target."
            )
        }
