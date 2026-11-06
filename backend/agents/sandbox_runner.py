import asyncio
import time
from typing import Dict, Any, List
from ..mock_target.store import mock_store

class SandboxRunnerAgent:
    """
    Agent 3: Sandbox Runner (Võ đài Thực thi & Định giá Thiệt hại)
    Hỗ trợ 4 kịch bản lỗ hổng nghiệp vụ (Multi-Scenario Business Logic Flaws):
    1. TOCTOU_RACE_CONDITION
    2. BOLA_IDOR
    3. NEGATIVE_AMOUNT_TAMPERING
    4. STEP_SKIPPING_STATE_BYPASS
    """

    async def execute_burst_attack(self, user_id: str = "usr_attacker_cerebrus_01", voucher_code: str = "TET2026_VIP", burst_count: int = 15, amount: float = 500.0) -> Dict[str, Any]:
        start_time = time.time()
        if not mock_store.patch_enabled and not mock_store.patch_modules.get("concurrency_mutex"):
            mock_store.user_claims.pop(user_id, None)
            mock_store.distributed_lock.pop(f"lock:claim:{user_id}", None)
        
        tasks = [
            mock_store.claim_voucher(user_id=user_id, voucher_code=voucher_code, amount=amount)
            for _ in range(burst_count)
        ]
        
        responses = await asyncio.gather(*tasks)
        elapsed_ms = (time.time() - start_time) * 1000.0

        successful_claims = [r for r in responses if r.get("status_code") == 200]
        blocked_claims = [r for r in responses if r.get("status_code") in (400, 429)]
        
        success_count = len(successful_claims)
        total_stolen = success_count * amount
        illegal_claims_count = max(0, success_count - 1)
        illegal_stolen_amount = illegal_claims_count * amount

        is_exploited = illegal_claims_count > 0

        logs = []
        for idx, res in enumerate(responses):
            status = res.get("status_code")
            if status == 200:
                logs.append(f"[STREAM #{idx+1:02d}] HTTP 200 OK — Claimed {res.get('data', {}).get('claim_id')} (${amount})")
            elif status == 429:
                logs.append(f"[STREAM #{idx+1:02d}] HTTP 429 BLOCKED — {res.get('error')}")
            else:
                logs.append(f"[STREAM #{idx+1:02d}] HTTP {status} REJECTED — {res.get('error')}")

        return {
            "agent": "Sandbox Executor",
            "scenario": "TOCTOU_RACE_CONDITION",
            "status": "EXPLOIT_VERIFIED" if is_exploited else "EXPLOIT_NEUTRALIZED",
            "is_vulnerable": is_exploited,
            "total_requests": burst_count,
            "total_burst_count": burst_count,
            "successful_requests": success_count,
            "blocked_requests": len(blocked_claims),
            "execution_time_ms": round(elapsed_ms, 2),
            "total_stolen_amount": total_stolen,
            "illegal_claims_count": illegal_claims_count,
            "illegal_stolen_amount": illegal_stolen_amount,
            "budget_remaining": mock_store.budget_remaining,
            "stream_logs": logs,
            "summary_message": (
                f"EXPLOIT CONFIRMED: Test account claimed {success_count} vouchers "
                f"(Total value: ${total_stolen:,.2f}), exceeding allowance by {illegal_claims_count} claims due to missing Idempotency Lock."
                if is_exploited else
                f"EXPLOIT NEUTRALIZED: 1 legitimate request approved, {len(blocked_claims)} concurrent requests blocked by Aegis Idempotency Guard."
            )
        }

    async def execute_bola_attack(self, attacker_id: str = "usr_attacker_cerebrus_01") -> Dict[str, Any]:
        """Tấn công BOLA / IDOR trích xuất trái phép tài khoản người khác"""
        t0 = time.time()
        logs = []
        targets = [
            {"account_id": "acc_victim_01", "amount": 5000.0},
            {"account_id": "acc_victim_02", "amount": 10000.0}
        ]

        total_stolen = 0.0
        blocked_count = 0
        success_count = 0

        for t in targets:
            res = await mock_store.withdraw_account_funds(caller_id=attacker_id, target_account_id=t["account_id"], amount=t["amount"])
            if res["status_code"] == 200:
                success_count += 1
                total_stolen += t["amount"]
                logs.append(f"[BOLA BREACH] Successfully debited ${t['amount']:,.2f} from '{t['account_id']}' without ownership check!")
            else:
                blocked_count += 1
                logs.append(f"[BOLA BLOCKED] HTTP {res['status_code']} — {res.get('error')}")

        is_vulnerable = success_count > 0
        elapsed_ms = (time.time() - t0) * 1000.0

        return {
            "agent": "Sandbox Executor",
            "scenario": "BOLA_IDOR",
            "status": "EXPLOIT_VERIFIED" if is_vulnerable else "EXPLOIT_NEUTRALIZED",
            "is_vulnerable": is_vulnerable,
            "total_requests": len(targets),
            "successful_requests": success_count,
            "blocked_requests": blocked_count,
            "total_stolen_amount": total_stolen,
            "illegal_claims_count": success_count,
            "execution_time_ms": round(elapsed_ms, 2),
            "stream_logs": logs,
            "summary_message": (
                f"BOLA EXPLOIT VERIFIED: Attacker successfully drained ${total_stolen:,.2f} from {success_count} victim accounts due to missing Object Ownership verification."
                if is_vulnerable else
                "BOLA NEUTRALIZED: All unauthorized object access attempts rejected with HTTP 403 Forbidden by Aegis BOLA Guard."
            )
        }

    async def execute_tamper_attack(self, attacker_id: str = "usr_attacker_cerebrus_01") -> Dict[str, Any]:
        """Tấn công Negative Amount & Parameter Tampering"""
        t0 = time.time()
        logs = []
        payloads = [
            {"amount": -5000.0, "discount": 0.0, "desc": "Negative Amount Inversion"},
            {"amount": 1000.0, "discount": 150.0, "desc": "Negative Net Payment via 150% Discount"}
        ]

        success_count = 0
        blocked_count = 0
        total_stolen = 0.0

        for p in payloads:
            res = await mock_store.process_checkout_payment(user_id=attacker_id, amount=p["amount"], discount_percent=p["discount"])
            if res["status_code"] == 200 and "EXPLOITED" in res.get("message", ""):
                success_count += 1
                stolen = res.get("data", {}).get("credit_reversed", 5000.0)
                total_stolen += stolen
                logs.append(f"[TAMPER BREACH] {p['desc']}: Server reversed balance and credited ${stolen:,.2f} to attacker!")
            elif res["status_code"] == 422:
                blocked_count += 1
                logs.append(f"[TAMPER BLOCKED] HTTP 422 — {res.get('error')}")
            else:
                logs.append(f"[NORMAL] Payment of ${p['amount']} processed.")

        is_vulnerable = success_count > 0
        elapsed_ms = (time.time() - t0) * 1000.0

        return {
            "agent": "Sandbox Executor",
            "scenario": "NEGATIVE_AMOUNT_TAMPERING",
            "status": "EXPLOIT_VERIFIED" if is_vulnerable else "EXPLOIT_NEUTRALIZED",
            "is_vulnerable": is_vulnerable,
            "total_requests": len(payloads),
            "successful_requests": success_count,
            "blocked_requests": blocked_count,
            "total_stolen_amount": total_stolen,
            "illegal_claims_count": success_count,
            "execution_time_ms": round(elapsed_ms, 2),
            "stream_logs": logs,
            "summary_message": (
                f"PARAMETER TAMPERING CONFIRMED: Inverted negative amounts credited ${total_stolen:,.2f} to attacker account!"
                if is_vulnerable else
                "PARAMETER TAMPERING BLOCKED: Negative/inverted amounts rejected with HTTP 422 by Aegis Boundary Guard."
            )
        }

    async def execute_step_skipping_attack(self, attacker_id: str = "usr_attacker_cerebrus_01") -> Dict[str, Any]:
        """Tấn công Step-Skipping & State Machine Inversion"""
        t0 = time.time()
        logs = []
        order_id = f"ORD-EXPLOIT-{int(time.time()*1000)%10000}"
        
        # Thử nhảy cóc từ S1 thẳng sang S4 (Bỏ qua S2 thanh toán và S3 ký quỹ)
        res = await mock_store.execute_order_state_transition(user_id=attacker_id, order_id=order_id, target_state="S4_FULFILLED")
        is_vulnerable = res["status_code"] == 200 and "EXPLOITED" in res.get("message", "")
        
        if is_vulnerable:
            logs.append(f"[STEP-SKIPPING BREACH] Order {order_id} marked as FULFILLED directly from INIT without payment authorization! Loss: $3,500.00")
            total_stolen = 3500.0
        else:
            logs.append(f"[STEP-SKIPPING BLOCKED] HTTP {res['status_code']} — {res.get('error')}")
            total_stolen = 0.0

        elapsed_ms = (time.time() - t0) * 1000.0

        return {
            "agent": "Sandbox Executor",
            "scenario": "STEP_SKIPPING_STATE_BYPASS",
            "status": "EXPLOIT_VERIFIED" if is_vulnerable else "EXPLOIT_NEUTRALIZED",
            "is_vulnerable": is_vulnerable,
            "total_requests": 1,
            "successful_requests": 1 if is_vulnerable else 0,
            "blocked_requests": 0 if is_vulnerable else 1,
            "total_stolen_amount": total_stolen,
            "illegal_claims_count": 1 if is_vulnerable else 0,
            "execution_time_ms": round(elapsed_ms, 2),
            "stream_logs": logs,
            "summary_message": (
                f"STATE MACHINE BYPASS VERIFIED: Order {order_id} delivered without payment authorization ($3,500 loss)."
                if is_vulnerable else
                "STATE MACHINE INVARIANT ENFORCED: Illegitimate state transitions rejected with HTTP 409 Conflict."
            )
        }

    async def execute_scenario(self, scenario: str, burst_count: int = 15) -> Dict[str, Any]:
        """Router điều phối kịch bản tấn công"""
        if scenario == "BOLA_IDOR":
            return await self.execute_bola_attack()
        elif scenario == "NEGATIVE_AMOUNT_TAMPERING":
            return await self.execute_tamper_attack()
        elif scenario == "STEP_SKIPPING_STATE_BYPASS":
            return await self.execute_step_skipping_attack()
        else:
            return await self.execute_burst_attack(burst_count=burst_count)
