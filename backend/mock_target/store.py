import asyncio
import time
from typing import Dict, Any, List, Optional

class VulnerableVoucherStore:
    """
    Mock FinTech & Banking Target Server với 4 nhóm lỗ hổng logic nghiệp vụ:
    1. TOCTOU_RACE_CONDITION: Concurrency double-spending trên /api/v1/voucher/claim
    2. BOLA_IDOR: Broken Object Level Authorization trên /api/v1/account/{account_id}/withdraw
    3. NEGATIVE_AMOUNT_TAMPERING: Parameter tampering & negative payout trên /api/v1/payment/checkout
    4. STEP_SKIPPING_STATE_BYPASS: Bỏ qua bước thanh toán gọi thẳng /api/v1/order/confirm
    """
    def __init__(self):
        self.reset()

    def reset(self, preserve_patches: bool = False):
        patch_enabled = getattr(self, "patch_enabled", False)
        patch_modules = dict(getattr(self, "patch_modules", {}))

        self.budget_remaining: float = 200000.0  # Ngân sách $200,000
        self.user_claims: Dict[str, int] = {}    # user_id -> số lần đã nhận
        self.vouchers_issued: List[Dict[str, Any]] = []
        
        # Accounts data for BOLA / IDOR simulation
        self.accounts: Dict[str, Dict[str, Any]] = {
            "acc_victim_01": {"owner": "usr_victim_bob", "balance": 15000.0, "account_type": "VIP_SAVINGS"},
            "acc_victim_02": {"owner": "usr_victim_alice", "balance": 28000.0, "account_type": "BUSINESS_CHECKING"},
            "acc_attacker_01": {"owner": "usr_attacker_cerebrus_01", "balance": 100.0, "account_type": "RETAIL_BASIC"}
        }

        # Order states for Step-Skipping simulation
        self.orders: Dict[str, Dict[str, Any]] = {}

        # Velocity tracking for Risk Engine
        self.velocity_window: List[Dict[str, Any]] = []
        self.velocity_limit_per_10s: int = 5

        # Cờ bật các lớp bản vá bảo mật của Blue Team
        self.patch_enabled: bool = False
        self.patch_modules: Dict[str, bool] = {
            "concurrency_mutex": False,
            "bola_ownership_guard": False,
            "parameter_validation": False,
            "state_machine_guard": False,
            "velocity_limiter": False
        }

        self.distributed_lock: Dict[str, float] = {}

        if preserve_patches:
            self.patch_enabled = patch_enabled
            self.patch_modules = patch_modules

    def set_all_patches(self, enabled: bool):
        self.patch_enabled = enabled
        for k in self.patch_modules:
            self.patch_modules[k] = enabled

    # =========================================================================
    # 1. TOCTOU RACE CONDITION ENDPOINT
    # =========================================================================
    async def claim_voucher(self, user_id: str, voucher_code: str, amount: float = 500.0) -> Dict[str, Any]:
        lock_key = None
        if self.patch_enabled or self.patch_modules.get("concurrency_mutex"):
            lock_key = f"lock:claim:{user_id}"
            now = time.time()
            if lock_key in self.distributed_lock and (now - self.distributed_lock[lock_key]) < 3.0:
                return {
                    "success": False,
                    "status_code": 429,
                    "error": "Too Many Requests: Concurrent claim blocked by Aegis Idempotency Guard.",
                    "user_id": user_id,
                    "blocked_by": "Aegis_Blue_Team_Patch"
                }
            self.distributed_lock[lock_key] = now
        try:
            return await self._claim_voucher_unlocked(user_id, voucher_code, amount)
        finally:
            if lock_key is not None:
                self.distributed_lock.pop(lock_key, None)

    async def _claim_voucher_unlocked(self, user_id: str, voucher_code: str, amount: float) -> Dict[str, Any]:
        timestamp = time.time()
        current_claims = self.user_claims.get(user_id, 0)
        if current_claims >= 1:
            return {
                "success": False,
                "status_code": 400,
                "error": "Policy Violation: User has already claimed maximum allowed vouchers (1/1).",
                "user_id": user_id
            }

        if self.budget_remaining < amount:
            return {
                "success": False,
                "status_code": 400,
                "error": "Campaign budget exhausted.",
                "user_id": user_id
            }

        await asyncio.sleep(0.02) # Network I/O gap

        if self.budget_remaining < amount:
            return {
                "success": False,
                "status_code": 400,
                "error": "Campaign budget exhausted.",
                "user_id": user_id
            }

        self.user_claims[user_id] = current_claims + 1
        self.budget_remaining -= amount
        claim_id = f"VOUCHER-{int(timestamp*1000)}-{len(self.vouchers_issued)+1}"
        record = {
            "claim_id": claim_id,
            "user_id": user_id,
            "code": voucher_code,
            "amount": amount,
            "timestamp": timestamp
        }
        self.vouchers_issued.append(record)

        return {
            "success": True,
            "status_code": 200,
            "message": f"Successfully claimed voucher {claim_id} for ${amount}",
            "data": record,
            "budget_remaining": self.budget_remaining
        }

    # =========================================================================
    # 2. BOLA / IDOR ENDPOINT (Broken Object Level Authorization)
    # =========================================================================
    async def withdraw_account_funds(self, caller_id: str, target_account_id: str, amount: float = 2000.0) -> Dict[str, Any]:
        await asyncio.sleep(0.015)
        account = self.accounts.get(target_account_id)
        if not account:
            return {"success": False, "status_code": 404, "error": "Account not found"}

        # NẾU ĐÃ VÁ: Kiểm tra quyền sở hữu Object Level
        if self.patch_enabled or self.patch_modules.get("bola_ownership_guard"):
            if account["owner"] != caller_id:
                return {
                    "success": False,
                    "status_code": 403,
                    "error": f"Access Denied: Caller '{caller_id}' is not authorized to debit account '{target_account_id}' (Owner: '{account['owner']}'). BOLA Blocked by Aegis Guard.",
                    "blocked_by": "Aegis_BOLA_Ownership_Interceptor"
                }

        # NẾU CHƯA VÁ: Lỗ hổng BOLA cho phép caller rút tiền từ tài khoản nạn nhân
        if account["balance"] < amount:
            return {"success": False, "status_code": 400, "error": "Insufficient account balance"}

        account["balance"] -= amount
        return {
            "success": True,
            "status_code": 200,
            "message": f"Withdrew ${amount:,.2f} from {target_account_id} to caller {caller_id}",
            "data": {
                "account_id": target_account_id,
                "victim_owner": account["owner"],
                "caller_id": caller_id,
                "amount_stolen": amount,
                "remaining_balance": account["balance"]
            }
        }

    # =========================================================================
    # 3. NEGATIVE AMOUNT & PARAMETER TAMPERING ENDPOINT
    # =========================================================================
    async def process_checkout_payment(self, user_id: str, amount: float, discount_percent: float = 0.0) -> Dict[str, Any]:
        await asyncio.sleep(0.015)

        # NẾU ĐÃ VÁ: Kiểm tra miền giá trị chặt chẽ (Strict Bounds Validation)
        if self.patch_enabled or self.patch_modules.get("parameter_validation"):
            if amount <= 0.0:
                return {
                    "success": False,
                    "status_code": 422,
                    "error": f"Invalid Parameter: Transaction amount (${amount}) must be strictly positive (> 0.00). Inverted payment blocked by Aegis Boundary Guard.",
                    "blocked_by": "Aegis_Parameter_Invariant_Guard"
                }
            if discount_percent < 0.0 or discount_percent > 50.0:
                return {
                    "success": False,
                    "status_code": 422,
                    "error": f"Invalid Parameter: Discount percent ({discount_percent}%) exceeds regulatory maximum allowed (50.0%).",
                    "blocked_by": "Aegis_Parameter_Invariant_Guard"
                }

        # NẾU CHƯA VÁ: Số tiền âm khiến hệ thống cộng ngược tiền vào tài khoản
        final_payable = amount * (1.0 - (discount_percent / 100.0))
        if final_payable < 0:
            # Gian lận số tiền âm
            self.budget_remaining += abs(final_payable)
            return {
                "success": True,
                "status_code": 200,
                "message": f"EXPLOITED: Negative payment payload generated credit payout of ${abs(final_payable):,.2f} to user!",
                "data": {"user_id": user_id, "amount_manipulated": amount, "credit_reversed": abs(final_payable)}
            }

        return {
            "success": True,
            "status_code": 200,
            "message": f"Payment of ${final_payable:,.2f} processed successfully.",
            "data": {"user_id": user_id, "amount_charged": final_payable}
        }

    # =========================================================================
    # 4. STEP-SKIPPING & STATE MACHINE INVARIANT BYPASS
    # =========================================================================
    async def execute_order_state_transition(self, user_id: str, order_id: str, target_state: str) -> Dict[str, Any]:
        await asyncio.sleep(0.015)
        curr_state = self.orders.get(order_id, {}).get("state", "S1_INIT")

        # NẾU ĐÃ VÁ: Kiểm tra máy trạng thái hữu hạn nghiêm ngặt S1 -> S2 -> S3 -> S4
        valid_transitions = {
            "S1_INIT": ["S2_PAYMENT_AUTHORIZED"],
            "S2_PAYMENT_AUTHORIZED": ["S3_ESCROW_COMMITTED"],
            "S3_ESCROW_COMMITTED": ["S4_FULFILLED"]
        }

        if self.patch_enabled or self.patch_modules.get("state_machine_guard"):
            allowed = valid_transitions.get(curr_state, [])
            if target_state not in allowed:
                return {
                    "success": False,
                    "status_code": 409,
                    "error": f"State Invariant Breach: Cannot transition order '{order_id}' directly from '{curr_state}' to '{target_state}'. Step-skipping blocked by Aegis State Machine Guard.",
                    "blocked_by": "Aegis_State_Machine_Validator"
                }

        # NẾU CHƯA VÁ: Cho phép nhảy cóc từ S1_INIT thẳng sang S4_FULFILLED
        if order_id not in self.orders:
            self.orders[order_id] = {"user_id": user_id, "state": "S1_INIT", "paid": False}

        self.orders[order_id]["state"] = target_state
        if target_state == "S4_FULFILLED" and curr_state != "S3_ESCROW_COMMITTED":
            return {
                "success": True,
                "status_code": 200,
                "message": f"EXPLOITED: Step-skipping succeeded! Order {order_id} marked as FULFILLED without payment authorized!",
                "data": {"order_id": order_id, "status": "DELIVERED_WITHOUT_PAYMENT", "unpaid_loss": 3500.0}
            }

        return {
            "success": True,
            "status_code": 200,
            "message": f"Order {order_id} transitioned from {curr_state} to {target_state}",
            "data": {"order_id": order_id, "current_state": target_state}
        }

    # =========================================================================
    # 5. FINTECH RISK & VELOCITY ENGINE (Sardine & Feedzai inspired)
    # =========================================================================
    def evaluate_transaction_risk(self, client_ip: str, user_id: str, amount: float, device_entropy: float = 0.85) -> Dict[str, Any]:
        now = time.time()
        self.velocity_window = [r for r in self.velocity_window if (now - r["timestamp"]) < 10.0]
        ip_count = sum(1 for r in self.velocity_window if r["ip"] == client_ip)
        self.velocity_window.append({"ip": client_ip, "user_id": user_id, "timestamp": now})

        # Calculate risk score 0 - 100
        risk_score = 15.0
        if ip_count >= self.velocity_limit_per_10s:
            risk_score += 55.0
        if amount > 5000.0:
            risk_score += 20.0
        if device_entropy < 0.4:
            risk_score += 25.0

        risk_score = min(100.0, risk_score)

        # 4-Tier FinTech Action
        if risk_score >= 80.0:
            action = "BLOCK"
            status_code = 429
            reason = f"High velocity burst detected ({ip_count} reqs / 10s from IP subnet). Immediate block."
        elif risk_score >= 60.0:
            action = "CHALLENGE_FACEID_OTP"
            status_code = 202
            reason = "Elevated risk profile detected. Requires secondary biometric / FaceID verification."
        elif risk_score >= 40.0:
            action = "HOLD_REVIEW"
            status_code = 423
            reason = "Unusual transaction parameter. Routed to 15-minute escrow review queue."
        else:
            action = "ALLOW"
            status_code = 200
            reason = "Clean behavioral profile and low velocity. Instant clearance."

        return {
            "risk_score": round(risk_score, 1),
            "action": action,
            "status_code": status_code,
            "reason": reason,
            "metrics": {
                "rolling_10s_velocity": ip_count + 1,
                "velocity_limit": self.velocity_limit_per_10s,
                "device_entropy": device_entropy
            }
        }

mock_store = VulnerableVoucherStore()
