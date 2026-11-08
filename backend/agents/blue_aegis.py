"""Mock-control activation and canonical reference patch handoff."""
import time
from backend.mock_target.store import mock_store
from backend.llm_engine import global_llm_engine
from backend.patch_registry import python_guard, metadata
from backend.evidence import illegal_loss


class BlueAegisAgent:
    async def analyze_and_synthesize_patch(self, sandbox_report):
        mock_store.patch_enabled = True
        return {"agent": "Auto-Remediator", "agent_role": "Reference Patch Handoff",
                "model_engine": global_llm_engine.get_status()["provider"],
                "status": "SIMULATED_PATCH_DEPLOYED", "assessment_state": "NOT_ASSESSED",
                "context": sandbox_report.get("evidence"),
                "thought_chain": [f"Measured illegal value: ${illegal_loss(sandbox_report):,.2f}.",
                                  "Enabled mock control; reference code is not executed or verified by this action."],
                "root_cause_analysis": "The mock splits its quota check and state mutation across an await.",
                "patch_strategy": "AUTHENTICATED_OWNER_TOKEN_LOCK", "patch_code": python_guard(),
                "template_metadata": metadata(), "vulnerable_code": "# Mock target: backend/mock_target/store.py",
                "remediation_status": "Mock flag enabled; production not modified.", "next_step": "Run matched retest and regression."}

    async def run_zero_regression_test(self, sample_users=50):
        sample_users = max(1, min(int(sample_users), 500))
        original_enabled = mock_store.patch_enabled
        original_modules = dict(mock_store.patch_modules)

        async def measure(enabled):
            mock_store.reset(preserve_patches=True)
            mock_store.set_all_patches(enabled)
            latencies, approved = [], 0
            for index in range(sample_users):
                start = time.perf_counter()
                response = await mock_store.claim_voucher(f"legit_{index}", "REGRESSION", 10)
                latencies.append((time.perf_counter() - start) * 1000)
                approved += response.get("status_code") == 200
            return approved, sum(latencies) / len(latencies)

        try:
            baseline_approved, baseline = await measure(False)
            approved, patched = await measure(True)
        finally:
            mock_store.patch_enabled = original_enabled
            mock_store.patch_modules = original_modules
        overhead = round(patched - baseline, 2)
        passed = baseline_approved == approved == sample_users and overhead <= 2
        return {"agent": "Auto-Remediator", "status": "ZERO_REGRESSION_VERIFIED" if passed else "REGRESSION_DETECTED",
                "assessment_state": "MITIGATION_VERIFIED_IN_MOCK" if passed else "VERIFICATION_FAILED",
                "sample_users_tested": sample_users, "legitimate_requests_approved": approved,
                "baseline_requests_approved": baseline_approved,
                "false_positive_rate": f"{(sample_users-approved)/sample_users*100:.2f}%",
                "baseline_latency_ms": round(baseline, 2), "patched_latency_ms": round(patched, 2),
                "total_latency_ms": round(patched, 2), "latency_overhead_ms": overhead,
                "verdict": "PASSED in mock workload" if passed else "FAILED mock regression or latency target"}
