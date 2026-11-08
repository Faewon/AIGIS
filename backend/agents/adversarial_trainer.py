"""Isolated, seeded mock attack/retest training with paired evidence."""
import asyncio
import random
import time

from backend.mock_target.store import mock_store
from backend.simulation import isolated_training, current_run
from backend.run_store import save_run
from backend.evidence import illegal_loss
from backend.patch_registry import reference_diff, metadata
from backend.llm_engine import global_llm_engine
from backend.wargame_workload import make_workload, VERSION
from .sandbox_runner import SandboxRunnerAgent
from .blue_aegis import BlueAegisAgent
from .arbiter import ArenaArbiterAgent

SCENARIOS = ("TOCTOU_RACE_CONDITION", "BOLA_IDOR", "STEP_SKIPPING_STATE_BYPASS", "NEGATIVE_AMOUNT_TAMPERING")


class AdversarialTrainer:
    def __init__(self):
        self.sandbox_agent = SandboxRunnerAgent()
        self.blue_agent = BlueAegisAgent()
        self.arbiter_agent = ArenaArbiterAgent()

    @isolated_training
    async def train_adversarial_rounds(self, total_rounds=5, burst_streams=15, seed=None, run_id=None, workloads=None):
        start = time.perf_counter()
        run = current_run()
        total_rounds = max(1, min(int(total_rounds), 20))
        burst_streams = max(2, min(int(burst_streams), 100))
        from backend.wargame_workload import validate_workloads, execution_versions
        manifests = workloads if workloads is not None else [
            make_workload(run['seed'], SCENARIOS[i % len(SCENARIOS)], burst_streams, i) for i in range(total_rounds)]
        validate_workloads(manifests, total_rounds, burst_streams, SCENARIOS)
        config = {**run, "kind": "training", "total_rounds": total_rounds, "burst_streams": burst_streams,
                  "scenarios": list(SCENARIOS), "simulation_version": VERSION, "workloads": manifests,
                  "versions": execution_versions(),
                  "reproducibility": "Workload and outcomes; wall-clock latency and generated IDs vary."}
        history, pairs = [], []
        patch = {"patch_strategy": "MOCK_TARGET_CONTROLS", "patch_code": reference_diff(),
                 "template_metadata": metadata(), "status": "SIMULATED_PATCH_DEPLOYED"}
        for index in range(total_rounds):
            scenario = SCENARIOS[index % len(SCENARIOS)]
            workload = manifests[index]
            mock_store.set_all_patches(False)
            attack = await self.sandbox_agent.execute_scenario(scenario, burst_streams, workload)
            mock_store.set_all_patches(True)
            retest = await self.sandbox_agent.execute_scenario(scenario, burst_streams, workload)
            regression = await self.blue_agent.run_zero_regression_test(10, scenario)
            dossier = await self.arbiter_agent.generate_dossier(attack, patch, regression, retest)
            pairs.append({"attack": attack, "retest": retest, "regression": regression, "dossier": dossier})
            verified = dossier["assessment_state"] == "MITIGATION_VERIFIED_IN_MOCK" and regression['status'] == 'ZERO_REGRESSION_VERIFIED'
            history.append({"round": index + 1, "title": f"Round {index+1}: {scenario}", "scenario": scenario,
                            "red_tactic": scenario, "red_description": "Measured mock scenario",
                            "llm_red_insight": None, "llm_blue_patch": None,
                            "blue_tactic": "MOCK_TARGET_CONTROLS", "blue_description": "Mock control flags enabled",
                            "attack_total_requests": attack["total_requests"], "attack_successful_requests": attack["successful_requests"],
                            "retest_total_requests": retest["total_requests"], "retest_successful_requests": retest["successful_requests"],
                            "retest_blocked_requests": retest["blocked_requests"],
                            "unpatched_loss_usd": illegal_loss(attack), "retest_loss_usd": illegal_loss(retest),
                            "mitigation_rate": dossier["score_breakdown"]["mitigation_rate"] * 100,
                            "score_before": dossier["initial_score"], "score_after": dossier["patched_score"],
                            "round_status": "CONVERGED_NEUTRALIZED" if verified else "FAILED",
                             "evidence": attack.get("evidence")})
            save_run(run['run_id'], config, {'completed_rounds': index + 1, 'round_evidence': pairs}, 'RUNNING')
        samples = sum(p['regression']['sample_users_tested'] for p in pairs)
        approved = sum(p['regression']['legitimate_requests_approved'] for p in pairs)
        regression = {"status": "ZERO_REGRESSION_VERIFIED" if all(p['regression']['status'] == 'ZERO_REGRESSION_VERIFIED' for p in pairs) else 'REGRESSION_DETECTED',
                      'sample_users_tested': samples, 'legitimate_requests_approved': approved,
                      'false_positive_rate': f'{(samples-approved)/samples*100:.2f}%',
                      'latency_overhead_ms': max(p['regression']['latency_overhead_ms'] for p in pairs),
                      'scenario_reports': [p['regression'] for p in pairs]}
        # The compatibility dossier has one matched scope; aggregates are separate.
        dossier = await self.arbiter_agent.generate_dossier(pairs[-1]["attack"], patch, regression, pairs[-1]["retest"])
        converged = all(r["round_status"] == "CONVERGED_NEUTRALIZED" for r in history)
        total_illegal = sum(p["attack"]["illegal_claims_count"] for p in pairs)
        remaining = sum(p["retest"]["illegal_claims_count"] for p in pairs)
        result = {"success": converged and regression["status"] == "ZERO_REGRESSION_VERIFIED",
                  "status": "TRAINING_COMPLETED", "run_id": run["run_id"], "configuration": config,
                  "assessment_state": "MITIGATION_VERIFIED_IN_MOCK" if converged and regression["status"] == "ZERO_REGRESSION_VERIFIED" else "VERIFICATION_FAILED",
                  "total_rounds": total_rounds, "training_time_sec": round(time.perf_counter() - start, 2),
                  "model_engine": global_llm_engine.get_status()["provider"], "has_api_key": global_llm_engine.get_status()["has_api_key"],
                  "initial_security_score": history[0]["score_before"], "final_security_score": history[-1]["score_after"],
                  "score_progression": [r["score_after"] for r in history], "rounds_history": history,
                  "round_evidence": pairs, "regression_report": regression, "dossier": dossier,
                  "training_summary": {"total_exploits_tested": sum(r["attack_total_requests"] for r in history),
                      "total_capital_defended_usd": sum(max(0, r["unpatched_loss_usd"] - r["retest_loss_usd"]) for r in history),
                      "final_mitigation_rate": round((1 - remaining / total_illegal) * 100, 1) if total_illegal else 0,
                      "convergence_state": "MEASURED_CONVERGED" if converged else "NOT_CONVERGED"}}
        # A lifecycle write must finish before cancellation can mark this run.
        save_run(run["run_id"], config, result)
        return result

    async def run_multicycle_recheck(self, cycles=5, burst_streams=15, seed=None):
        # HTTP dispatch isolates this operation; direct callers can inject a failed
        # control into their current store for negative-control verification.
        cycles = max(1, min(int(cycles), 20))
        burst_streams = max(2, min(int(burst_streams), 100))
        rng = random.Random(seed)
        start = time.perf_counter()
        history = []
        for index in range(cycles):
            mock_store.reset(preserve_patches=True)
            jitter = [rng.uniform(0, 1.5) for _ in range(burst_streams)]
            async def claim(delay):
                await asyncio.sleep(delay / 1000)
                return await mock_store.claim_voucher(f"recheck_{index}", "RECHECK", 500)
            began = time.perf_counter()
            responses = await asyncio.gather(*(claim(delay) for delay in jitter))
            approved = sum(r.get("status_code") == 200 for r in responses)
            blocked = sum(r.get("status_code") == 429 and r.get("blocked_by") == "Aegis_Blue_Team_Patch" for r in responses)
            leaked = max(0, approved - 1)
            history.append({"cycle": index+1, "streams": burst_streams, "approved": approved, "blocked": blocked,
                            "leaked": leaked, "business_failures": burst_streams-approved-blocked,
                            "elapsed_ms": round((time.perf_counter()-began)*1000, 2),
                            "jitter_injected_ms": round(max(jitter), 2), "jitter_schedule_ms": jitter,
                            "status": "BREACHED" if leaked else "PASSED (IMMUNE)" if approved == 1 and blocked == burst_streams-1 else "OVER_BLOCKED" if not approved else "FAILED"})
        passed = all(c["status"] == "PASSED (IMMUNE)" for c in history)
        latencies = [c["elapsed_ms"] for c in history]
        return {"success": passed, "assessment_state": "MITIGATION_VERIFIED_IN_MOCK" if passed else "VERIFICATION_FAILED",
                "seed": seed, "total_cycles": cycles, "total_exploit_attempts": cycles*burst_streams,
                "total_blocked": sum(c["blocked"] for c in history), "total_leaked": sum(c["leaked"] for c in history),
                "mitigation_rate": round(min(1, sum(c["blocked"] for c in history)/(cycles*(burst_streams-1)))*100, 1),
                "avg_latency_ms": round(sum(latencies)/cycles, 2), "min_latency_ms": min(latencies), "max_latency_ms": max(latencies),
                "jitter_variance_ms": round(max(latencies)-min(latencies), 2), "cycles_history": history,
                "execution_time_sec": round(time.perf_counter()-start, 2),
                "verdict": "VERIFIED IN MOCK TARGET: Exactly one legitimate success per cycle." if passed else "FAILED: Leaked, over-blocked, or unexpected failures."}

    def generate_composite_patch_diff(self, rounds_history):
        return reference_diff()


global_adversarial_trainer = AdversarialTrainer()
