"""Evidence-gated demo scoring and matched simulation dossiers."""
from backend.evidence import pair_error, illegal_loss
from backend.patch_registry import reference_diff, metadata
from backend.llm_engine import global_llm_engine


class ArenaArbiterAgent:
    def compute_quantified_security_score(self, attack_report=None, patch_report=None,
                                         regression_report=None, retest_report=None):
        attack, retest, regression = attack_report or {}, retest_report or {}, regression_report or {}
        error = pair_error(attack, retest)
        available = error is None
        voucher = attack.get("scenario") == "TOCTOU_RACE_CONDITION"
        expected = max(1, int(attack.get("total_requests", 0)) - int(voucher))
        illegal = int(attack.get("illegal_claims_count", 0))
        exploit_rate = min(1, illegal / expected)
        initial = round(max(5, 25 + 75 * (1 - exploit_rate) - min(10, illegal_loss(attack) / 1000)), 1)
        approved = int(retest.get("successful_requests", 0))
        blocked = int(retest.get("blocked_requests", 0))
        verified = (available and attack.get("status") == "EXPLOIT_VERIFIED" and
                    retest.get("status") == "EXPLOIT_NEUTRALIZED" and
                    int(retest.get("illegal_claims_count", 0)) == 0 and
                    approved == int(voucher) and blocked == expected)
        mitigation = max(0, min(1, 1 - int(retest.get("illegal_claims_count", 0)) / max(1, illegal))) if available else 0
        if not verified:
            mitigation = 0
        sample = int(regression.get("sample_users_tested", 0))
        fp = max(0, (sample - int(regression.get("legitimate_requests_approved", 0))) / sample) if sample else None
        overhead = regression.get("latency_overhead_ms")
        fp_penalty = round(fp * 500, 1) if fp is not None else 0
        latency_penalty = max(0, round((overhead - 3) * 1.5, 1)) if overhead is not None else 0
        patched = round(max(5, min(99, 25 + 75 * mitigation - fp_penalty - latency_penalty)), 1)
        return {"score_available": available, "comparison_error": error, "mitigation_verified": verified,
                "score_model": "DEMO_HEURISTIC_NOT_CERTIFIED", "initial_score": initial if available else None,
                "patched_score": patched if available else None,
                "score_delta": round(patched - initial, 1) if available else None,
                "posture_rating": ("HARDENED (DEMO SCORE)" if patched >= 90 else "CRITICAL LOGIC RISK (DEMO SCORE)") if available else "NOT ASSESSED",
                "badge_color": "text-emerald-700" if verified else "text-rose-700",
                "unpatched_exploit_rate": exploit_rate, "mitigation_rate": mitigation,
                "fp_penalty": fp_penalty, "latency_penalty": latency_penalty, "resilience_penalty": 0,
                "regression_assessed": sample > 0,
                "breakdown": {"patched_logic_mitigation": f"blocked {blocked}/{expected} expected attempts; matched={available}",
                              "false_positive_penalty": fp_penalty, "latency_sla_penalty": latency_penalty},
                "formula": "Demo: 25 + 75 * verified mitigation - measured regression penalties"}

    async def generate_dossier(self, attack_report, patch_report, regression_report, retest_report=None):
        attack, retest = attack_report or {}, retest_report or {}
        scoring = self.compute_quantified_security_score(attack, patch_report, regression_report, retest)
        matched = scoring["score_available"]
        verified = scoring["mitigation_verified"]
        before, after = illegal_loss(attack), illegal_loss(retest)
        saved = round(max(0, before - after), 2) if matched else None
        scenario = attack.get("scenario", "NOT_ASSESSED")
        diff = reference_diff()
        summary = (f"Matched {scenario} mock workload: illegal loss ${before:,.2f} -> ${after:,.2f}. "
                   f"Capital preserved ${saved:,.2f}. Demo only." if matched else
                   "Not assessed: " + scoring["comparison_error"])
        return {"agent": "Compliance Arbiter", "agent_role": "Matched Mock Evidence Review",
                "model_engine": global_llm_engine.get_status()["provider"],
                "status": "DOSSIER_FINALIZED" if matched else "INCOMPATIBLE_EVIDENCE",
                "assessment_state": "MITIGATION_VERIFIED_IN_MOCK" if verified else "VERIFICATION_FAILED" if matched else "NOT_ASSESSED",
                "context": attack.get("evidence"), "scenario": scenario,
                "thought_chain": [summary, "Telemetry inference and production compliance are not verified by a mock retest."],
                "security_score_before": scoring["initial_score"], "security_score_after": scoring["patched_score"],
                "initial_score": scoring["initial_score"], "patched_score": scoring["patched_score"],
                "score_breakdown": scoring, "git_pull_request_diff": diff,
                "template_metadata": metadata(),
                "risk_classification": "CRITICAL_BLV_RESOLVED" if verified else "CRITICAL_BLV_UNRESOLVED" if matched else "NOT_ASSESSED",
                "compliance_scope": "DEMO_ONLY", "compliance_matrix": [
                    {"framework": name, "clause": "Not assessed", "name": "Illustrative topic mapping",
                     "status": "NOT_ASSESSED", "badge": "DEMO", "detail": "No regulatory assessment performed."}
                    for name in ("PCI-DSS v4.0", "OWASP API Top 10", "SBV", "NIST CSF")],
                "transaction_graph": {"flow_name": f"{scenario}: matched mock retest", "nodes": [
                    {"id": "G1", "label": f"Incoming Burst ({retest.get('total_requests', 0)} requests)", "type": "traffic", "status": "TESTED"},
                    {"id": "G4", "label": f"{retest.get('successful_requests', 0)} requests allowed", "type": "outcome_legit", "status": "MEASURED"},
                    {"id": "G5", "label": f"{retest.get('blocked_requests', 0)} requests blocked", "type": "outcome_blocked", "status": "MEASURED"}],
                    "capital_preserved_usd": saved},
                "financial_exposure_saved": saved, "financial_exposure_period": "per_matched_retest_event",
                "financial_exposure_currency": "USD", "executive_summary": summary,
                "git_pull_request": {"simulated": True, "title": "Reference concurrency guard; review template applicability",
                                     "branch": "aigis/reference-patch", "diff": diff, "commit_message": summary}}
