/* Evidence presentation only: never executes scenarios or generated code. */
function wargameVerificationView(result) {
    const regression = result.regression_report || {};
    const pairs = result.round_evidence || [];
    const passed = result.success === true
        && result.assessment_state === 'MITIGATION_VERIFIED_IN_MOCK'
        && regression.status === 'ZERO_REGRESSION_VERIFIED'
        && Number(regression.sample_users_tested) > 0
        && regression.legitimate_requests_approved === regression.sample_users_tested
        && pairs.length > 0
        && pairs.every(pair => pair.dossier?.assessment_state === 'MITIGATION_VERIFIED_IN_MOCK'
            && pair.retest?.illegal_claims_count === 0);
    return {
        passed,
        label: passed ? 'PASSED IN MOCK — tested workload only' : 'NOT VERIFIED — inspect evidence and regression',
        lines: [
            `Run: ${result.run_id ?? 'N/A'} | Seed: ${result.configuration?.seed ?? 'N/A'} | Requests per scenario: ${result.configuration?.burst_streams ?? 'N/A'}`,
            ...pairs.map((pair, index) =>
                `Round ${index + 1} | ${pair.attack?.scenario ?? pair.retest?.scenario ?? 'N/A'} | Baseline illegal: ${pair.attack?.illegal_claims_count ?? 'N/A'} | Control: mock configuration (see evidence) | Retest illegal: ${pair.retest?.illegal_claims_count ?? 'N/A'} | ${pair.dossier?.assessment_state ?? 'NOT_ASSESSED'}`),
            `Legitimate regression: ${regression.legitimate_requests_approved ?? 'N/A'}/${regression.sample_users_tested ?? 'N/A'} approved | False positives: ${regression.false_positive_rate ?? 'N/A'} | ${regression.status ?? 'NOT_ASSESSED'}`,
            'Scope: in-memory mock with synthetic data. Reference patch only; no production deployment or certification.'
        ]
    };
}

if (typeof module !== 'undefined') module.exports = {wargameVerificationView};
