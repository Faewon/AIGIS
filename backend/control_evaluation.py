"""Bounded local-only control ablation; separate from primary benchmark results."""
from unittest.mock import patch
from backend.simulation import simulation_scope
from backend.mock_target.store import mock_store
from backend.agents.sandbox_runner import SandboxRunnerAgent
from backend.agents.blue_aegis import BlueAegisAgent
from backend.agents.adversarial_trainer import SCENARIOS
from backend.wargame_workload import make_workload

CONTROLS = dict(zip(SCENARIOS, ('concurrency_mutex', 'bola_ownership_guard',
                               'state_machine_guard', 'parameter_validation')))


async def evaluate_controls(seed=1729, burst_streams=5):
    results = []
    for scenario in SCENARIOS:
        for mode in ('none', 'relevant', 'all', 'broken', 'reject_all'):
            with simulation_scope(seed):
                mock_store.set_all_patches(mode == 'all')
                if mode == 'relevant':
                    mock_store.patch_modules[CONTROLS[scenario]] = True
                workload = make_workload(seed, scenario, burst_streams)
                runner = SandboxRunnerAgent()
                # Fault injection stays within this task-local mock instance.
                method = {'TOCTOU_RACE_CONDITION': 'claim_voucher', 'BOLA_IDOR': 'withdraw_account_funds',
                          'NEGATIVE_AMOUNT_TAMPERING': 'process_checkout_payment',
                          'STEP_SKIPPING_STATE_BYPASS': 'execute_order_state_transition'}[scenario]
                async def reject(*args, **kwargs):
                    return {'status_code': 503, 'error': 'Injected reject-all control'}
                from contextlib import nullcontext
                from backend.simulation import current_target
                store = current_target()
                with patch.object(store, method, reject) if mode == 'reject_all' else nullcontext():
                    measured = await runner.execute_scenario(scenario, burst_streams, workload)
                    modules = dict(mock_store.patch_modules)
                    regression = await BlueAegisAgent().run_zero_regression_test(3, scenario, modules)
                verified = (measured['status'] == 'EXPLOIT_NEUTRALIZED'
                            and measured['illegal_claims_count'] == 0
                            and regression['status'] == 'ZERO_REGRESSION_VERIFIED')
                results.append({'scenario': scenario, 'mode': mode, 'control': CONTROLS[scenario],
                                'verified': verified, 'measurement': measured, 'regression': regression})
    return {'scope': 'LOCAL_MOCK_CONTROL_ABLATION', 'seed': seed, 'results': results}
