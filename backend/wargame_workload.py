"""Versioned synthetic workloads; no external targets or generated code."""
import hashlib
import json
import random
from pathlib import Path

VERSION = 3


def make_workload(seed, scenario, count, round_index=0):
    rng = random.Random(f'{seed}:{scenario}:{round_index}')
    workload = {"version": VERSION, "scenario": scenario, "burst_streams": count,
                "start_delays_ms": [round(rng.uniform(0, 1.5), 6) for _ in range(count)]}
    workload['fixture_order'] = rng.sample([0, 1], 2)
    workload['order_id'] = f'synthetic-order-{rng.getrandbits(64):016x}'
    workload["hash"] = hashlib.sha256(json.dumps(workload, sort_keys=True).encode()).hexdigest()
    return workload


def validate_workloads(workloads, rounds, count, scenarios):
    if not isinstance(workloads, list) or len(workloads) != rounds:
        raise ValueError('Manifest round count mismatch')
    for index, workload in enumerate(workloads):
        if not isinstance(workload, dict):
            raise ValueError('Invalid manifest')
        payload = {k: v for k, v in workload.items() if k != 'hash'}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        delays = workload.get('start_delays_ms')
        if (workload.get('version') != VERSION or workload.get('hash') != digest
                or workload.get('scenario') != scenarios[index % len(scenarios)]
                or workload.get('burst_streams') != count or not isinstance(delays, list)
                or workload.get('fixture_order') not in ([0, 1], [1, 0])
                or not isinstance(workload.get('order_id'), str) or len(workload['order_id']) > 64
                or len(delays) != count or any(type(x) not in (int, float) or not 0 <= x <= 1.5 for x in delays)):
            raise ValueError('Incompatible or corrupted workload manifest')


def execution_versions():
    root = Path(__file__).parent
    paths = ['wargame_workload.py', 'agents/sandbox_runner.py', 'mock_target/store.py',
             'agents/adversarial_trainer.py', 'agents/blue_aegis.py', 'agents/arbiter.py',
             'evidence.py', 'patch_registry.py']
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode())
        digest.update((root / path).read_bytes().replace(b'\r\n', b'\n'))
    return {'schema': 1, 'scenario': 1, 'control': 1, 'code_sha256': digest.hexdigest()}
