"""Independent scenario stress fixtures, not a real-world accuracy benchmark."""
import random
from backend.traffic_classifier import classify_traffic_row, _evaluation_metrics


def evaluate_classifier(seed=1729, per_scenario=100):
    rng = random.Random(seed)
    scenarios = {
        "legitimate_automation": (False, {"user_agent": "python-httpx/0.28", "has_idempotency_key": 1}),
        "legitimate_cloud_customer": (False, {"ip_isp": "Amazon Web Services", "is_datacenter_proxy": 1, "has_idempotency_key": 1}),
        "browser_fingerprint_attack": (True, {"user_agent": "Mozilla/5.0", "has_idempotency_key": 0}),
        "low_and_slow_abuse": (True, {"user_agent": "Mozilla/5.0", "has_idempotency_key": 1}),
        "unmarked_concurrent_attack": (True, {"user_agent": "Mozilla/5.0", "has_idempotency_key": 0}),
        "observable_automated_abuse": (True, {"user_agent": "curl/8", "is_datacenter_proxy": 1, "has_idempotency_key": 0}),
    }
    reports = {}
    totals = [0, 0, 0, 0]
    for name, (attack, features) in scenarios.items():
        counts = [0, 0, 0, 0]
        for index in range(per_scenario):
            # No is_attack, attack_type or attacker-named IDs enter the classifier.
            row = {"api_endpoint": "/api/v1/voucher/claim", "burst_stream_id": "", "burst_concurrency_rank": "",
                   "user_id": f"customer_{rng.randrange(100000)}", "epoch_ms": index * rng.randrange(1000, 5000), **features}
            predicted = classify_traffic_row(row)["is_attack"]
            counts[0 if attack and predicted else 1 if predicted else 3 if attack else 2] += 1
        totals = [a+b for a, b in zip(totals, counts)]
        reports[name] = {**_evaluation_metrics(*counts, {}), "coverage": 1.0,
                         "caveat": "Independent hand-authored synthetic stress fixtures; not simulator output or real-world validation.",
                         "observability_note": "No timing-aggregation feature; low-and-slow and unmarked bursts may be unobservable."}
    overall = _evaluation_metrics(*totals, {})
    overall['caveat'] = "Independent synthetic stress fixtures; not a real-world benchmark."
    return {"seed": seed, "fixture_version": 1, "per_scenario": per_scenario,
            "evaluation_scope": "INDEPENDENT_SYNTHETIC_STRESS_FIXTURES_NOT_REAL_WORLD_BENCHMARK",
             "scenarios": reports, "overall": overall}


def evaluate_temporal_holdout(seed=9187):
    """Separate sequence fixtures; thresholds are fixed, not fitted to labels."""
    from backend.temporal_classifier import classify_event_sequence
    rng = random.Random(seed)
    reports = {}
    for name, attack, spacing, identity in (
        ('browser_burst', True, 10, 'shared'),
        ('legitimate_retry_burst', False, 10, 'shared'),
        ('legitimate_automation', False, 1500, 'shared'),
        ('low_and_slow', True, 2000, 'shared'),
        ('distributed_unobservable', True, 10, 'distinct'),
    ):
        rows = [{'epoch_ms': index * spacing + rng.randrange(3),
                 'user_id': f'customer_{index}' if identity == 'distinct' else 'customer',
                 'api_endpoint': '/api/v1/voucher/claim', 'user_agent': 'Mozilla/5.0',
                 'has_idempotency_key': 1} for index in range(20)]
        predicted = classify_event_sequence(rows)
        positive = sum(row['is_attack'] for row in predicted)
        reports[name] = _evaluation_metrics(positive if attack else 0, positive if not attack else 0,
                                            20-positive if not attack else 0, 20-positive if attack else 0, {})
    return {'scope': 'HELD_OUT_SYNTHETIC_SEQUENCES_NOT_REAL_WORLD', 'seed': seed,
            'thresholds': {'window_ms': 1000, 'threshold': 5}, 'scenarios': reports,
            'limitations': 'Timing alone cannot distinguish legitimate retries, or detect all low-rate/distributed abuse.'}


if __name__ == "__main__":
    import json
    print(json.dumps(evaluate_classifier(), indent=2))
