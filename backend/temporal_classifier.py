"""Observable timing signals, not proof of abuse; independent of ground-truth labels."""
from collections import defaultdict, deque
import math
from backend.traffic_classifier import classify_traffic_row


def classify_event_sequence(events, window_ms=1000, threshold=5):
    if not 1 <= window_ms <= 60000 or not 2 <= threshold <= 1000:
        raise ValueError('Invalid temporal detector limits')
    windows = defaultdict(deque)
    results = []
    if len(events) > 50000:
        raise ValueError('Temporal sample exceeds 50000 events')
    def timestamp_key(row):
        value = row.get('epoch_ms')
        return value if type(value) in (int, float) and math.isfinite(value) else 0
    for event in sorted(events, key=timestamp_key):
        result = classify_traffic_row(event)
        user = event.get('user_id')
        endpoint = event.get('api_endpoint') or event.get('endpoint')
        timestamp = event.get('epoch_ms')
        if (not user or not endpoint or type(timestamp) not in (int, float)
                or not math.isfinite(timestamp) or timestamp < 0):
            result['temporal_state'] = 'INSUFFICIENT_DATA'
        else:
            window = windows[(user, endpoint)]
            while window and timestamp - window[0] > window_ms:
                window.popleft()
            window.append(timestamp)
            signal = len(window) >= threshold
            result['temporal_state'] = 'SIGNAL_DETECTED' if signal else 'NO_TIMING_SIGNAL'
            result['window_count'] = len(window)
            if signal:
                result.update(is_attack=True, label='SUSPICIOUS', attack_type='TEMPORAL_RATE_SIGNAL')
                result['reasons'] = ['Repeated user/endpoint events within configured window; legitimate retries may also trigger.']
        results.append({'epoch_ms': event.get('epoch_ms'), **result})
    return results
