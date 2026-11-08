"""Verify the review fixes three times with isolated databases."""
import asyncio
import csv
from contextlib import ExitStack, closing
from pathlib import Path
import sqlite3
import tempfile
import time
from unittest.mock import patch

from backend import database as db
from backend.agents.adversarial_trainer import AdversarialTrainer
from backend.agents.fintech_sentinel import FinTechSentinelAgent
from backend.agents.quant_investigator import DeepQuantInvestigatorAgent
from backend.mock_target.store import mock_store


async def verify_recheck():
    mock_store.reset()
    mock_store.set_all_patches(True)
    mock_store.budget_remaining = 0
    result = await AdversarialTrainer().run_multicycle_recheck(2, 3)
    assert all(c['approved'] == 1 for c in result['cycles_history'])
    assert result['success'] and result['mitigation_rate'] == 100
    print('PASS recheck resets exhausted state and approves one legitimate claim per cycle')
    mock_store.reset()
    with patch.object(mock_store, 'claim_voucher', mock_store._claim_voucher_unlocked):
        result = await AdversarialTrainer().run_multicycle_recheck(2, 3)
    assert result['total_leaked'] == 4
    assert not result['success'] and result['verdict'].startswith('FAILED')
    print('PASS broken-guard negative control fails:', result['total_leaked'], 'leaked')
    from unittest.mock import AsyncMock
    with patch.object(mock_store, 'claim_voucher', AsyncMock(return_value={'status_code': 400, 'error': 'budget exhausted'})):
        result = await AdversarialTrainer().run_multicycle_recheck(2, 3)
    assert not result['success'] and result['mitigation_rate'] == 0
    assert all(c['status'] == 'OVER_BLOCKED' and c['business_failures'] == 3 for c in result['cycles_history'])
    print('PASS reject-all negative control fails without counting business errors as mitigation')
    mock_store.reset()


def verify_database(root):
    path = str(root / 'isolated.db')
    with ExitStack() as stack:
        for key, value in {'DATASETS_DIR': str(root), 'UPLOADS_DIR': str(root),
                           'DB_PATH': path, 'ACTIVE_DB_PATH': path,
                           'ACTIVE_DB_NAME': 'isolated.db'}.items():
            stack.enter_context(patch.object(db, key, value))
        db.init_db()
        now = int(time.time() * 1000)
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.executemany('INSERT INTO telemetry (event_id, epoch_ms, user_id, api_endpoint, '
                             'transaction_amount_usd, status_code_unpatched, burst_stream_id, '
                             'is_datacenter_proxy) VALUES (?,?,?,?,?,?,?,?)',
                             [(f'benign{i}', now - 50000 + i, f'u{i}', '/api/v1/voucher/claim',
                               10, 200, '', 0) for i in range(1000)] +
                             [(f'attack{i}', now - 100 + i, 'attacker', '/api/v1/voucher/claim',
                               500, 200, 'burst', 1) for i in range(5)])
        investigator = DeepQuantInvestigatorAgent()
        metrics = investigator._compute_concurrency_metrics_in_process('/api/v1/voucher/claim', 60)
        assert metrics['total_analyzed'] == 1005 and metrics['has_collisions']
        assert metrics['dirty_read_count'] == 4 and metrics['max_loss_usd'] == 2000
        print('PASS investigator detects newer attack beyond old row cap')
        with closing(sqlite3.connect(path)) as conn:
            count = conn.execute('SELECT COUNT(*) FROM telemetry WHERE epoch_ms >= ?', (now - 60000,)).fetchone()[0]
        sentinel = FinTechSentinelAgent(path)
        state = sentinel.evaluate_telemetry(window_seconds=60, policies_override=[], now_override=now / 1000)
        assert count == 1005 and state['tps'] == round(count / 60, 2)
        assert state['drain_velocity_usd_s'] == round((1000 * 10 + 5 * 500) / 60, 2)
        print('PASS sentinel uses complete window for TPS and drain')

        # A standard telemetry CSV is recognized by count + event_id, not column order.
        with closing(sqlite3.connect(path)) as conn:
            headers = [r[1] for r in conn.execute('PRAGMA table_info(telemetry)')]
        values = {h: '' for h in headers}
        values.update(event_id='csv-event', user_id='csv-user', epoch_ms=str(now),
                      api_endpoint='/api/v1/voucher/claim', transaction_amount_usd='10',
                      status_code_unpatched='200', is_attack='0')
        headers[0], headers[3] = headers[3], headers[0]
        csv_path = root / 'reordered.csv'
        with csv_path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerow([values[h] for h in headers])
        result = db.import_custom_csv_to_db(str(csv_path))
        assert result['success']
        with closing(sqlite3.connect(path)) as conn:
            row = conn.execute('SELECT event_id, user_id FROM telemetry').fetchone()
        assert row == ('csv-event', 'csv-user')
        print('PASS reordered CSV correctly maps named columns:', row)

        # A duplicate in a later batch must roll back the complete replacement.
        csv_path = root / 'duplicates.csv'
        with csv_path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            ordered = sorted(headers, key=lambda h: list(values).index(h))
            writer.writerow(ordered)
            writer.writerow([values[h] for h in ordered])
            writer.writerow([values[h] for h in ordered])
        result = db.import_custom_csv_to_db(str(csv_path), chunk_size=1)
        assert not result['success']
        with closing(sqlite3.connect(path)) as conn:
            count = conn.execute('SELECT COUNT(*) FROM telemetry').fetchone()[0]
        assert count == 1
        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute('SELECT event_id, user_id FROM telemetry').fetchone() == row
            assert not conn.execute("SELECT name FROM sqlite_master WHERE name LIKE '_aigis_import_%'").fetchall()
        print('PASS failed import preserves prior data and rolls back staging table')

        # Invalid numeric fields and malformed full-size headers must also be atomic.
        for bad_field in ('epoch_ms', 'transaction_amount_usd', 'header'):
            bad_values = dict(values)
            bad_header = list(values)
            if bad_field == 'header':
                bad_header[-1] = 'unexpected_column'
                bad_values['unexpected_column'] = ''
            else:
                bad_values[bad_field] = 'not-a-number'
            with csv_path.open('w', newline='', encoding='utf-8') as handle:
                writer = csv.writer(handle)
                writer.writerow(bad_header)
                writer.writerow([bad_values[h] for h in bad_header])
            assert not db.import_custom_csv_to_db(str(csv_path))['success']
            with closing(sqlite3.connect(path)) as conn:
                assert conn.execute('SELECT event_id, user_id FROM telemetry').fetchone() == row
        print('PASS malformed telemetry headers and numeric values preserve existing data')


if __name__ == '__main__':
    for attempt in range(1, 4):
        print(f'--- Independent fix verification {attempt}/3 ---')
        asyncio.run(verify_recheck())
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            verify_database(Path(directory))
