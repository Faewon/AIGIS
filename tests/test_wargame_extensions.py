"""Local-only verification of run lifecycle, input validation and control quality."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from backend import server
from backend.agents.adversarial_trainer import AdversarialTrainer
from backend.control_evaluation import evaluate_controls
from backend.run_store import list_runs, get_run
from backend.temporal_classifier import classify_event_sequence
from backend.wargame_workload import make_workload


class WargameExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env = patch.dict('os.environ', {'AIGIS_RUN_DB': str(Path(self.directory.name) / 'runs.db')})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_seed_changes_workload_and_is_reproducible(self):
        self.assertEqual(make_workload(42, 'TOCTOU', 5), make_workload(42, 'TOCTOU', 5))
        self.assertNotEqual(make_workload(42, 'TOCTOU', 5), make_workload(43, 'TOCTOU', 5))

    def test_failure_and_cancellation_are_saved(self):
        for error, expected in ((RuntimeError('fixture'), 'FAILED'), (asyncio.CancelledError(), 'CANCELLED')):
            trainer = AdversarialTrainer()
            with patch.object(trainer.sandbox_agent, 'execute_scenario', AsyncMock(side_effect=error)):
                with self.assertRaises(type(error)):
                    asyncio.run(trainer.train_adversarial_rounds(1, 3, 42))
            run = next(r for r in list_runs() if r['status'] == expected)
            self.assertEqual(get_run(run['run_id'])['result']['assessment_state'], 'NOT_ASSESSED')

    def test_all_scenario_controls_and_negative_controls(self):
        report = asyncio.run(evaluate_controls(42, 3))
        self.assertEqual(len(report['results']), 20)
        for result in report['results']:
            self.assertEqual(result['verified'], result['mode'] in ('all', 'relevant'), result)

    def test_strict_inputs_and_stage_isolation(self):
        client = TestClient(server.app)
        headers = {'X-AIGIS-Token': server.AIGIS_API_TOKEN}
        for body in ({'rounds': 0}, {'burst_streams': 1}, {'seed': -1}, {'rounds': '3'}, {'unknown': True}):
            self.assertEqual(client.post('/api/v1/wargame/run_full', headers=headers, json=body).status_code, 422)
        self.assertEqual(client.post('/api/v1/wargame/run_full', headers=headers, content='invalid').status_code, 422)
        first = {**headers, 'X-AIGIS-Wargame-Session': 'extension-test-a'}
        second = {**headers, 'X-AIGIS-Wargame-Session': 'extension-test-b'}
        for h in (first, second):
            self.assertEqual(client.post('/api/v1/target/reset', headers=h).status_code, 200)
        client.post('/api/v1/wargame/stage/3_sandbox_attack', headers=first, json={'burst_streams': 3})
        a = client.get('/api/v1/target/status', headers=first).json()
        b = client.get('/api/v1/target/status', headers=second).json()
        self.assertGreater(a['vouchers_issued_count'], 0)
        self.assertEqual(b['vouchers_issued_count'], 0)
        self.assertEqual(client.get('/api/v1/wargame/runs', headers=headers).status_code, 200)

    def test_temporal_features_do_not_use_labels(self):
        events = [{'user_id': 'customer', 'api_endpoint': '/claim', 'epoch_ms': i * 10,
                   'user_agent': 'Mozilla/5.0', 'is_attack': False} for i in range(8)]
        results = classify_event_sequence(events)
        self.assertEqual(results[-1]['temporal_state'], 'SIGNAL_DETECTED')
        altered = [{**event, 'is_attack': True, 'attack_type': 'fake'} for event in events]
        self.assertEqual(results, classify_event_sequence(altered))
        self.assertEqual(classify_event_sequence([{}])[0]['temporal_state'], 'INSUFFICIENT_DATA')
        slow = [{**event, 'epoch_ms': i * 2000} for i, event in enumerate(events)]
        self.assertTrue(all(r['temporal_state'] == 'NO_TIMING_SIGNAL' for r in classify_event_sequence(slow)))
        from backend.classifier_evaluation import evaluate_temporal_holdout
        holdout = evaluate_temporal_holdout()
        self.assertGreater(holdout['scenarios']['browser_burst']['recall_pct'], 0)
        self.assertGreater(holdout['scenarios']['legitimate_retry_burst']['false_positive_rate_pct'], 0)
        self.assertEqual(holdout['scenarios']['low_and_slow']['recall_pct'], 0)


class SQLiteControlIntegrationTests(unittest.TestCase):
    def test_atomic_unique_claim_across_connections_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'target.db')
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.executescript('CREATE TABLE budget(value INTEGER NOT NULL CHECK(value>=0));'
                                   'INSERT INTO budget VALUES(100);'
                                   'CREATE TABLE claims(user TEXT UNIQUE, amount INTEGER CHECK(amount>0));')
            def claim(_):
                conn = sqlite3.connect(path, timeout=10)
                try:
                    with conn:
                        conn.execute('BEGIN IMMEDIATE')
                        conn.execute('INSERT INTO claims VALUES(?, ?)', ('same-user', 10))
                        conn.execute('UPDATE budget SET value=value-10 WHERE value>=10')
                    return True
                except sqlite3.IntegrityError:
                    return False
                finally:
                    conn.close()
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(sum(pool.map(claim, range(16))), 1)
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(conn.execute('SELECT value FROM budget').fetchone()[0], 90)
                with self.assertRaises(sqlite3.IntegrityError), conn:
                    conn.execute('UPDATE budget SET value=0')
                    conn.execute('INSERT INTO claims VALUES(?,?)', ('invalid', -1))
                self.assertEqual(conn.execute('SELECT value FROM budget').fetchone()[0], 90)
