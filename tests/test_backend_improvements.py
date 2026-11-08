import asyncio
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from backend import database
from backend.agents.adversarial_trainer import AdversarialTrainer
from backend.agents.arbiter import ArenaArbiterAgent
from backend.agents.fintech_sentinel import FinTechSentinelAgent
from backend.agents.quant_investigator import DeepQuantInvestigatorAgent
from backend.agents.secops_copilot import SecOpsCopilotAgent
from backend.evidence import dataset_identity
from backend.mock_target.store import mock_store
from backend.patch_registry import python_guard
from backend.simulation import simulation_scope


class ProvenanceTests(unittest.TestCase):
    def test_read_snapshot_keeps_counts_and_rows_consistent_during_append(self):
        from backend import telemetry_analysis
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'snapshot.db')
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('PRAGMA journal_mode=WAL')
                database._create_telemetry_table(conn, 'telemetry')
                conn.execute("INSERT INTO telemetry(event_id,epoch_ms,user_id,api_endpoint,is_datacenter_proxy) VALUES ('first',1000,'one','/claim',0)")
            actual_connect = telemetry_analysis.get_connection
            def connection(*args, **kwargs):
                conn = actual_connect(*args, **kwargs)
                def trace(sql):
                    if sql.startswith('SELECT user_id, COUNT(*)'):
                        with closing(sqlite3.connect(path)) as writer, writer:
                            writer.execute("INSERT INTO telemetry(event_id,epoch_ms,user_id,api_endpoint,is_datacenter_proxy) VALUES ('later',1001,'two','/claim',0)")
                conn.set_trace_callback(trace)
                return conn
            with patch.object(telemetry_analysis, 'get_connection', side_effect=connection):
                result = telemetry_analysis.sentinel_window(path, 60, 2000)
            self.assertEqual(result['total'], 1)
            self.assertTrue(result['context']['dataset_revision'].startswith('snapshot-changed:'))
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM telemetry').fetchone()[0], 2)

    def test_same_path_replacement_invalidates_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'dataset.db')
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('CREATE TABLE telemetry(name)')
            agent = DeepQuantInvestigatorAgent()
            with patch('backend.agents.quant_investigator.get_active_db_path', return_value=path):
                report = asyncio.run(agent.diagnose_anomaly())
                self.assertIsNotNone(agent.latest_report)
                with closing(sqlite3.connect(path)) as conn, conn:
                    conn.execute("INSERT INTO telemetry VALUES ('changed')")
                self.assertIsNone(agent.latest_report)
                self.assertNotEqual(report['context']['dataset_revision'], dataset_identity(path).dataset_revision)

    def test_selected_dataset_and_no_fabricated_copilot_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'custom.db')
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('CREATE TABLE telemetry(name,value)')
            with patch.object(database, 'ACTIVE_DB_PATH', path):
                state = FinTechSentinelAgent().evaluate_telemetry()
                self.assertEqual(state['database_path'], path)
                self.assertEqual(state['assessment_state'], 'INSUFFICIENT_DATA')
                result = asyncio.run(SecOpsCopilotAgent().answer_query('diagnose'))
                for invented in ('$7,500', '93.3%', '1.45ms'):
                    self.assertNotIn(invented, result['reply'])
                self.assertEqual(result['assessment_state'], 'INSUFFICIENT_DATA')

    def test_mismatched_dossier_rejected(self):
        attack = {'scenario': 'TOCTOU_RACE_CONDITION', 'total_requests': 3, 'illegal_claims_count': 2}
        retest = {'scenario': 'BOLA_IDOR', 'total_requests': 2, 'blocked_requests': 2, 'status': 'EXPLOIT_NEUTRALIZED'}
        result = asyncio.run(ArenaArbiterAgent().generate_dossier(attack, {}, {}, retest))
        self.assertEqual(result['status'], 'INCOMPATIBLE_EVIDENCE')
        self.assertIsNone(result['patched_score'])
        self.assertIsNone(result['financial_exposure_saved'])


class SimulationTests(unittest.TestCase):
    def test_parallel_training_replay_and_persistence(self):
        from backend.run_store import get_run
        async def run():
            return await asyncio.gather(*(AdversarialTrainer().train_adversarial_rounds(2, 3, seed=42) for _ in range(2)))
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', {'AIGIS_RUN_DB': str(Path(directory)/'runs.db')}):
            mock_store.reset()
            mock_store.budget_remaining = 12345
            first, second = asyncio.run(run())
            self.assertNotEqual(first['run_id'], second['run_id'])
            self.assertEqual(mock_store.budget_remaining, 12345)
            self.assertEqual(first['training_summary'], second['training_summary'])
            self.assertEqual(first['training_summary']['total_capital_defended_usd'], 16000)
            self.assertEqual(first['dossier']['scenario'], 'BOLA_IDOR')
            self.assertEqual(first['dossier']['financial_exposure_saved'], 15000)
            self.assertEqual(get_run(first['run_id'])['configuration']['seed'], 42)
            for pair in first['round_evidence']:
                self.assertEqual(pair['attack']['evidence']['workload_id'], pair['retest']['evidence']['workload_id'])
            mock_store.reset()

    def test_exception_restores_task_local_store(self):
        mock_store.reset()
        original = mock_store.budget_remaining
        with self.assertRaises(RuntimeError):
            with simulation_scope(1):
                mock_store.budget_remaining = 0
                raise RuntimeError('cancelled run')
        self.assertEqual(mock_store.budget_remaining, original)


class GuardTests(unittest.TestCase):
    def test_canonical_guard_uses_authenticated_identity_and_owner_release(self):
        async def run():
            namespace = {}
            exec(python_guard(), namespace)
            class Redis:
                def __init__(self):
                    self.locks = {}
                    self.releases = []
                async def set(self, key, value, **kwargs):
                    if key in self.locks:
                        return False
                    self.locks[key] = value
                    return True
                async def eval(self, script, count, key, value):
                    self.releases.append((key, value))
                    if self.locks.get(key) == value:
                        del self.locks[key]
            redis = Redis()
            calls, statuses = [], []
            async def app(scope, receive, send):
                calls.append(scope['state']['user_id'])
                await asyncio.sleep(.01)
            async def receive():
                return {'type': 'http.request', 'body': b''}
            async def send(message):
                if message['type'] == 'http.response.start':
                    statuses.append(message['status'])
            guard = namespace['RedisIdempotencyMiddleware'](app, redis)
            def scope(header, user='authenticated'):
                return {'type': 'http', 'method': 'POST', 'path': '/api/v1/voucher/claim',
                        'state': {'user_id': user} if user else {}, 'headers': [(b'x-user-id', header)]}
            await asyncio.gather(*(guard(scope(header), receive, send) for header in (b'fake-a', b'fake-b')))
            self.assertEqual(calls, ['authenticated'])
            self.assertEqual(statuses, [429])
            self.assertFalse(redis.locks)
            self.assertEqual(len(redis.releases), 1)
            await guard(scope(b'fake', None), receive, send)
            self.assertEqual(statuses[-1], 401)
            with patch.object(redis, 'set', side_effect=OSError('Redis offline')):
                await guard(scope(b'fake'), receive, send)
            self.assertEqual(statuses[-1], 503)
        asyncio.run(run())


class ReproducibilityTests(unittest.TestCase):
    def test_seeded_dataset_bytes_and_stress_evaluation(self):
        from backend import data_simulator
        from backend.classifier_evaluation import evaluate_classifier
        with tempfile.TemporaryDirectory() as directory:
            csv = str(Path(directory)/'data.csv')
            with patch.object(data_simulator, 'CSV_PATH', csv), patch.object(data_simulator, 'META_PATH', str(Path(directory)/'meta.json')), patch.object(data_simulator, 'PROJECT_ROOT', directory):
                data_simulator.generate_million_row_dataset(total_rows=100, seed=7)
                first = Path(csv).read_bytes()
                data_simulator.generate_million_row_dataset(total_rows=100, seed=7)
                self.assertEqual(first, Path(csv).read_bytes())
        report = evaluate_classifier(per_scenario=10)
        self.assertEqual(report['scenarios']['low_and_slow_abuse']['confusion_matrix']['fn'], 10)
        self.assertEqual(report, evaluate_classifier(per_scenario=10))
