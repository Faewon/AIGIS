import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend import job_queue as jobs


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict('os.environ', {'AIGIS_RUN_DB': str(Path(directory.name) / 'runs.db')})
        env.start()
        self.addCleanup(env.stop)

    def test_capacity_cancel_and_atomic_claim(self):
        run_id = jobs.submit({'rounds': 1, 'burst_streams': 3}, capacity=1)
        with self.assertRaises(OverflowError):
            jobs.submit({}, capacity=1)
        with ThreadPoolExecutor(max_workers=4) as pool:
            claimed = list(pool.map(jobs.claim, ['one', 'two', 'three', 'four']))
        self.assertEqual(sum(x is not None for x in claimed), 1)
        self.assertEqual(jobs.cancel(run_id)['cancel'], 1)
        queued = jobs.submit({'rounds': 1}, capacity=2)
        self.assertEqual(jobs.cancel(queued)['status'], 'CANCELLED')

    def test_expired_lease_and_timeout_are_not_requeued(self):
        run_id = jobs.submit({'rounds': 1})
        jobs.claim('worker')
        with jobs.connection() as conn:
            conn.execute('UPDATE benchmark_jobs SET heartbeat=0 WHERE run_id=?', (run_id,))
        conn.close()
        self.assertIsNone(jobs.claim('new-worker'))
        self.assertEqual(jobs.lookup(run_id)['status'], 'INTERRUPTED')
        run_id = jobs.submit({'rounds': 1})
        jobs.claim('worker', timeout=-1)
        self.assertIsNone(jobs.claim('new-worker'))
        self.assertEqual(jobs.lookup(run_id)['status'], 'TIMED_OUT')

    def test_worker_completion_and_cancellation(self):
        async def exercise():
            task = asyncio.create_task(jobs.worker())
            try:
                run_id = jobs.submit({'rounds': 1, 'burst_streams': 3, 'seed': 42})
                for _ in range(100):
                    await asyncio.sleep(.05)
                    if jobs.lookup(run_id)['status'] not in ('QUEUED', 'RUNNING'):
                        break
                job = jobs.lookup(run_id)
                self.assertEqual(job['status'], 'COMPLETED')
                self.assertEqual(job['run']['run_id'], run_id)
                self.assertEqual(job['run']['status'], 'COMPLETED')
                async def slow(*args, **kwargs):
                    await asyncio.sleep(30)
                with patch('backend.agents.adversarial_trainer.AdversarialTrainer.train_adversarial_rounds', slow):
                    cancelled = jobs.submit({'rounds': 1, 'burst_streams': 3})
                    for _ in range(30):
                        await asyncio.sleep(.05)
                        if jobs.lookup(cancelled)['status'] == 'RUNNING':
                            break
                    jobs.cancel(cancelled)
                    for _ in range(30):
                        await asyncio.sleep(.05)
                        if jobs.lookup(cancelled)['status'] == 'CANCELLED':
                            break
                    self.assertEqual(jobs.lookup(cancelled)['status'], 'CANCELLED')
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        asyncio.run(exercise())

    def test_replay_consumes_saved_manifest_not_generator(self):
        from backend.agents.adversarial_trainer import AdversarialTrainer
        first = asyncio.run(AdversarialTrainer().train_adversarial_rounds(1, 3, 42))
        with patch('backend.agents.adversarial_trainer.make_workload', side_effect=AssertionError('Do not regenerate')):
            second = asyncio.run(AdversarialTrainer().train_adversarial_rounds(
                1, 3, 42, workloads=first['configuration']['workloads']))
        self.assertEqual(first['configuration']['workloads'], second['configuration']['workloads'])

    def test_api_submit_cancel_and_manifest_corruption(self):
        from fastapi.testclient import TestClient
        from backend import server
        from backend.run_store import save_run
        from backend.agents.adversarial_trainer import AdversarialTrainer
        client = TestClient(server.app)
        headers = {'X-AIGIS-Token': server.AIGIS_API_TOKEN}
        response = client.post('/api/v1/wargame/jobs', headers=headers, json={'rounds': 1, 'burst_streams': 3})
        self.assertEqual(response.status_code, 202)
        run_id = response.json()['run_id']
        self.assertEqual(client.get(f'/api/v1/wargame/jobs/{run_id}', headers=headers).json()['status'], 'QUEUED')
        self.assertEqual(client.post(f'/api/v1/wargame/jobs/{run_id}/cancel', headers=headers, json={}).json()['status'], 'CANCELLED')
        self.assertEqual(client.post('/api/v1/wargame/jobs', headers=headers, json={'rounds': '1'}).status_code, 422)
        result = asyncio.run(AdversarialTrainer().train_adversarial_rounds(1, 3, 42))
        result['configuration']['workloads'][0]['start_delays_ms'][0] = 500
        save_run(result['run_id'], result['configuration'], result)
        self.assertEqual(client.post(f"/api/v1/wargame/runs/{result['run_id']}/replay", headers=headers, json={}).status_code, 409)

    def test_shadow_handles_malformed_timestamps(self):
        from backend.temporal_classifier import classify_event_sequence
        for value in ('not-a-number', float('nan'), float('inf'), -1, True):
            result = classify_event_sequence([{'user_id': 'synthetic', 'endpoint': '/local', 'epoch_ms': value}])
            self.assertEqual(result[0]['temporal_state'], 'INSUFFICIENT_DATA')
