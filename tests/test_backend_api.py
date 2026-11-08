"""HTTP integration for run manifests, replay, and unchanged dashboard contracts."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import server


class RunApiTests(unittest.TestCase):
    def test_recheck_manifest_preserves_control_state_and_replays(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', {'AIGIS_RUN_DB': str(Path(directory)/'runs.db')}):
            client = TestClient(server.app)
            headers = {'X-AIGIS-Token': server.AIGIS_API_TOKEN}
            server.mock_store.reset()
            server.mock_store.set_all_patches(True)
            server.mock_store.budget_remaining = 12345
            response = client.post('/api/v1/wargame/recheck_multicycle', headers=headers,
                                   json={'cycles': 2, 'burst_streams': 3, 'seed': 7})
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertTrue(result['success'])
            self.assertEqual(server.mock_store.budget_remaining, 12345)
            replay = client.post('/api/v1/wargame/runs/' + result['run_id'] + '/replay', headers=headers, json={})
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertTrue(replay.json()['success'])
            self.assertEqual(replay.json()['cycles_history'][0]['jitter_schedule_ms'], result['cycles_history'][0]['jitter_schedule_ms'])
            server.mock_store.reset()

    def test_full_workflow_manifest_replay_and_shared_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', {'AIGIS_RUN_DB': str(Path(directory)/'runs.db')}):
            client = TestClient(server.app)
            headers = {'X-AIGIS-Token': server.AIGIS_API_TOKEN}
            before = client.get('/api/v1/target/status', headers=headers).json()
            response = client.post('/api/v1/wargame/run_full', headers=headers,
                                   json={'rounds': 2, 'burst_streams': 3, 'seed': 42})
            self.assertEqual(response.status_code, 200, response.text)
            run = response.json()
            self.assertIn('rea', run)
            self.assertIn('red_team', run)
            self.assertIn('regression', run)
            self.assertEqual(run['training_summary']['total_capital_defended_usd'], 16000)
            saved = client.get('/api/v1/wargame/runs/' + run['run_id'], headers=headers).json()
            self.assertEqual(saved['configuration']['seed'], 42)
            replay = client.post('/api/v1/wargame/runs/' + run['run_id'] + '/replay', headers=headers, json={})
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertEqual(replay.json()['training_summary'], run['training_summary'])
            self.assertEqual(client.get('/api/v1/target/status', headers=headers).json(), before)
            self.assertIn('x-request-id', response.headers)
