from contextlib import ExitStack
import os
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from backend import database, postgres_source as source, server


class PostgreSQLSourceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        root = Path(directory)
        for key, value in {'DATASETS_DIR': directory, 'UPLOADS_DIR': str(root / 'uploads'),
                           'DB_PATH': str(root / 'default.db'), 'ACTIVE_DB_PATH': str(root / 'default.db'),
                           'ACTIVE_DB_NAME': 'default.db'}.items():
            self.stack.enter_context(patch.object(database, key, value))
        database.init_db()
        self.stack.enter_context(patch.dict(os.environ, {'AIGIS_POSTGRES_UNIT': 'secret-never-returned'}))
        self.stack.enter_context(patch.object(source, '_profiles', {}))
        self.stack.enter_context(patch.object(source, '_sources', {}))
        self.client = TestClient(server.app)
        self.headers = {'X-AIGIS-Token': server.AIGIS_API_TOKEN}

    def remote(self):
        remote = MagicMock()
        remote.__enter__.return_value = remote
        remote.execute.return_value.fetchall.return_value = [('user_id', 'text'), ('epoch_ms', 'bigint')]
        cursor = remote.cursor.return_value.__enter__.return_value
        cursor.fetchmany.side_effect = [[('synthetic-a', 100), ('synthetic-b', 200), ('synthetic-c', 300)]]
        return remote

    def test_discovery_redaction_and_auth_validation(self):
        with patch.object(source, '_connect', return_value=self.remote()), patch.object(source, '_tables', return_value=[('public', 'events')]):
            result = source.discover('AIGIS_POSTGRES_UNIT')
        self.assertEqual(result['tables'], [{'schema': 'public', 'table': 'events'}])
        self.assertNotIn('secret-never-returned', str(result))
        endpoint = '/api/v1/database/postgres/discover'
        self.assertEqual(self.client.post(endpoint, json={}).status_code, 401)
        self.assertEqual(self.client.post(endpoint, headers=self.headers, json={'password': 'never-accept'}).status_code, 422)
        with patch.object(source, 'discover', side_effect=RuntimeError('secret-never-returned')):
            response = self.client.post(endpoint, headers=self.headers, json={'profile': 'AIGIS_POSTGRES_UNIT'})
        self.assertEqual(response.status_code, 502)
        self.assertNotIn('secret-never-returned', response.text)

    def test_snapshot_pagination_metadata_and_sqlite_restore(self):
        source._profiles['unit'] = 'AIGIS_POSTGRES_UNIT'
        sql = types.SimpleNamespace(SQL=lambda value: MagicMock(), Identifier=lambda value: value)
        with patch.dict('sys.modules', {'psycopg': types.SimpleNamespace(sql=sql)}), patch.object(
                source, '_connect', return_value=self.remote()), patch.object(source, '_tables', return_value=[('public', 'events')]):
            result = source.snapshot('unit', 'public', 'events', 2)
        self.assertTrue(result['success'])
        self.assertTrue(result['truncated'])
        self.assertEqual(result['rows_imported'], 2)
        self.assertFalse(database.get_active_db_info()['live'])
        self.assertEqual(database.query_table_data('telemetry')['total_rows'], 2)
        self.assertEqual(database.query_telemetry_rows()[0]['user_id'], 'synthetic-b')
        self.assertTrue(database.set_active_db(database.DB_PATH)['success'])
        self.assertNotIn('snapshot_id', database.get_active_db_info())

    def test_failed_snapshot_preserves_dataset_and_removes_staging(self):
        previous = database.ACTIVE_DB_PATH
        source._profiles['unit'] = 'AIGIS_POSTGRES_UNIT'
        sql = types.SimpleNamespace(SQL=lambda value: MagicMock(), Identifier=lambda value: value)
        with patch.dict('sys.modules', {'psycopg': types.SimpleNamespace(sql=sql)}), patch.object(
                source, '_connect', side_effect=RuntimeError('private connection error')):
            with self.assertRaises(RuntimeError):
                source.snapshot('unit', 'public', 'events', 2)
        self.assertEqual(database.ACTIVE_DB_PATH, previous)
        self.assertEqual(list(Path(database.UPLOADS_DIR).glob('postgres_*.db')), [])

    def test_driver_enforces_readonly_and_timeouts(self):
        driver = types.SimpleNamespace(connect=MagicMock(return_value=self.remote()))
        with patch.dict('sys.modules', {'psycopg': driver}):
            source._connect('AIGIS_POSTGRES_UNIT')
        kwargs = driver.connect.call_args.kwargs
        self.assertEqual(kwargs['connect_timeout'], 5)
        self.assertIn('default_transaction_read_only=on', kwargs['options'])
        self.assertIn('statement_timeout=10000', kwargs['options'])
        driver.connect.return_value.execute.assert_called_once_with('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
