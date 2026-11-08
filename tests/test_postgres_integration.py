"""Opt-in PostgreSQL transaction fixture; never touches application tables."""
from concurrent.futures import ThreadPoolExecutor
import os
import unittest
import uuid


@unittest.skipUnless(os.getenv('AIGIS_TEST_POSTGRES_DSN'), 'Set AIGIS_TEST_POSTGRES_DSN for isolated PostgreSQL tests')
class PostgreSQLInvariantTests(unittest.TestCase):
    def test_application_source_snapshot(self):
        import psycopg
        from psycopg import sql
        from contextlib import ExitStack
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        from backend import database, postgres_source as source
        schema = 'aigis_source_' + uuid.uuid4().hex
        with psycopg.connect(os.environ['AIGIS_TEST_POSTGRES_DSN'], autocommit=True) as admin:
            admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            try:
                admin.execute(sql.SQL('CREATE TABLE {}.events(user_id TEXT, epoch_ms BIGINT)').format(sql.Identifier(schema)))
                admin.execute(sql.SQL('INSERT INTO {}.events VALUES(%s,%s),(%s,%s)').format(sql.Identifier(schema)),
                              ('synthetic-a', 100, 'synthetic-b', 200))
                with ExitStack() as stack:
                    directory = stack.enter_context(tempfile.TemporaryDirectory())
                    for key, value in {'DATASETS_DIR': directory, 'UPLOADS_DIR': str(Path(directory)/'uploads'),
                                       'ACTIVE_DB_PATH': str(Path(directory)/'default.db'), 'ACTIVE_DB_NAME': 'default.db'}.items():
                        stack.enter_context(patch.object(database, key, value))
                    stack.enter_context(patch.dict(os.environ, {'AIGIS_POSTGRES_INTEGRATION': os.environ['AIGIS_TEST_POSTGRES_DSN']}))
                    stack.enter_context(patch.object(source, '_profiles', {}))
                    stack.enter_context(patch.object(source, '_sources', {}))
                    found = source.discover('AIGIS_POSTGRES_INTEGRATION')
                    self.assertIn({'schema': schema, 'table': 'events'}, found['tables'])
                    imported = source.snapshot(found['source_id'], schema, 'events', 1)
                    self.assertTrue(imported['truncated'])
                    self.assertEqual(len(database.query_telemetry_rows()), 1)
                    with source._connect('AIGIS_POSTGRES_INTEGRATION') as readonly:
                        self.assertEqual(readonly.execute('SHOW transaction_read_only').fetchone()[0], 'on')
            finally:
                admin.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))

    def test_unique_claim_budget_and_rollback(self):
        import psycopg
        from psycopg import sql
        dsn = os.environ['AIGIS_TEST_POSTGRES_DSN']
        schema = 'aigis_test_' + uuid.uuid4().hex
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            try:
                def connect():
                    conn = psycopg.connect(dsn)
                    conn.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
                    return conn
                with connect() as conn:
                    conn.execute('CREATE TABLE budget(id INTEGER PRIMARY KEY, value INTEGER NOT NULL CHECK(value>=0))')
                    conn.execute('INSERT INTO budget VALUES(1,100)')
                    conn.execute('CREATE TABLE claims(user_id TEXT UNIQUE NOT NULL, amount INTEGER NOT NULL CHECK(amount>0))')
                def claim(_):
                    try:
                        with connect() as conn:
                            conn.execute('SELECT value FROM budget WHERE id=1 FOR UPDATE')
                            conn.execute('INSERT INTO claims VALUES(%s,%s)', ('same-user', 10))
                            changed = conn.execute('UPDATE budget SET value=value-10 WHERE id=1 AND value>=10').rowcount
                            if changed != 1:
                                raise ValueError('Insufficient budget')
                        return True
                    except psycopg.errors.UniqueViolation:
                        return False
                with ThreadPoolExecutor(max_workers=8) as pool:
                    self.assertEqual(sum(pool.map(claim, range(16))), 1)
                with connect() as conn:
                    self.assertEqual(conn.execute('SELECT value FROM budget').fetchone()[0], 90)
                    self.assertEqual(conn.execute('SELECT count(*) FROM claims').fetchone()[0], 1)
                with self.assertRaises(psycopg.errors.CheckViolation), connect() as conn:
                    conn.execute('UPDATE budget SET value=0')
                    conn.execute('INSERT INTO claims VALUES(%s,%s)', ('invalid', -1))
                with connect() as conn:
                    self.assertEqual(conn.execute('SELECT value FROM budget').fetchone()[0], 90)
                    conn.execute('INSERT INTO claims VALUES(%s,%s)', ('legitimate-user', 10))
                    conn.execute('UPDATE budget SET value=value-10 WHERE id=1')
            finally:
                admin.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
