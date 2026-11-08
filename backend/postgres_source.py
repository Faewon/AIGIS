"""Read-only PostgreSQL discovery and bounded snapshots for SQLite analysis.

Credentials are supplied through a server-side environment variable, never API
request bodies. No arbitrary SQL is executed against the remote database.
"""
from contextlib import closing
from datetime import date, datetime, time
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import uuid

_lock = threading.Lock()
_profiles = {}
_sources = {}


def _connect(profile):
    import psycopg
    # libpq configuration is not accepted directly from the browser.
    conn = psycopg.connect(os.environ[profile], connect_timeout=5,
                           options='-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=2000',
                           application_name='aigis_readonly_snapshot')
    try:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        return conn
    except BaseException:
        conn.close()
        raise


def _profile(name):
    if not isinstance(name, str) or not re.fullmatch(r'AIGIS_POSTGRES_[A-Z0-9_]{1,48}', name):
        raise ValueError('Use a server environment variable named AIGIS_POSTGRES_<NAME>')
    if not os.getenv(name):
        raise ValueError('PostgreSQL profile is not configured on the server')
    return name


def _tables(conn):
    # No system schemas or foreign tables; permission checks happen on server.
    return conn.execute("SELECT table_schema,table_name FROM information_schema.tables "
                        "WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema') "
                        "AND table_schema NOT LIKE 'pg_toast%' ORDER BY table_schema,table_name LIMIT 501").fetchall()


def discover(profile):
    profile = _profile(profile)
    with _connect(profile) as conn:
        rows = _tables(conn)
    source_id = uuid.uuid4().hex
    with _lock:
        if len(_profiles) >= 20:
            raise ValueError('Profile limit reached; restart the application to clear profiles')
        _profiles[source_id] = profile
    return {'success': True, 'source_id': source_id, 'source_type': 'postgresql',
            'read_only': True, 'tables': [{'schema': r[0], 'table': r[1]} for r in rows[:500]],
            'tables_truncated': len(rows) > 500}


def _value(value):
    if value is None or isinstance(value, (str, bytes, int, float)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        # Keep exact decimals as text, rather than silently rounding money.
        return str(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, default=str)
    return str(value)


def snapshot(source_id, schema, table, limit=100000):
    from psycopg import sql
    from backend import database
    with _lock:
        profile = _profiles.get(source_id)
    if not profile:
        raise ValueError('Source not found; test the connection again')
    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError('Snapshot limit must be between 1 and 100000')
    # Stage under the existing approved upload directory, then publish on success.
    root = Path(database.UPLOADS_DIR)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f'postgres_{uuid.uuid4().hex}.db'
    completed = False
    try:
        with _connect(profile) as remote, closing(sqlite3.connect(path)) as local:
            if (schema, table) not in _tables(remote):
                raise ValueError('Select a table from the discovered list')
            columns = remote.execute("SELECT column_name,data_type FROM information_schema.columns "
                                     "WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position",
                                     (schema, table)).fetchall()
            if not columns or len(columns) > 200:
                raise ValueError('Source table must have 1–200 columns')
            names = [r[0] for r in columns]
            def kind(data_type):
                if data_type in ('smallint', 'integer', 'bigint', 'boolean'):
                    return 'INTEGER'
                if data_type in ('real', 'double precision'):
                    return 'REAL'
                return 'TEXT'
            quote = database._quote_identifier
            definitions = ','.join(f'{quote(name)} {kind(dtype)}' for name, dtype in columns)
            # Normalized table name lets existing analyzers inspect the same schema.
            local.execute(f'CREATE TABLE telemetry ({definitions})')
            placeholders = ','.join('?' for _ in names)
            count = byte_count = 0
            truncated = False
            with remote.cursor(name='aigis_snapshot') as cursor:
                cursor.execute(sql.SQL('SELECT * FROM {}.{} LIMIT %s').format(
                    sql.Identifier(schema), sql.Identifier(table)), (limit + 1,))
                while True:
                    batch = cursor.fetchmany(min(1000, limit + 1 - count))
                    if not batch:
                        break
                    converted = []
                    for row in batch:
                        if count >= limit:
                            truncated = True
                            break
                        values = tuple(_value(v) for v in row)
                        byte_count += sum(len(v) if isinstance(v, bytes) else len(str(v).encode('utf-8')) for v in values)
                        if byte_count > 50 * 1024 * 1024:
                            raise ValueError('Snapshot exceeds 50 MiB data budget; select fewer rows')
                        converted.append(values)
                        count += 1
                    local.executemany(f'INSERT INTO telemetry VALUES ({placeholders})', converted)
                    if truncated:
                        break
            local.commit()
        result = database.set_active_db(str(path))
        if not result.get('success'):
            raise ValueError('Could not activate the staged snapshot')
        metadata = {'source_type': 'postgresql_snapshot', 'source_id': source_id,
                    'schema': schema, 'table': table, 'rows_imported': count,
                    'row_limit': limit, 'truncated': truncated, 'read_only': True,
                    'snapshot_id': path.stem, 'live': False,
                    'sample_order': 'Database scan order; not guaranteed latest or deterministic'}
        from datetime import timezone
        metadata['captured_at'] = datetime.now(timezone.utc).isoformat()
        with _lock:
            _sources[str(path.resolve())] = metadata
        completed = True
        return {**result, **metadata}
    finally:
        if not completed:
            path.unlink(missing_ok=True)


def active_metadata(path):
    with _lock:
        return dict(_sources.get(str(Path(path).resolve()), {}))
