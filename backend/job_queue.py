"""Bounded durable local benchmark queue. Expired leases are never retried silently."""
import asyncio
from contextlib import closing, suppress
import json
import secrets
import sqlite3
import time
import uuid

from backend.run_store import _path, get_run, save_run


def connection():
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE IF NOT EXISTS benchmark_jobs ('
                 'run_id TEXT PRIMARY KEY, config TEXT NOT NULL, status TEXT NOT NULL, '
                 'created REAL NOT NULL, owner TEXT, heartbeat REAL, deadline REAL, cancel INTEGER DEFAULT 0)')
    conn.commit()
    return conn


def submit(config, capacity=20):
    run_id = uuid.uuid4().hex
    config = {**config, 'seed': config.get('seed') if config.get('seed') is not None else secrets.randbits(32)}
    with closing(connection()) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        if conn.execute("SELECT count(*) FROM benchmark_jobs WHERE status IN ('QUEUED','RUNNING')").fetchone()[0] >= capacity:
            raise OverflowError('Local benchmark queue is full')
        conn.execute('INSERT INTO benchmark_jobs(run_id,config,status,created) VALUES(?,?,?,?)',
                     (run_id, json.dumps(config), 'QUEUED', time.time()))
    return run_id


def lookup(run_id):
    with closing(connection()) as conn:
        row = conn.execute('SELECT * FROM benchmark_jobs WHERE run_id=?', (run_id,)).fetchone()
    if not row:
        return None
    job = dict(row)
    job['configuration'] = json.loads(job.pop('config'))
    job.pop('owner', None)
    job['run'] = get_run(run_id)
    return job


def cancel(run_id):
    with closing(connection()) as conn, conn:
        conn.execute("UPDATE benchmark_jobs SET cancel=1, status=CASE WHEN status='QUEUED' THEN 'CANCELLED' ELSE status END "
                     "WHERE run_id=? AND status IN ('QUEUED','RUNNING')", (run_id,))
    return lookup(run_id)


def claim(owner, timeout=120, lease=10):
    now = time.time()
    with closing(connection()) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        expired = conn.execute("SELECT run_id,deadline FROM benchmark_jobs WHERE status='RUNNING' "
                               "AND (heartbeat<? OR deadline<=?)", (now-lease, now)).fetchall()
        conn.execute("UPDATE benchmark_jobs SET status=CASE WHEN deadline<=? THEN 'TIMED_OUT' ELSE 'INTERRUPTED' END "
                     "WHERE status='RUNNING' AND (heartbeat<? OR deadline<=?)", (now, now-lease, now))
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='simulation_runs'").fetchone():
            for job in expired:
                saved = conn.execute('SELECT result_json FROM simulation_runs WHERE run_id=?', (job['run_id'],)).fetchone()
                if saved:
                    result = {**json.loads(saved[0]), 'assessment_state': 'NOT_ASSESSED'}
                    conn.execute('UPDATE simulation_runs SET status=?,result_json=? WHERE run_id=?',
                                 ('TIMED_OUT' if job['deadline'] <= now else 'INTERRUPTED', json.dumps(result), job['run_id']))
        if conn.execute("SELECT count(*) FROM benchmark_jobs WHERE status='RUNNING'").fetchone()[0] >= 1:
            return None
        row = conn.execute("SELECT run_id,config FROM benchmark_jobs WHERE status='QUEUED' ORDER BY created,run_id LIMIT 1").fetchone()
        if row:
            conn.execute("UPDATE benchmark_jobs SET status='RUNNING',owner=?,heartbeat=?,deadline=? WHERE run_id=?",
                         (owner, now, now+timeout, row['run_id']))
            return row['run_id'], json.loads(row['config'])


def pulse(run_id, owner):
    with closing(connection()) as conn, conn:
        conn.execute("UPDATE benchmark_jobs SET heartbeat=? WHERE run_id=? AND owner=? AND status='RUNNING'",
                     (time.time(), run_id, owner))
        row = conn.execute('SELECT status,cancel,deadline FROM benchmark_jobs WHERE run_id=? AND owner=?', (run_id, owner)).fetchone()
        return dict(row) if row else None


def finish(run_id, owner, status):
    with closing(connection()) as conn, conn:
        changed = conn.execute("UPDATE benchmark_jobs SET status=?,heartbeat=? WHERE run_id=? AND owner=? AND status='RUNNING'",
                               (status, time.time(), run_id, owner)).rowcount
    saved = get_run(run_id)
    if changed and saved and status != 'COMPLETED':
        save_run(run_id, saved['configuration'], {**saved['result'], 'assessment_state': 'NOT_ASSESSED'}, status)


async def worker():
    from backend.agents.adversarial_trainer import AdversarialTrainer
    owner = uuid.uuid4().hex
    while True:
        item = await asyncio.to_thread(claim, owner)
        if not item:
            await asyncio.sleep(.25)
            continue
        run_id, config = item
        task = asyncio.create_task(AdversarialTrainer().train_adversarial_rounds(
            config['rounds'], config['burst_streams'], config['seed'], run_id=run_id))
        status = 'FAILED'
        try:
            while not task.done():
                state = await asyncio.to_thread(pulse, run_id, owner)
                if not state or state['status'] != 'RUNNING':
                    status = 'INTERRUPTED'
                    break
                if state['cancel'] or time.time() >= state['deadline']:
                    status = 'CANCELLED' if state['cancel'] else 'TIMED_OUT'
                    break
                await asyncio.wait({task}, timeout=.2)
            else:
                await task
                status = 'COMPLETED'
        except asyncio.CancelledError:
            status = 'INTERRUPTED'
            raise
        except Exception:
            status = 'FAILED'
        finally:
            if not task.done():
                task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task
            await asyncio.to_thread(finish, run_id, owner, status)
