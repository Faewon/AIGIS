"""Bounded-memory window analysis over a single read-only SQLite snapshot."""
from contextlib import closing
import sqlite3

from backend.database import get_connection
from backend.evidence import analysis_context, dataset_identity


def _finish_context(context, path, count):
    # If the file/WAL changed while the read snapshot was open, preserve the
    # measurements but mark the context so it is never reused as a current cache.
    changed = dataset_identity(path).dataset_revision != context.dataset_revision
    return context.model_copy(update={"analyzed_count": count,
                                      "dataset_revision": "snapshot-changed:" + context.dataset_revision if changed else context.dataset_revision}).model_dump()


def concurrency_metrics(path, endpoint, seconds, now_ms=None):
    context = analysis_context(path, seconds, endpoint, now_ms)
    with closing(get_connection(path, read_only=True)) as conn:
        conn.execute("BEGIN")
        columns = {r[1] for r in conn.execute("PRAGMA table_info(telemetry)")}
        required = {"event_id", "epoch_ms", "user_id", "api_endpoint", "transaction_amount_usd",
                    "status_code_unpatched", "burst_stream_id"}
        missing = sorted(required - columns)
        if missing:
            return {"supported": False, "missing_columns": missing,
                    "error": "Dataset not supported for concurrency analysis: missing telemetry columns",
                    "total_analyzed": 0, "has_collisions": False,
                    "context": context.model_copy(update={"coverage_complete": False}).model_dump()}
        cursor = conn.execute("""SELECT event_id, epoch_ms, user_id, burst_stream_id,
            status_code_unpatched, transaction_amount_usd FROM telemetry
            WHERE api_endpoint=? AND epoch_ms BETWEEN ? AND ? ORDER BY epoch_ms, event_id""",
            (endpoint, context.window_start_ms, context.window_end_ms))
        previous = {}
        count = collisions = dirty = gap_count = 0
        gap_sum = loss = 0.0
        minimum_gap = first = last = None
        for row in cursor:
            count += 1
            epoch = row["epoch_ms"]
            first = epoch if first is None else first
            last = epoch
            burst = row["burst_stream_id"] or "NONE"
            key = (row["user_id"] or row["event_id"], burst)
            prev, successes = previous.get(key, (None, 0))
            if prev is not None:
                gap = epoch - prev
                gap_count += 1
                gap_sum += gap
                minimum_gap = gap if minimum_gap is None else min(minimum_gap, gap)
                collisions += gap <= 50
                if gap > 50:
                    successes = 0
            if burst not in ("NONE", "None", "null", "") and row["status_code_unpatched"] == 200:
                if successes:
                    dirty += 1
                    loss += max(0.0, float(row["transaction_amount_usd"] or 0))
                successes += 1
            previous[key] = (epoch, successes)
    duration = (last - first) / 1000 if count else 0
    return {"supported": True, "total_analyzed": count, "concurrency_collisions": collisions,
            "dirty_read_count": dirty, "dirty_read_ratio": round(dirty / count, 3) if count else 0,
            "avg_gap_ms": round(gap_sum / gap_count, 2) if gap_count else 0,
            "min_gap_ms": minimum_gap or 0, "max_loss_usd": round(loss, 2),
            "tps_in_burst": round(count / duration, 1) if duration else 0,
            "has_collisions": collisions > 0 and dirty > 0,
            "context": _finish_context(context, path, count)}


def sentinel_window(path, seconds, now_ms):
    context = analysis_context(path, seconds, now_ms=now_ms)
    bounds = (context.window_start_ms, context.window_end_ms)
    with closing(get_connection(path, read_only=True)) as conn:
        conn.execute("BEGIN")
        row = conn.execute("""SELECT COUNT(*) AS total, COUNT(NULLIF(user_id,'')) AS identities,
            COUNT(DISTINCT NULLIF(user_id,'')) AS users,
            COALESCE(SUM(is_datacenter_proxy=1),0) AS proxies,
            COALESCE(SUM(CASE WHEN api_endpoint LIKE '%/voucher/claim%'
                THEN transaction_amount_usd ELSE 0 END),0) AS drain
            FROM telemetry WHERE epoch_ms BETWEEN ? AND ?""", bounds).fetchone()
        # SQL computes adjacency over the complete window without materializing rows in Python.
        clusters = conn.execute("""SELECT user_id, COUNT(*) FROM (
            SELECT user_id, epoch_ms,
                LAG(epoch_ms) OVER (PARTITION BY user_id ORDER BY epoch_ms) AS previous
            FROM telemetry WHERE epoch_ms BETWEEN ? AND ? AND user_id IS NOT NULL AND user_id != ''
            ) WHERE epoch_ms-previous <= 50 GROUP BY user_id""", bounds).fetchall()
        bursts = [r[0] for r in conn.execute("""SELECT DISTINCT burst_stream_id FROM telemetry
            WHERE epoch_ms BETWEEN ? AND ? AND burst_stream_id NOT IN ('','NONE','None','null')
            ORDER BY burst_stream_id LIMIT 3""", bounds)]
        policies = [dict(r) for r in conn.execute("SELECT * FROM policy_rules")] if _has_table(conn, "policy_rules") else []
        incidents = [dict(r) for r in conn.execute("SELECT * FROM incident_memory ORDER BY epoch_ms DESC LIMIT 5")] if _has_table(conn, "incident_memory") else []
    return {"total": row["total"], "user_entropy": round(row["users"] / max(1, row["identities"]), 3),
            "proxy_ratio": round(row["proxies"] / max(1, row["total"]), 3),
            "concurrency_clusters": sum(r[1] for r in clusters),
            "clustered_users": [r[0] for r in clusters[:5]], "burst_streams": bursts,
            "drain": row["drain"], "policies": policies, "incidents": incidents,
            "context": _finish_context(context, path, row["total"])}


def _has_table(conn, name):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None
