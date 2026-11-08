"""Reproducible, disposable analysis benchmark: --rows 1000000 for a full run."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import tracemalloc

from backend.database import _create_telemetry_table
from backend.telemetry_analysis import concurrency_metrics, sentinel_window


def benchmark(rows):
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "benchmark.db")
        now = int(time.time()*1000)
        with closing(sqlite3.connect(path)) as conn, conn:
            _create_telemetry_table(conn, "telemetry")
            conn.executemany("INSERT INTO telemetry(event_id,epoch_ms,user_id,api_endpoint,transaction_amount_usd,"
                             "status_code_unpatched,burst_stream_id,is_datacenter_proxy) VALUES (?,?,?,?,?,?,?,?)",
                             ((str(i), now - rows + i, f"u{i%10000}", "/api/v1/voucher/claim", 10, 200, "", 0) for i in range(rows)))
            conn.execute("CREATE INDEX idx_endpoint_epoch ON telemetry(api_endpoint,epoch_ms)")
            conn.execute("CREATE INDEX idx_epoch ON telemetry(epoch_ms)")
            plan = [tuple(r) for r in conn.execute("EXPLAIN QUERY PLAN SELECT * FROM telemetry WHERE api_endpoint=? AND epoch_ms BETWEEN ? AND ?",
                                                  ("/api/v1/voucher/claim", now-rows, now))]
        tracemalloc.start()
        start = time.perf_counter()
        metrics = concurrency_metrics(path, "/api/v1/voucher/claim", max(1, rows//1000+1), now)
        investigator_seconds = time.perf_counter()-start
        start = time.perf_counter()
        sentinel = sentinel_window(path, max(1, rows//1000+1), now)
        sentinel_seconds = time.perf_counter()-start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert metrics["total_analyzed"] == sentinel["total"] == rows
        return {"rows": rows, "investigator_seconds": round(investigator_seconds, 3),
                "sentinel_seconds": round(sentinel_seconds, 3), "python_peak_mb": round(peak/1024/1024, 2),
                "query_plan": plan, "note": "Python allocations only; SQLite native buffers are not included."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=100000)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.rows), indent=2))
