import asyncio
import io
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi import UploadFile
from fastapi.testclient import TestClient
from backend import server, database
from backend.agents import quant_investigator as quant
from backend import stream_engine as streaming


class UploadTests(unittest.TestCase):
    def test_read_failure_removes_partial_upload(self):
        from unittest.mock import AsyncMock
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / "partial.db"
            upload = UploadFile(io.BytesIO(b"data"))
            upload.read = AsyncMock(side_effect=[b"part", OSError("read failed")])
            with self.assertRaises(OSError):
                asyncio.run(server._stream_upload_to_disk(upload, dest))
            self.assertFalse(dest.exists())
            self.assertTrue(upload.file.closed)

    def test_chunked_upload_and_limit_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory) / "upload.db"
            ok, _ = asyncio.run(server._stream_upload_to_disk(UploadFile(io.BytesIO(b"data")), dest))
            self.assertTrue(ok)
            self.assertEqual(dest.read_bytes(), b"data")
            other = Path(directory) / "oversize.db"
            ok, _ = asyncio.run(server._stream_upload_to_disk(UploadFile(io.BytesIO(b"data")), other, 3))
            self.assertFalse(ok)
            self.assertFalse(other.exists())

    def test_multipart_routes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(server, "BASE_DIR", directory), patch.object(server, "set_active_db", return_value={"success": True}), patch.object(server, "import_custom_csv_to_db", return_value={"success": True}):
            client = TestClient(server.app)
            for route, filename in [("upload_db", "sample.db"), ("upload_csv", "sample.csv")]:
                response = client.post("/api/v1/database/" + route, files={"file": (filename, b"data")}, headers={"X-AIGIS-Token": server.AIGIS_API_TOKEN})
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json()["success"])
            self.assertTrue(all(p.stat().st_size == 4 for p in (Path(directory) / "backend/datasets/uploads").iterdir()))


class ValidationTests(unittest.TestCase):
    def test_invalid_inputs_rejected_before_execution(self):
        client = TestClient(server.app)
        for route, body in [("database/sql", {"max_limit": "abc"}), ("agent/config", {"provider": []}), ("wargame/train", {"rounds": -1}), ("stream/start", {"tps": 999}), ("scanner/pii", [])]:
            response = client.post("/api/v1/" + route, json=body, headers={"X-AIGIS-Token": server.AIGIS_API_TOKEN})
            self.assertEqual(response.status_code, 422, route)

    def test_dashboard_opens_without_login_and_has_strict_script_policy(self):
        client = TestClient(server.app)
        response = client.get("/")
        self.assertNotIn('www-authenticate', response.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("'unsafe-inline'", response.headers["content-security-policy"].split("style-src")[0])
        self.assertNotIn("'unsafe-hashes'", response.headers["content-security-policy"])
        self.assertIn('/assets/dashboard.js', response.text)
        self.assertLess(len(response.headers["content-security-policy"]), 1024)


class QuantTests(unittest.TestCase):
    def metrics(self, rows):
        from backend.telemetry_analysis import concurrency_metrics
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'metrics.db')
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('CREATE TABLE telemetry(event_id, epoch_ms, user_id, api_endpoint, transaction_amount_usd, status_code_unpatched, burst_stream_id)')
                conn.executemany('INSERT INTO telemetry VALUES (?,?,?,?,?,?,?)', [
                    (str(i), r['epoch_ms'], r['user_id'], '/claim', r['transaction_amount_usd'],
                     r['status_code_unpatched'], r.get('burst_stream_id', '')) for i, r in enumerate(rows)])
            return concurrency_metrics(path, '/claim', 60, now_ms=2000)

    def test_legitimate_successes_are_not_losses(self):
        rows = [{"user_id": "u", "epoch_ms": 1000 + i * 100, "status_code_unpatched": 200, "transaction_amount_usd": 10} for i in range(10)]
        result = self.metrics(rows)
        self.assertEqual(result["dirty_read_count"], 0)
        self.assertEqual(result["max_loss_usd"], 0)
        self.assertEqual(result["tps_in_burst"], 11.1)

    def test_first_success_per_burst_is_legitimate(self):
        rows = [{"user_id": "u", "burst_stream_id": burst, "epoch_ms": 1000 + i, "status_code_unpatched": 200, "transaction_amount_usd": 10} for burst in ("a", "b") for i in range(3)]
        result = self.metrics(rows)
        self.assertEqual(result["dirty_read_count"], 4)
        self.assertEqual(result["max_loss_usd"], 40)


class FifoTests(unittest.TestCase):
    def test_below_at_and_above_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "stream.db")
            engine = streaming.LiveStreamEngine(path)
            event = engine._generate_event()
            conn = sqlite3.connect(path)
            columns = ", ".join('"' + key + '"' for key in event)
            conn.execute(f"CREATE TABLE telemetry ({columns})")
            conn.close()
            with patch.object(streaming, "TARGET_ROW_LIMIT", 3):
                for count in range(1, 5):
                    ev = dict(event, event_id=str(count), epoch_ms=count)
                    engine._flush_batch([ev])
                    with closing(sqlite3.connect(path)) as conn:
                        epochs = [r[0] for r in conn.execute("SELECT epoch_ms FROM telemetry ORDER BY epoch_ms")]
                    self.assertEqual(epochs, list(range(max(1, count - 2), count + 1)))
            self.assertEqual(engine.metrics["rolling_deletions"], 1)


class NationalIdTests(unittest.TestCase):
    def test_cmnd_detected_and_masked(self):
        from backend.pii_scanner import SensitiveDataScanner
        result = SensitiveDataScanner.scan_content("CMND: 123456789")
        self.assertTrue(result["has_pii_leak"])
        self.assertNotIn("123456789", result["sanitized_content"])


class IncidentTests(unittest.TestCase):
    def test_default_ids_are_unique_and_duplicate_does_not_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "incidents.db")
            with closing(sqlite3.connect(path)) as conn:
                database.init_sentinel_tables(conn)
                conn.commit()
            with patch.object(database, "get_connection", side_effect=lambda: sqlite3.connect(path)):
                self.assertTrue(database.add_incident_memory({"rca_summary": "first"}))
                self.assertTrue(database.add_incident_memory({"rca_summary": "second"}))
                self.assertTrue(database.add_incident_memory({"incident_id": "fixed", "rca_summary": "original"}))
                self.assertFalse(database.add_incident_memory({"incident_id": "fixed", "rca_summary": "replacement"}))
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(conn.execute("SELECT rca_summary FROM incident_memory WHERE incident_id='fixed'").fetchone()[0], "original")
                self.assertEqual(conn.execute("SELECT count(*) FROM incident_memory WHERE rca_summary IN ('first', 'second')").fetchone()[0], 2)
