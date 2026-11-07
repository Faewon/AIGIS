"""
Regression tests for the security review findings.
Run with:  python -m unittest discover -s tests -v
Uses a temporary copy of the datasets directory so the real DB is never touched.
"""
import asyncio
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("AIGIS_API_TOKEN", "test-token")

from backend import database  # noqa: E402


class _TempDatasetMixin:
    """Point the database module at an isolated temp datasets dir."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="aigis_test_")
        cls._orig = (database.DATASETS_DIR, database.UPLOADS_DIR, database.DB_PATH,
                     database.ACTIVE_DB_PATH, database.ACTIVE_DB_NAME)
        database.DATASETS_DIR = cls._tmp
        database.UPLOADS_DIR = os.path.join(cls._tmp, "uploads")
        os.makedirs(database.UPLOADS_DIR, exist_ok=True)
        database.DB_PATH = os.path.join(cls._tmp, "aigis_telemetry.db")
        database.ACTIVE_DB_PATH = database.DB_PATH
        database.init_db()
        conn = sqlite3.connect(database.DB_PATH)
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(5)])
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        (database.DATASETS_DIR, database.UPLOADS_DIR, database.DB_PATH,
         database.ACTIVE_DB_PATH, database.ACTIVE_DB_NAME) = cls._orig
        shutil.rmtree(cls._tmp, ignore_errors=True)


class ReadOnlySqlTests(_TempDatasetMixin, unittest.TestCase):
    def _count(self):
        conn = sqlite3.connect(database.DB_PATH)
        try:
            return conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        finally:
            conn.close()

    def test_cte_delete_is_blocked(self):
        res = database.execute_raw_sql("WITH x AS (SELECT 1) DELETE FROM t")
        self.assertFalse(res["success"])
        self.assertEqual(self._count(), 5)

    def test_pragma_write_is_blocked(self):
        res = database.execute_raw_sql("PRAGMA user_version=42")
        self.assertFalse(res["success"])
        conn = sqlite3.connect(database.DB_PATH)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
        conn.close()

    def test_runaway_recursive_cte_times_out(self):
        t0 = time.time()
        res = database.execute_raw_sql(
            "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT count(*) FROM r"
        )
        self.assertFalse(res["success"])
        self.assertLess(time.time() - t0, 20)

    def test_plain_select_works(self):
        res = database.execute_raw_sql("SELECT x FROM t ORDER BY x")
        self.assertTrue(res["success"], res)
        self.assertEqual(len(res["rows"]), 5)


class FileAccessTests(_TempDatasetMixin, unittest.TestCase):
    def test_connect_outside_datasets_is_denied(self):
        outside = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        outside.close()
        sqlite3.connect(outside.name).close()
        try:
            res = database.set_active_db(outside.name)
            self.assertFalse(res["success"])
        finally:
            os.remove(outside.name)

    def test_delete_without_filename_cannot_escape_uploads(self):
        # Force the active DB to a file inside datasets but outside uploads.
        other = os.path.join(database.DATASETS_DIR, "other.db")
        sqlite3.connect(other).close()
        database.ACTIVE_DB_PATH = other
        try:
            res = database.delete_uploaded_database(None)
            self.assertFalse(res["success"])
            self.assertTrue(os.path.exists(other))
        finally:
            database.ACTIVE_DB_PATH = database.DB_PATH

    def test_connect_does_not_switch_journal_mode(self):
        target = os.path.join(database.UPLOADS_DIR, "foreign.db")
        conn = sqlite3.connect(target)
        conn.execute("CREATE TABLE a (b)")
        conn.commit()
        conn.close()
        database.set_active_db(target)
        database.get_db_stats()
        conn = sqlite3.connect(target)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        database.ACTIVE_DB_PATH = database.DB_PATH
        self.assertNotEqual(mode.lower(), "wal")


class InvestigatorTests(unittest.TestCase):
    def test_endpoint_injection_is_neutralised(self):
        from backend.agents.quant_investigator import DeepQuantInvestigatorAgent
        agent = DeepQuantInvestigatorAgent()
        payload = "/x'); import os; os.system('echo pwned'); ('"
        self.assertEqual(agent._validate_endpoint(payload), "/api/v1/voucher/claim")

    def test_no_subprocess_in_investigator(self):
        src = (ROOT / "backend" / "agents" / "quant_investigator.py").read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", src)
        self.assertNotIn("subprocess.run(", src)


class LlmKeyTheftTests(unittest.TestCase):
    def test_base_url_must_be_official_host(self):
        from backend.llm_engine import LLMEngine
        eng = LLMEngine()
        eng.configure("openai", api_key="sk-secret")
        eng.configure("openai", base_url="http://127.0.0.1:9999/v1")
        self.assertEqual(eng.base_url, "https://api.openai.com/v1")
        self.assertEqual(eng.api_key, "sk-secret")

    def test_provider_switch_clears_key(self):
        from backend.llm_engine import LLMEngine
        eng = LLMEngine()
        eng.configure("openai", api_key="sk-secret")
        eng.configure("groq")
        self.assertEqual(eng.api_key, "")


class RetestTests(unittest.TestCase):
    def test_patched_retest_allows_exactly_one(self):
        from backend.agents.sandbox_runner import SandboxRunnerAgent
        from backend.mock_target.store import mock_store
        runner = SandboxRunnerAgent()
        mock_store.reset()
        mock_store.set_all_patches(True)
        rep = asyncio.run(runner.execute_burst_attack(burst_count=15))
        self.assertEqual(rep["successful_requests"], 1)
        self.assertEqual(rep["status"], "EXPLOIT_NEUTRALIZED")
        self.assertIn("1 legitimate request approved", rep["summary_message"])

    def test_unpatched_is_exploited(self):
        from backend.agents.sandbox_runner import SandboxRunnerAgent
        from backend.mock_target.store import mock_store
        runner = SandboxRunnerAgent()
        mock_store.reset()
        rep = asyncio.run(runner.execute_burst_attack(burst_count=15))
        self.assertGreater(rep["illegal_claims_count"], 0)

    def test_noop_lock_does_not_report_neutralized(self):
        """With the lock disabled but stale claim state present, the retest must not pass."""
        from backend.agents.sandbox_runner import SandboxRunnerAgent
        from backend.mock_target.store import mock_store
        runner = SandboxRunnerAgent()
        mock_store.reset()
        mock_store.user_claims["usr_attacker_cerebrus_01"] = 1  # stale state from an earlier run
        rep = asyncio.run(runner.execute_burst_attack(burst_count=15))
        self.assertNotEqual(rep["status"], "EXPLOIT_NEUTRALIZED")


class ClassifierLabelLeakTests(unittest.TestCase):
    def test_user_id_and_label_do_not_drive_classification(self):
        from backend.traffic_classifier import classify_traffic_row
        row = {"user_id": "usr_botnet_cerebrus_001", "is_attack": 1, "burst_stream_id": "NONE",
               "is_datacenter_proxy": 0, "user_agent": "Mozilla/5.0", "api_endpoint": "/api/v1/card/verify"}
        self.assertFalse(classify_traffic_row(row)["is_attack"])


class SentinelWindowTests(unittest.TestCase):
    def test_lapsed_flash_sale_does_not_stand_down(self):
        from backend.agents.fintech_sentinel import FinTechSentinelAgent
        s = FinTechSentinelAgent()
        now = time.time()
        events, policies = s._build_scenario_events("flash_sale", int(now * 1000))
        for p in policies:
            if p["rule_type"] == "FLASH_SALE_WINDOW":
                p["active_from"] = "2000-01-01 00:00:00"
                p["active_to"] = "2000-01-02 00:00:00"
        s.last_tps, s.last_eval_time = 10.0, now - 15
        res = s.evaluate_telemetry(15, events_override=events, policies_override=policies, now_override=now)
        self.assertNotEqual(res["verdict"], "STAND_DOWN")


class IntentMatchingTests(unittest.TestCase):
    def test_substring_does_not_trigger_investigator(self):
        from backend.agents.secops_copilot import _has_intent
        self.assertFalse(_has_intent("what is the description", ["rca", "kb", "ip", "past"]))
        self.assertFalse(_has_intent("paste this", ["past"]))
        self.assertTrue(_has_intent("run rca now", ["rca"]))

    def test_nl2sql_ip_in_description(self):
        from backend.text_to_sql import _has_kw
        self.assertFalse(_has_kw("show the description", ["ip"]))


class PiiScannerTests(unittest.TestCase):
    def setUp(self):
        from backend.pii_scanner import SensitiveDataScanner
        self.s = SensitiveDataScanner

    def _types(self, text):
        return [f["type"] for f in self.s.scan_content(text)["findings"]]

    def test_dashed_and_spaced_cards(self):
        self.assertIn("PAYMENT_CARD_PAN_EXPOSURE", self._types("card 4111-1111-1111-1111"))
        self.assertIn("PAYMENT_CARD_PAN_EXPOSURE", self._types("card 4111 1111 1111 1111"))

    def test_api_keys_detected(self):
        self.assertIn("API_SECRET_KEY_LEAK", self._types("key=ghp_" + "a" * 36))

    def test_random_leading_zero_number_not_cccd(self):
        self.assertNotIn("NATIONAL_ID_EXPOSURE", self._types("order 099999999999"))
        self.assertIn("NATIONAL_ID_EXPOSURE", self._types("id 001099012345"))

    def test_openapi_empty_security_is_public(self):
        import json
        spec = {"security": [{"bearer": []}], "paths": {
            "/pay": {"post": {"security": []}},
            "/me": {"get": {}},
        }}
        eps = {e["path"]: e for e in self.s.parse_openapi_spec(json.dumps(spec))["endpoints"]}
        self.assertFalse(eps["/pay"]["is_protected"])
        self.assertTrue(eps["/me"]["is_protected"])


class PatchExporterTests(unittest.TestCase):
    def test_endpoint_injection_rejected(self):
        from backend.patch_exporter import MultiTargetPatchExporter
        out = MultiTargetPatchExporter.generate_all_patches(endpoint='/x"; os.system("id"); "')
        self.assertEqual(out["target_endpoint"], "/api/v1/voucher/claim")

    def test_patches_do_not_trust_client_header(self):
        from backend.patch_exporter import MultiTargetPatchExporter
        out = MultiTargetPatchExporter.generate_all_patches()
        for group in ("languages", "waf_rules"):
            for item in out[group].values():
                code = "\n".join(l for l in item["code"].lower().splitlines()
                                 if not l.lstrip().startswith(("#", "//", "--")))
                self.assertNotIn("x-user-id", code)
        self.assertIn("ON CONFLICT", out["languages"]["sql"]["code"])
        self.assertNotIn("@Transactional(", out["languages"]["java"]["code"])
        self.assertIn("WithTries(1)", out["languages"]["golang"]["code"])
        self.assertNotIn("rate(", out["waf_rules"]["cloudflare"]["code"])
        self.assertIn("set_keepalive", out["waf_rules"]["nginx_lua"]["code"])


class ServerAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from backend import server
        cls.server = server
        cls.client = TestClient(server.app)

    def test_api_requires_token(self):
        self.assertEqual(self.client.get("/api/v1/agent/config").status_code, 401)

    def test_api_with_token(self):
        r = self.client.get("/api/v1/agent/config", headers={"X-AIGIS-Token": self.server.AIGIS_API_TOKEN})
        self.assertEqual(r.status_code, 200)

    def test_cross_origin_preflight_not_approved(self):
        r = self.client.options("/api/v1/database/connect", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in r.headers})

    def test_dashboard_embeds_token(self):
        r = self.client.get("/")
        self.assertIn('name="aigis-token"', r.text)


if __name__ == "__main__":
    unittest.main()
