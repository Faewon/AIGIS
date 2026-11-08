import asyncio
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from backend.dashboard import build_dashboard
from backend.agents import quant_investigator as quant


class InvestigatorDatasetTests(unittest.TestCase):
    def test_custom_schema_returns_unsupported_and_closes_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'custom.db')
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE telemetry (name TEXT, value INTEGER)')
            conn.commit()
            conn.close()
            with patch.object(quant, 'get_active_db_path', return_value=path):
                report = asyncio.run(quant.DeepQuantInvestigatorAgent().diagnose_anomaly())
            self.assertEqual(report['status'], 'UNSUPPORTED_DATASET')
            self.assertIn('event_id', report['quantitative_metrics']['missing_columns'])
            Path(path).unlink()  # Fails on Windows if the connection was leaked.

    def test_query_exception_always_closes_connection(self):
        conn = MagicMock()
        conn.execute.side_effect = sqlite3.OperationalError('query failed')
        with patch('backend.telemetry_analysis.get_connection', return_value=conn):
            with self.assertRaises(sqlite3.OperationalError):
                quant.DeepQuantInvestigatorAgent()._compute_concurrency_metrics_in_process('/claim', 60)
        conn.close.assert_called_once()

    def test_cache_invalidated_on_database_switch(self):
        agent = quant.DeepQuantInvestigatorAgent()
        with patch.object(quant, 'get_active_db_path', return_value='first.db'):
            agent.latest_report = {'database_path': 'first.db', 'status': 'DIAGNOSIS_COMPLETED'}
            self.assertIsNotNone(agent.latest_report)
        with patch.object(quant, 'get_active_db_path', return_value='second.db'):
            self.assertIsNone(agent.latest_report)


class DashboardTests(unittest.TestCase):
    def test_served_html_has_unique_ids_and_no_inline_execution(self):
        page, script = build_dashboard(str(Path(__file__).resolve().parents[1] / 'frontend/index.html'))
        ids = []
        inline = []
        class Inspect(HTMLParser):
            def handle_starttag(self, tag, attrs):
                for name, value in attrs:
                    if name == 'id':
                        ids.append(value)
                    if name.startswith('on'):
                        inline.append(name)
                if tag == 'script':
                    self.assert_external = dict(attrs).get('src')
        Inspect().feed(page)
        self.assertTrue(ids)
        self.assertTrue(all(count == 1 for count in Counter(ids).values()))
        self.assertEqual(inline, [])
        self.assertNotIn('<script>', page)
        self.assertIn('data-dashboard-controls="ribbon"', page)
        self.assertIn('data-dashboard-controls="explorer"', page)
        self.assertIn('function dashboardControl(id)', script)
        self.assertNotIn('eval(', script)
        self.assertNotIn('new Function(', script)

    def test_compiler_preserves_dynamic_action_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'page.html'
            path.write_text('<button id="one" data-valid="yes" onclick="document.getElementById(\'one\').focus()">Go</button><script>const markup = `<button data-aigis-action="table" data-value="${name}">Table</button>`;</script>', encoding='utf-8')
            page, script = build_dashboard(str(path))
            self.assertIn('data-valid="yes"', page)
            self.assertIn('data-aigis-action="table"', script)
            self.assertIn("dashboardControl('one').focus()", script)


class RiskSimulatorTests(unittest.TestCase):
    def test_simulated_velocity_changes_risk_without_recording_requests(self):
        from backend.mock_target.store import VulnerableVoucherStore
        store = VulnerableVoucherStore()
        low = store.evaluate_transaction_risk('127.0.0.1', 'demo', 100, simulated_velocity=1)
        high = store.evaluate_transaction_risk('127.0.0.1', 'demo', 100, simulated_velocity=20)
        self.assertGreater(high['risk_score'], low['risk_score'])
        self.assertEqual(store.velocity_window, [])
