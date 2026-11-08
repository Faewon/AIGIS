"""Behavioral regressions for the five confirmed November review findings."""
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend.agents.fintech_sentinel import FinTechSentinelAgent

from scratch.review_confirmations import verify_database, verify_recheck


class ReviewFixTests(unittest.TestCase):
    def test_import_integrity_and_full_window_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            verify_database(Path(directory))

    def test_verifier_accepts_working_control_and_rejects_failed_controls(self):
        asyncio.run(verify_recheck())

    def test_unavailable_database_does_not_report_clean_window(self):
        from backend.agents import fintech_sentinel as sentinel
        with patch.object(sentinel, 'sentinel_window', side_effect=OSError('unavailable')), \
                patch.object(sentinel.stream_engine, 'get_events', return_value=[]):
            state = FinTechSentinelAgent().evaluate_telemetry(policies_override=[])
        self.assertEqual(state['verdict'], 'INSUFFICIENT_DATA')
        self.assertEqual(state['data_source'], 'STREAM_BUFFER')
        self.assertFalse(state['coverage_complete'])
