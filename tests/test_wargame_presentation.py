"""Exercise the same evidence presenter used by the browser without a DOM."""
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WargamePresentationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_presenter_requires_regression_and_explicit_verification(self):
        script = r"""
const assert = require('node:assert/strict');
const {wargameVerificationView: view} = require('./frontend/wargame-verification.js');
const good = {success: true, assessment_state: 'MITIGATION_VERIFIED_IN_MOCK',
 regression_report: {status: 'ZERO_REGRESSION_VERIFIED', sample_users_tested: 50,
 legitimate_requests_approved: 50}, configuration: {seed: 0, burst_streams: 15},
 round_evidence: [{attack: {scenario: 'FIXTURE', illegal_claims_count: 3},
 retest: {illegal_claims_count: 0}, dossier: {assessment_state: 'MITIGATION_VERIFIED_IN_MOCK'}}]};
assert.equal(view(good).passed, true);
assert.equal(view({}).passed, false);
assert.equal(view({...good, success: false}).passed, false);
assert.equal(view({...good, regression_report: {status: 'FAILED'}}).passed, false);
assert.equal(view({...good, assessment_state: 'NOT_ASSESSED'}).passed, false);
assert.equal(view({...good, round_evidence: []}).passed, false);
assert.equal(view({...good, regression_report: {...good.regression_report, legitimate_requests_approved: 0}}).passed, false);
assert.equal(view({...good, round_evidence: [{...good.round_evidence[0], retest: {illegal_claims_count: 1}}]}).passed, false);
assert.ok(view(good).lines[0].includes('Seed: 0'));
assert.ok(view(good).lines[1].includes('Baseline illegal: 3'));
assert.ok(view(good).lines[1].includes('Retest illegal: 0'));
"""
        subprocess.run(['node', '-e', script], cwd=ROOT, check=True, capture_output=True, text=True)

    def test_ui_has_scope_and_no_elo_or_immunity_claim(self):
        source = (ROOT / 'frontend/index.html').read_text(encoding='utf-8')
        self.assertNotIn('IMMUNE', source)
        self.assertNotIn('Red ELO:', source)
        self.assertIn('LOCAL MOCK / SYNTHETIC DATA', source)
        self.assertIn('latestTrainingDossier || await fetchWargameResult', source)
        self.assertIn('INCONCLUSIVE — verification request failed', source)
        self.assertIn('final_mitigation_rate', source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js required')
    def test_inline_javascript_syntax(self):
        source = (ROOT / 'frontend/index.html').read_text(encoding='utf-8')
        script = source.split('<script>', 1)[1].split('</script>', 1)[0]
        subprocess.run(['node', '--check'], input=script, check=True, capture_output=True,
                       text=True, encoding='utf-8', timeout=20)
