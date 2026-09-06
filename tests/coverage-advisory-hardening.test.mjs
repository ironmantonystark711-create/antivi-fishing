import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { ADVISORY_RUNTIME } from '../src/advisory.mjs';

function declaredPath(overrides = {}) {
  return { path_id: 'bank-api', action_type: 'finance.bank.change', target: 'bank-sim', environment: 'simulation', connector_version: '1.0.0', owner: 'security', status: 'UNKNOWN', max_age_ms: 60000, configuration_digest: digest('coverage-config'), ...overrides };
}

test('COV-003 COV-010: isolated Fabric/target execution detects the direct target bypass and cannot claim enforcement', t => {
  const h = fixture(t), path = declaredPath(); h.f.declareCoverage(h.p('security'), path);
  const fabricated = signed({ format: 'IF-COVERAGE-TEST-1', tenant_id: 'acme', path_id: path.path_id, result: 'all tests passed' }, h.setup.issuerKeys.acme.governance, 'coverage-test');
  assert.throws(() => h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id, evidence: fabricated }), hasCode('INV-400-SCHEMA'));
  const coverage = h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id }), envelope = h.f.store.must('acme', 'coverage', path.path_id).technical_validation;
  assert.equal(envelope.protected.key_id, h.f.keys('acme').coverage_assessor.key_id);
  assert.equal(coverage.status, 'UNKNOWN'); assert.equal(envelope.payload.negative_tests.find(test => test.name === 'direct-bypass').rejected, false);
  assert.equal(h.f.store.must('acme', 'coverage-task', path.path_id).reason, 'DIRECT_BYPASS_DETECTED');
});

test('COV-005: a protected transaction preserves the direct-bypass withdrawal without a coverage read', t => {
  const h = fixture(t), path = declaredPath({ path_id: 'fresh-api' }); h.f.declareCoverage(h.p('security'), path); h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id }); h.advance(10001); h.proposed();
  assert.equal(h.f.store.must('acme', 'coverage', path.path_id).status, 'UNKNOWN');
});

test('COV-003 COV-010 CON-006: bypass evidence is exact and connector downgrades fail closed', t => {
  const h = fixture(t), path = declaredPath(); h.f.declareCoverage(h.p('security'), path);
  const fabricated = signed({ format: 'IF-COVERAGE-TEST-1', tenant_id: 'acme', path_id: path.path_id, negative_tests: [{ name: 'replay', rejected: true }] }, h.setup.issuerKeys.acme.governance, 'coverage-test');
  assert.throws(() => h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id, evidence: fabricated }), hasCode('INV-400-SCHEMA'));
  assert.equal(h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id }).status, 'UNKNOWN');
  assert.throws(() => h.f.declareCoverage(h.p('security'), declaredPath({ path_id: 'production-api', environment: 'production' })), hasCode('INV-412-COVERAGE'));
  h.f.coverageLifecycle.drift(h.p('security'), { path_id: path.path_id, configuration_digest: digest('upgraded-config'), connector_version: '2.0.0' });
  assert.throws(() => h.f.coverageLifecycle.drift(h.p('security'), { path_id: path.path_id, configuration_digest: digest('downgraded-config'), connector_version: '1.0.0' }), hasCode('INV-409-LIFECYCLE'));
});

test('AIG-004 AIG-010: only an executable durable local regression can promote the configured advisory model', t => {
  const h = fixture(t), baseline = h.f.runAdvisoryRegression(h.p('security'), {});
  assert.equal(baseline.payload.status, 'ALLOW');
  assert.equal(h.f.promoteAdvisory(h.p('security'), { evaluation_id: baseline.payload.evaluation_id, baseline_evaluation_id: baseline.payload.evaluation_id }).payload.evaluation_id, baseline.payload.evaluation_id);
  assert.throws(() => h.f.runAdvisoryRegression(h.p('security'), { candidate: { provider: 'remote', model: ADVISORY_RUNTIME.model, version: ADVISORY_RUNTIME.version } }), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.promoteAdvisory(h.p('security'), { evaluation_id: 'forged-evaluation', baseline_evaluation_id: baseline.payload.evaluation_id }), hasCode('INV-404-NOT-FOUND'));
});

test('CON-006: unregistered versions and post-floor retrograde registration fail closed', t => {
  const h = fixture(t), v2 = { kind: 'connector', id: 'bank-connector', version: '2', status: 'SUPPORTED', end_of_support: null, replacement: null, migration: null, compatibility_digest: digest('connector-v2') };
  h.f.versions.publish(h.p('security'), v2);
  assert.throws(() => h.f.versions.check('acme', 'connector', 'bank-connector', '1'), hasCode('INV-410-VERSION'));
  assert.throws(() => h.f.versions.publish(h.p('security'), { ...v2, version: '1', compatibility_digest: digest('connector-v1') }), hasCode('INV-409-LIFECYCLE'));
});
