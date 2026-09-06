import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest, clone } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { ADVISORY_EVALUATION_VERSION, compareEvaluations } from '../src/advisory.mjs';

const requiredTests = ['no-certificate', 'wrong-tenant', 'state-race', 'replay', 'direct-bypass'];
function declaredPath(overrides = {}) {
  return { path_id: 'bank-api', action_type: 'finance.bank.change', target: 'bank-sim', environment: 'simulation', connector_version: '1.0.0', owner: 'security', status: 'UNKNOWN', max_age_ms: 60000, configuration_digest: digest('coverage-config'), ...overrides };
}
function technicalEvidence(h, path, overrides = {}) {
  return { format: 'IF-COVERAGE-TEST-1', tenant_id: 'acme', path_id: path.path_id, target: path.target, configuration_digest: path.configuration_digest, connector_version: path.connector_version, tested_at: h.now(), expires_at: h.now() + 10000, credential_owner: 'root-gate', permissions: ['read', 'exact-mutation'], negative_tests: requiredTests.map(name => ({ name, rejected: true, result_digest: digest(name) })), environment: path.environment, ...overrides };
}

test('COV-003 COV-004 COV-005 COV-009: assessor revocation and expiry withdraw coverage and close its interval', t => {
  const h = fixture(t), path = declaredPath(); h.f.declareCoverage(h.p('security'), path);
  const envelope = signed(technicalEvidence(h, path), h.setup.issuerKeys.acme.governance, 'coverage-test'); h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id, evidence: envelope });
  const initial = h.f.store.list('acme', 'coverage-history').find(x => x.status === 'ENFORCED'); assert.ok(initial.effective_from); assert.equal(initial.effective_until, null);
  h.f.revoke(h.p('security'), { kind: 'issuer', id: envelope.protected.key_id, reason: 'Synthetic assessor compromise' });
  assert.equal(h.f.coverage(h.p()).payload.paths[0].effective_status, 'UNKNOWN');
  const closed = h.f.store.get('acme', 'coverage-history', initial.history_id); assert.equal(closed.interval_close_reason, 'ASSESSOR_REVOKED'); assert.equal(closed.effective_until, h.now());
  const replacement = declaredPath({ path_id: 'fresh-api' }); h.f.declareCoverage(h.p('security'), replacement); h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: replacement.path_id, evidence: signed(technicalEvidence(h, replacement), h.setup.issuerKeys.acme.registry, 'coverage-test') }); h.advance(10001);
  assert.equal(h.f.coverage(h.p()).payload.paths.find(x => x.path_id === replacement.path_id).effective_status, 'UNKNOWN');
});

test('COV-003 COV-010 CON-006: bypass evidence is exact and connector downgrades fail closed', t => {
  const h = fixture(t), path = declaredPath(); h.f.declareCoverage(h.p('security'), path);
  const duplicate = technicalEvidence(h, path, { negative_tests: [...requiredTests, 'replay'].map(name => ({ name, rejected: true, result_digest: digest(name) })) });
  assert.throws(() => h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id, evidence: signed(duplicate, h.setup.issuerKeys.acme.governance, 'coverage-test') }), hasCode('INV-412-COVERAGE'));
  const insufficientPermissions = technicalEvidence(h, path, { permissions: ['read'] });
  assert.throws(() => h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: path.path_id, evidence: signed(insufficientPermissions, h.setup.issuerKeys.acme.governance, 'coverage-test') }), hasCode('INV-412-COVERAGE'));
  assert.throws(() => h.f.declareCoverage(h.p('security'), declaredPath({ path_id: 'production-api', environment: 'production' })), hasCode('INV-412-COVERAGE'));
  h.f.coverageLifecycle.drift(h.p('security'), { path_id: path.path_id, configuration_digest: digest('upgraded-config'), connector_version: '2.0.0' });
  assert.throws(() => h.f.coverageLifecycle.drift(h.p('security'), { path_id: path.path_id, configuration_digest: digest('downgraded-config'), connector_version: '1.0.0' }), hasCode('INV-409-LIFECYCLE'));
});

test('AIG-010: only the configured local model can pass a complete versioned promotion report', () => {
  const baseline = { suite: ADVISORY_EVALUATION_VERSION, provider: 'local', model: 'deterministic-extractor', version: '1', results: ['injection', 'provenance', 'structured-output', 'ambiguous-fields', 'tenant-isolation'].map(name => ({ name, pass: true })) };
  assert.equal(compareEvaluations(baseline, baseline).promotion, 'ALLOW');
  for (const change of [candidate => candidate.provider = 'remote', candidate => candidate.model = 'replacement-model', candidate => candidate.version = '2']) {
    const candidate = clone(baseline); change(candidate); assert.equal(compareEvaluations(baseline, candidate).promotion, 'DENY');
  }
  const malformed = clone(baseline); malformed.results[0].pass = 'yes';
  assert.throws(() => compareEvaluations(baseline, malformed), hasCode('INV-400-AI-EVAL'));
});
