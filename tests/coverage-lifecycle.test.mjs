import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { signed, verifySigned } from '../src/crypto.mjs';
import { BYPASS_TESTS } from '../src/coverage.mjs';
function declared(h, overrides = {}) {
  const p = h.f.declareCoverage(h.p('security'), { path_id: 'bank-api', action_type: 'finance.bank.change', target: 'bank-sim', environment: 'simulation', connector_version: '1', owner: 'security', status: 'UNKNOWN', max_age_ms: 60000, configuration_digest: digest('config'), ...overrides });
  const evidence = { format: 'IF-COVERAGE-TEST-1', tenant_id: 'acme', path_id: p.path_id, target: p.target, configuration_digest: p.configuration_digest, connector_version: p.connector_version, tested_at: h.now(), expires_at: h.now() + 10000, credential_owner: 'root-gate', permissions: ['read', 'exact-mutation'], negative_tests: BYPASS_TESTS.map(name => ({ name, rejected: true, result_digest: digest(name) })), environment: p.environment };
  return { p, evidence, accept: e => h.f.coverageLifecycle.revalidate(h.p('security'), { path_id: p.path_id, evidence: signed(e ?? evidence, h.setup.issuerKeys.acme.governance, 'coverage-test') }) };
}
test('COV-001 COV-002 COV-008 COV-010: every declared path has a mandatory assigned plan and manual claims fail closed', t => {
  const h = fixture(t);
  for (const path_id of ['web', 'mobile', 'api', 'cli', 'batch', 'import', 'service-account', 'direct-database', 'recovery', 'emergency']) {
    const d = declared(h, { path_id }); assert.equal(d.p.bypass_plan.length, 5); assert.ok(d.p.bypass_plan.every(x => x.owner === 'security' && x.status === 'NOT_EXECUTED'));
  }
  assert.equal(h.f.coverage(h.p()).payload.paths.length, 10);
  for (const status of ['ENFORCED', 'PROTECTED', 'invalid']) assert.throws(() => declared(h, { status }), hasCode('INV-400-SCHEMA'));
  assert.throws(() => declared(h, { action_type: 'unknown.mutation' }), hasCode('INV-400-SCHEMA'));
  assert.equal(h.f.coverage(h.p()).payload.locally_enforced, false);
});
test('COV-003 COV-005 COV-006 COV-007 COV-009: scope-bound signed evidence, expiry intervals and tenant history isolation', t => {
  const h = fixture(t), d = declared(h); const begin = h.now();
  for (const change of [{ tenant_id: 'globex' }, { target: 'other' }, { environment: 'production' }, { credential_owner: 'application' }, { permissions: ['admin'] }, { expires_at: h.now() }, { negative_tests: [] }]) assert.throws(() => d.accept({ ...d.evidence, ...change }));
  h.advance(1); d.accept(); const envelope = h.f.coverage(h.p()), key = h.f.keys('acme').audit;
  assert.equal(verifySigned(envelope, { [key.key_id]: key }, 'coverage').paths[0].effective_status, 'ENFORCED');
  assert.throws(() => verifySigned(envelope, {}, 'coverage')); assert.equal(envelope.payload.guarantee, false);
  assert.throws(() => h.f.coverageLifecycle.timeline(h.p('auditor', 'globex'), 'bank-api'), hasCode('INV-404-NOT-FOUND'));
  assert.throws(() => h.f.coverageLifecycle.timeline(h.p(), 'bank-api'), hasCode('INV-403-ROLE'));
  h.advance(10000); assert.equal(h.f.coverage(h.p()).payload.paths[0].status, 'UNKNOWN');
  const timeline = h.f.coverageLifecycle.timeline(h.p('auditor'), 'bank-api');
  assert.equal(timeline[0].valid_from, begin); assert.equal(timeline[1].valid_until, d.evidence.expires_at); assert.equal(timeline.at(-1).reason, 'STALE_EVIDENCE');
  assert.equal(h.f.store.must('acme', 'coverage-task', 'bank-api').owner, 'security');
});
test('COV-004 COV-005: revoked assessor and changed configuration withdraw previously enforced paths', t => {
  const h = fixture(t), d = declared(h); d.accept();
  const issuer = h.setup.issuerKeys.acme.governance.key_id;
  h.f.revoke(h.p('security'), { kind: 'issuer', id: issuer, reason: 'compromised assessor' });
  assert.equal(h.f.coverage(h.p()).payload.locally_enforced, false);
  assert.equal(h.f.store.must('acme', 'coverage-task', 'bank-api').reason, 'ASSESSOR_REVOKED'); assert.throws(() => d.accept());
  const second = declared(h, { path_id: 'api-two' });
  h.f.coverageLifecycle.drift(h.p('security'), { path_id: second.p.path_id, configuration_digest: digest('changed credential owner'), connector_version: '2' });
  assert.equal(h.f.store.must('acme', 'coverage', second.p.path_id).status, 'UNKNOWN'); assert.throws(() => second.accept());
});
