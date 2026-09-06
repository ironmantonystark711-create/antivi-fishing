import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, stagePolicy, hasCode } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
function proof(h, candidate, stage, overrides = {}) {
  return signed({ tenant_id: 'acme', candidate_digest: digest(candidate), baseline_digest: digest(h.f.policy('acme')), stage, review_commit: 'a'.repeat(40), test_result_digest: digest('synthetic test run'), passed: true, tested_at: h.now(), expires_at: h.now() + 600000, ...overrides }, h.setup.issuerKeys.acme.governance, 'policy-stage');
}
function activate(h, candidate) {
  stagePolicy(h, candidate);
  const record = h.proposed('policy.change', { policy: candidate }, { policy_version: h.f.policy('acme').version, action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Customer-authorised staged transition' } });
  h.advance(120001); h.evidence(record, { kind: 'governance_review' }); h.evidence(record, { kind: 'governance_review', issuer: 'registry' }); h.approve(record, 3);
  const c = h.f.certificate(h.p(), record.capsule.capsule_id); assert.equal(h.f.execute(h.p(), c).payload.status, 'VERIFIED'); return c;
}
test('POL-008 POL-010: signed development, shadow and canary stages bind exact policy and cannot be skipped or self-asserted', t => {
  const h = fixture(t), candidate = clone(h.f.policy('acme')); candidate.version++;
  h.f.simulate(h.p('policy-admin'), candidate);
  assert.throws(() => h.f.policyLifecycle.stage(h.p('policy-admin'), { candidate, stage: 'CANARY', evidence: proof(h, candidate, 'CANARY') }), hasCode('INV-409-STAGE'));
  for (const change of [{ passed: false }, { tenant_id: 'globex' }, { candidate_digest: digest('wrong') }, { expires_at: h.now() }, { review_commit: 'unreviewed' }]) assert.throws(() => h.f.policyLifecycle.stage(h.p('policy-admin'), { candidate, stage: 'DEVELOPMENT', evidence: proof(h, candidate, 'DEVELOPMENT', change) }));
  for (const stage of ['DEVELOPMENT', 'SHADOW', 'CANARY']) {
    const input = { candidate, stage, evidence: proof(h, candidate, stage) };
    assert.throws(() => h.f.policyLifecycle.stage(h.p(), input), hasCode('INV-403-ROLE'));
    h.f.policyLifecycle.stage(h.p('policy-admin'), input);
  }
  assert.equal(h.f.policyLifecycle.ready('acme', candidate, h.now()), true); assert.equal(h.f.policy('acme').version, 1);
  h.f.revoke(h.p('security'), { kind: 'issuer', id: h.setup.issuerKeys.acme.governance.key_id, reason: 'review authority revoked' });
  assert.equal(h.f.policyLifecycle.ready('acme', candidate, h.now()), false);
});
test('POL-008 POL-009 POL-014: activation and rollback advance versions and never restore revoked authorities', t => {
  const h = fixture(t), original = clone(h.f.policy('acme')), candidate = clone(original); candidate.version = 2; candidate.rules['finance.payment.first'].max_quantity = 42;
  activate(h, candidate); assert.equal(h.f.policy('acme').version, 2); assert.equal(h.f.policy('acme').rules['finance.payment.first'].max_quantity, 42);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'compromised-device', reason: 'must survive rollback' });
  const rollback = h.f.policyLifecycle.rollbackCandidate(h.p('policy-admin'), 1);
  assert.equal(rollback.activation, false); assert.equal(rollback.candidate.version, 3); assert.equal(rollback.candidate.rules['finance.payment.first'].max_quantity, original.rules['finance.payment.first'].max_quantity);
  assert.throws(() => h.f.policyLifecycle.rollbackCandidate(h.p(), 1), hasCode('INV-403-ROLE'));
  activate(h, rollback.candidate); assert.equal(h.f.policy('acme').version, 3); assert.equal(h.f.revoked('acme', 'device', 'compromised-device'), true);
  assert.equal(h.f.store.list('acme', 'policy-history').length, 3);
});
test('POL-008: staging without simulation, stale baseline or expired evidence cannot activate', t => {
  const h = fixture(t), candidate = clone(h.f.policy('acme')); candidate.version++;
  assert.throws(() => h.f.policyLifecycle.stage(h.p('policy-admin'), { candidate, stage: 'DEVELOPMENT', evidence: proof(h, candidate, 'DEVELOPMENT') }), hasCode('INV-412-EVIDENCE'));
  stagePolicy(h, candidate); h.advance(600001); assert.equal(h.f.policyLifecycle.ready('acme', candidate, h.now()), false);
});
