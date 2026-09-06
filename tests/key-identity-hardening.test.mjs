import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
import { migrationPolicy } from '../src/suites.mjs';
import { Fabric } from '../src/fabric.mjs';
import { verifyAudit } from '../src/store.mjs';

function approveRotation(h, record) {
  for (let n = 1; n <= 3; n++) {
    const p = h.p(`custodian-${n}`), challenge = h.f.keyLifecycle.challenge(p, record.rotation_id);
    h.f.keyLifecycle.approve(p, signed(challenge, h.setup.custodianKeys.acme[`custodian-${n}`], 'key-rotation-approval'));
  }
}
function approveRecovery(h, record, start = 1) {
  for (let n = start; n <= 3; n++) {
    const p = h.p(`custodian-${n}`), challenge = h.f.keyLifecycle.recoveryChallenge(p, record.recovery_id);
    h.f.keyLifecycle.approveRecovery(p, signed(challenge, h.setup.custodianKeys.acme[`custodian-${n}`], 'key-recovery-approval'));
  }
}

test('IDN-004: JIT privilege is exact-scoped, durable, and expires', t => {
  const h = fixture(t), grant = h.f.identityLifecycle.issueJit(h.p('security'), { subject_id: 'operator', scope: ['policy.read'], device_id: 'operator-device', ttl_ms: 1000, reason: 'incident investigation' });
  assert.equal(h.f.identityLifecycle.consumeJit(h.p(), grant, 'policy.read').subject_id, 'operator');
  assert.throws(() => h.f.identityLifecycle.consumeJit(h.p(), grant, 'policy.write'), hasCode('INV-403-SCOPE'));
  h.advance(1001); assert.throws(() => h.f.identityLifecycle.consumeJit(h.p(), grant, 'policy.read'), hasCode('INV-403-SCOPE'));
});

test('IDN-005 IDN-006 IDN-010: recovery operations are separately recorded and reject weaker social recovery', t => {
  const h = fixture(t), weak = { operation: 'ACCOUNT_RECOVERY', subject_id: 'operator', new_authenticator: null, proofing_level: 1, recovery_domains: ['helpdesk'], out_of_band_receipt_digest: 'a'.repeat(64), reason: 'caller request' };
  assert.throws(() => h.f.identityLifecycle.request(h.p('security'), weak), hasCode('INV-401-AUTH'));
  const request = h.f.identityLifecycle.request(h.p('security'), { ...weak, operation: 'AUTHENTICATOR_ENROLL', new_authenticator: { id: 'operator-new-key', phishing_resistant: true, hardware_backed: true }, proofing_level: 2, recovery_domains: ['identity-proofing', 'customer-contact'], out_of_band_receipt_digest: 'b'.repeat(64) });
  for (let n = 1; n <= 2; n++) { const p = h.p(`custodian-${n}`), c = h.f.identityLifecycle.challenge(p, request.request_id); h.f.identityLifecycle.approve(p, signed(c, h.setup.custodianKeys.acme[`custodian-${n}`], 'identity-lifecycle-approval')); }
  assert.equal(h.f.identityLifecycle.complete(h.p('security'), request.request_id).status, 'COMPLETED');
  assert.equal(h.f.identity(h.p()).authenticators.at(-1).id, 'operator-new-key');
  assert.equal(h.f.store.list('acme', 'identity-lifecycle').length, 1);
});

test('IDN-001 IDN-007 KEY-011: reset authenticator or revoked firmware fails protected capability issuance', t => {
  const h = fixture(t), request = h.f.identityLifecycle.request(h.p('security'), { operation: 'MFA_RESET', subject_id: 'operator', new_authenticator: null, proofing_level: 2, recovery_domains: ['identity-proofing', 'customer-contact'], out_of_band_receipt_digest: 'c'.repeat(64), reason: 'lost authenticator' });
  for (let n = 1; n <= 2; n++) { const p = h.p(`custodian-${n}`), c = h.f.identityLifecycle.challenge(p, request.request_id); h.f.identityLifecycle.approve(p, signed(c, h.setup.custodianKeys.acme[`custodian-${n}`], 'identity-lifecycle-approval')); }
  h.f.identityLifecycle.complete(h.p('security'), request.request_id);
  assert.throws(() => h.f.runtime.issue(h.p(), { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 1, ttl_ms: 1000 }), hasCode('INV-401-AUTH'));
  const h2 = fixture(t); h2.f.revoke(h2.p('security'), { kind: 'component', id: 'operator-component:simulated-1', reason: 'firmware compromise' });
  assert.throws(() => h2.f.runtime.issue(h2.p(), { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 1, ttl_ms: 1000 }), hasCode('INV-403-HEALTH'));
});

test('KEY-004 KEY-005 KEY-007 KEY-008 KEY-010 KEY-012: threshold key rotation preserves audit verification and prevents suite downgrade', t => {
  const h = fixture(t), old = h.setup.config.tenants.acme.keys.audit, notBefore = h.now() + 1000;
  h.proposed();
  const rotation = h.f.keyLifecycle.startRotation(h.p('custodian-1'), { purpose: 'audit', suite: 'ECDSA-P256-SHA256-v1', not_before: notBefore, backup_digest: 'd'.repeat(64), reason: 'scheduled cryptographic migration', migration: migrationPolicy('Ed25519', 'ECDSA-P256-SHA256-v1', notBefore, notBefore + 1000, notBefore + 2000) });
  assert.throws(() => h.f.keyLifecycle.activateRotation(h.p('custodian-1'), rotation.rotation_id), hasCode('INV-412-EVIDENCE'));
  approveRotation(h, rotation); h.advance(1000);
  const activated = h.f.keyLifecycle.activateRotation(h.p('custodian-1'), rotation.rotation_id);
  assert.notEqual(activated.new_key_id, old.key_id);
  const bundle = h.f.exportAudit(h.p('auditor'), 'rotation verification'); assert.equal(verifyAudit(bundle, bundle.public_keys).valid, true);
  assert.ok(h.f.keyLifecycle.destroy(h.p('custodian-1'), { key_id: old.key_id, destruction_digest: '9'.repeat(64), reason: 'retired material destruction drill' }).destroyed_at);
  assert.throws(() => h.f.keyLifecycle.startRotation(h.p('custodian-1'), { purpose: 'audit', suite: 'Ed25519', not_before: h.now(), backup_digest: 'e'.repeat(64), reason: 'downgrade', migration: migrationPolicy('ECDSA-P256-SHA256-v1', 'Ed25519', h.now(), h.now() + 1000, h.now() + 2000) }), hasCode('INV-409-LIFECYCLE'));
  assert.equal(h.f.store.list('acme', 'key-ceremony').length, 0);
  h.f.keyLifecycle.ceremony(h.p('custodian-1'), { purpose: 'audit', participants: ['custodian-1', 'custodian-2', 'custodian-3'], devices: ['d1', 'd2', 'd3'], artifact_hashes: ['f'.repeat(64)], exceptions: [] });
  assert.equal(h.f.store.list('acme', 'key-ceremony').length, 1);
});

test('KEY-005 KEY-008: same-suite renewal and multiple rotation restart restore the newest public key', t => {
  const h = fixture(t), persistedConfig = JSON.parse(JSON.stringify(h.setup.config)), firstAt = h.now() + 1;
  const first = h.f.keyLifecycle.startRotation(h.p('custodian-1'), { purpose: 'execution', suite: 'Ed25519', not_before: firstAt, backup_digest: '3'.repeat(64), reason: 'scheduled renewal', migration: null });
  approveRotation(h, first); h.advance(1); h.f.keyLifecycle.activateRotation(h.p('custodian-1'), first.rotation_id);
  const secondAt = h.now() + 1, second = h.f.keyLifecycle.startRotation(h.p('custodian-1'), { purpose: 'execution', suite: 'Ed25519', not_before: secondAt, backup_digest: '4'.repeat(64), reason: 'second scheduled renewal', migration: null });
  approveRotation(h, second); h.advance(1); h.f.keyLifecycle.activateRotation(h.p('custodian-1'), second.rotation_id); h.close();
  const restarted = new Fabric(persistedConfig, h.directory, h.now); t.after(() => restarted.close());
  assert.equal(restarted.keys('acme').execution.key_id, second.replacement.key_id);
  assert.notEqual(restarted.keys('acme').execution.key_id, first.replacement.key_id);
});

test('KEY-001 KEY-002 KEY-003 KEY-009: recovery survives restart and requires three independent custodians plus delay', t => {
  const h = fixture(t), persistedConfig = JSON.parse(JSON.stringify(h.setup.config)), recovery = h.f.keyLifecycle.startRecovery(h.p('custodian-1'), { purpose: 'support', backup_digest: '1'.repeat(64), out_of_band_receipt_digest: '2'.repeat(64), reason: 'compromise drill' });
  const first = h.f.keyLifecycle.recoveryChallenge(h.p('custodian-1'), recovery.recovery_id);
  h.f.keyLifecycle.approveRecovery(h.p('custodian-1'), signed(first, h.setup.custodianKeys.acme['custodian-1'], 'key-recovery-approval'));
  assert.throws(() => h.f.keyLifecycle.completeRecovery(h.p('custodian-1'), recovery.recovery_id), hasCode('INV-412-EVIDENCE'));
  approveRecovery(h, h.f.store.must('acme', 'key-recovery', recovery.recovery_id), 2); h.close();
  const restarted = new Fabric(persistedConfig, h.directory, h.now);
  assert.throws(() => restarted.keyLifecycle.completeRecovery(h.p('custodian-1'), recovery.recovery_id), hasCode('INV-412-EVIDENCE'));
  h.advance(60000); const completed = restarted.keyLifecycle.completeRecovery(h.p('custodian-1'), recovery.recovery_id); assert.ok(completed.new_key_id);
  restarted.close(); const restored = new Fabric(JSON.parse(JSON.stringify(persistedConfig)), h.directory, h.now); t.after(() => restored.close());
  assert.equal(restored.keys('acme').support.key_id, completed.new_key_id);
});
