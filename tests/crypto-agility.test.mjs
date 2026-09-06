import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKey, signed, verifySigned } from '../src/crypto.mjs';
import { fixture, hasCode } from './helpers.mjs';
import { clone } from '../src/canonical.mjs';
import { verifyAudit } from '../src/store.mjs';
test('KEY-005 COM-002: key algorithm, suite, signature encoding and verification cutoff cannot be confused', () => {
  const ed = generateKey(), ec = generateKey('ECDSA-P256-SHA256-v1');
  assert.throws(() => signed({ value: 1 }, { ...ec, suite: 'Ed25519' }, 'audit'), hasCode('INV-401-SIGNATURE'));
  assert.throws(() => signed({ value: 1 }, { ...ed, suite: ec.suite }, 'audit'), hasCode('INV-401-SIGNATURE'));
  const original = { value: 1 }, e = signed(original, ed, 'audit'); original.value = 99; assert.equal(e.payload.value, 1);
  const keys = { [ed.key_id]: ed }; assert.throws(() => verifySigned(e, keys, 'audit', { now: 20, policy: { Ed25519: { verify_until: 20 } } }));
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const ambiguous = clone(e); ambiguous.signature = ambiguous.signature.slice(0, -1) + alphabet[alphabet.indexOf(ambiguous.signature.at(-1)) + 1];
  assert.equal(Buffer.from(ambiguous.signature, 'base64url').toString('hex'), Buffer.from(e.signature, 'base64url').toString('hex'));
  assert.throws(() => verifySigned(ambiguous, keys, 'audit'), hasCode('INV-401-SIGNATURE'));
});
test('KEY-005 KEY-010 NFR-MNT-002: independent verifiers accept mixed-suite audit history and reject cross-suite tampering', t => {
  const h = fixture(t), next = generateKey('ECDSA-P256-SHA256-v1'), old = h.f.keys('acme').audit;
  h.proposed(); const initial = h.f.exportAudit(h.p('auditor'), 'pre-migration audit');
  h.f.store.auditKeys.acme = next; h.f.store.tx(() => h.f.store.audit('acme', 'SUITE_MIGRATED', 'customer', next.key_id, { from: old.key_id, to: next.key_id }, h.now()));
  const bundle = h.f.store.auditExport('acme'), pinned = { [old.key_id]: { public_key: old.public_key }, [next.key_id]: { public_key: next.public_key } };
  assert.equal(verifyAudit(bundle, pinned, initial.checkpoint.payload).valid, true);
  const file = join(h.directory, 'migration-audit.json'), trust = join(h.directory, 'trust.json'); writeFileSync(trust, JSON.stringify(pinned));
  for (const script of ['scripts/verify-export.mjs', 'scripts/verify-export-webcrypto.mjs']) {
    writeFileSync(file, JSON.stringify(bundle)); const out = spawnSync(process.execPath, [script, file, trust], { encoding: 'utf8' }); assert.equal(out.status, 0, out.stderr);
    const bad = clone(bundle); bad.entries.at(-1).envelope.protected.suite = 'Ed25519'; writeFileSync(file, JSON.stringify(bad)); assert.equal(spawnSync(process.execPath, [script, file, trust]).status, 1);
  }
});
test('KEY-005 KEY-008 KEY-010: customer-quorum suite rotation survives restart and preserves independently pinned audit history', t => {
  const h = fixture(t), keys = Object.values(h.setup.custodianKeys.acme), old = clone(h.f.keys('acme').audit);
  const x = h.f.keyGovernance.prepare(h.p('security'), { purpose: 'audit', suite: 'ECDSA-P256-SHA256-v1', not_before: h.now() + 60000 });
  const sigs = keys.slice(0, 3).map(k => signed(x, k, 'key-rotation'));
  assert.throws(() => h.f.keyGovernance.activate(h.p('security'), { rotation_id: x.rotation_id, signatures: sigs }), hasCode('INV-423-DEFER'));
  h.advance(60000);
  for (const signatures of [sigs.slice(0, 2), [sigs[0], sigs[0], sigs[1]], sigs.map(s => ({ ...s, payload: { ...s.payload, next_suite: 'Ed25519' } }))]) assert.throws(() => h.f.keyGovernance.activate(h.p('security'), { rotation_id: x.rotation_id, signatures }));
  assert.equal(h.f.keyGovernance.activate(h.p('security'), { rotation_id: x.rotation_id, signatures: sigs }).status, 'ACTIVATED');
  assert.throws(() => h.f.keyGovernance.activate(h.p('security'), { rotation_id: x.rotation_id, signatures: sigs }), hasCode('INV-409-REPLAY'));
  assert.ok(!JSON.stringify(h.f.keyGovernance.publicHistory(h.p('auditor'))).includes('PRIVATE KEY'));
  h.close(); const recovered = new h.f.constructor(h.setup.config, h.directory, h.now); t.after(() => recovered.close());
  assert.equal(recovered.keys('acme').audit.suite, x.next_suite);
  assert.throws(() => recovered.keyGovernance.prepare(h.p('security'), { purpose: 'audit', suite: 'Ed25519', not_before: h.now() + 60000 }), hasCode('INV-451-POLICY'));
  const bundle = recovered.exportAudit(h.p('auditor'), 'post-migration pinned export'), trust = { [old.key_id]: { public_key: old.public_key }, [x.next_key_id]: { public_key: x.next_public_key } };
  assert.equal(verifyAudit(bundle, trust).valid, true);
  const file = join(h.directory, 'rotated.json'), pinned = join(h.directory, 'pinned.json'); writeFileSync(file, JSON.stringify(bundle)); writeFileSync(pinned, JSON.stringify(trust));
  const out = spawnSync(process.execPath, ['scripts/verify-export-webcrypto.mjs', file, pinned], { encoding: 'utf8' }); assert.equal(out.status, 0, out.stderr);
});
test('KEY-005: execution suite rotation invalidates old live authority and a stale peer cannot mint with the retired key', t => {
  const h = fixture(t), old = h.ready(), keys = Object.values(h.setup.custodianKeys.acme);
  const peer = new h.f.constructor(clone(h.setup.config), h.directory, h.now); t.after(() => peer.close());
  const x = h.f.keyGovernance.prepare(h.p('security'), { purpose: 'execution', suite: 'ECDSA-P256-SHA256-v1', not_before: h.now() + 60000 });
  h.advance(60000); h.f.keyGovernance.activate(h.p('security'), { rotation_id: x.rotation_id, signatures: keys.slice(0, 3).map(k => signed(x, k, 'key-rotation')) });
  assert.throws(() => peer.execute(h.p(), old.certificate), hasCode('INV-401-SIGNATURE'));
  const next = h.ready(); assert.equal(next.certificate.protected.suite, x.next_suite); assert.equal(h.f.execute(h.p(), next.certificate).payload.status, 'VERIFIED');
});
