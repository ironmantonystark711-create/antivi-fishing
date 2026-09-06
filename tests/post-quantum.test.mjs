import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { generateKey, signed, verifySigned } from '../src/crypto.mjs';
import { clone } from '../src/canonical.mjs';
for (const algorithm of ['ML-DSA-65-v1', 'HYBRID-Ed25519-ML-DSA-65-v1']) test(`KEY-006 KEY-005: ${algorithm} signs, rejects tampering and verifies independently without classical fallback`, t => {
 const h = fixture(t), k = generateKey(algorithm), payload = { tenant_id: 'acme', action: 'exact' }, e = signed(payload, k, 'audit'), keys = { [k.key_id]: k };
 assert.deepEqual(verifySigned(e, keys, 'audit'), payload);
 for (const offset of [0, 64, Buffer.from(e.signature, 'base64url').length-1]) { const bad = clone(e), bytes = Buffer.from(bad.signature, 'base64url'); bytes[offset] ^= 1; bad.signature = bytes.toString('base64url'); assert.throws(() => verifySigned(bad, keys, 'audit')); }
 const downgraded = clone(e); downgraded.protected.suite = 'Ed25519'; assert.throws(() => verifySigned(downgraded, keys, 'audit'));
 h.f.store.auditKeys.acme = k; h.f.store.tx(() => h.f.store.audit('acme', 'PQ_TEST', 'customer', 'pq', {}, h.now()));
 const bundle = h.f.store.auditExport('acme'), old = h.f.keys('acme').audit, trust = { [k.key_id]: { public_key: k.public_key }, [old.key_id]: { public_key: old.public_key } };
 const path = join(h.directory, 'pq-audit.json'), pins = join(h.directory, 'pq-pins.json'); writeFileSync(path, JSON.stringify(bundle)); writeFileSync(pins, JSON.stringify(trust));
 const result = spawnSync(process.execPath, ['scripts/verify-export-webcrypto.mjs', path, pins], { encoding: 'utf8' }); assert.equal(result.status, 0, result.stderr);
});
test('KEY-006 KEY-005: customer-approved hybrid migration executes real certificates and forbids component downgrade', t => {
 const h = fixture(t), x = h.f.keyGovernance.prepare(h.p('security'), { purpose: 'execution', suite: 'HYBRID-Ed25519-ML-DSA-65-v1', not_before: h.now() + 60000 });
 h.advance(60000); h.f.keyGovernance.activate(h.p('security'), { rotation_id: x.rotation_id, signatures: Object.values(h.setup.custodianKeys.acme).slice(0, 3).map(k => signed(x, k, 'key-rotation')) });
 const r = h.ready(); assert.equal(r.certificate.protected.suite, x.next_suite); assert.equal(h.f.execute(h.p(), r.certificate).payload.status, 'VERIFIED');
 for (const suite of ['ECDSA-P256-SHA256-v1', 'ML-DSA-65-v1']) assert.throws(() => h.f.keyGovernance.prepare(h.p('security'), { purpose: 'execution', suite, not_before: h.now() + 60000 }));
});
