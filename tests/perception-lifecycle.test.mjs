import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { PerceptionBroker } from '../src/perception.mjs';
import { signed } from '../src/crypto.mjs';
function setup(h) {
 const key = h.setup.issuerKeys.acme.governance, display = generateKeyPairSync('rsa', { modulusLength: 2048 }), broker = new PerceptionBroker({ attestationKeys: h.f.tenant('acme').issuers, auditKey: h.f.keys('acme').audit, clock: h.now, measurements: ['sim:1'], isRevoked: (kind, id) => h.f.revoked('acme', kind, id) });
 const attestation = () => signed({ challenge: broker.challenge('acme', 'operator', 'operator-device'), measurement: 'sim', firmware: '1', display_key: display.publicKey.export({ type: 'spki', format: 'pem' }), assurance: 'SIMULATED' }, key, 'device-attestation');
 const policy = { require_hardware: false, allow_lower_assurance: true, fields: ['amount'], purpose: 'review', ttl_ms: 1000 };
 return { broker, attestation, policy, key };
}
for (const revocation of ['issuer', 'device', 'firmware']) test(`PER-007 PER-006: ${revocation} revocation terminates live protected transport before plaintext release`, t => {
 const h = fixture(t), x = setup(h), id = x.broker.open(x.attestation(), x.policy).payload.session_id;
 assert.ok(x.broker.deliver(id, h.p(), { amount: 5 }, 'review').payload.ciphertext);
 if (revocation === 'firmware') x.broker.revokeMeasurement('sim', '1');
 else h.f.revoke(h.p('security'), { kind: revocation, id: revocation === 'issuer' ? x.key.key_id : 'operator-device', reason: 'revoked while viewing' });
 assert.throws(() => x.broker.deliver(id, h.p(), { amount: 5 }, 'review'));
 assert.throws(() => x.broker.open(x.attestation(), x.policy));
});
test('PER-001 PER-007 PER-009 PER-010: software sessions reject wrong purpose, oversized fields, empty scope and stale challenges without hardware claims', t => {
 const h = fixture(t), x = setup(h), e = x.attestation();
 assert.throws(() => x.broker.open(e, { ...x.policy, fields: [] }), hasCode('INV-400-SCHEMA'));
 assert.throws(() => x.broker.open(e, { ...x.policy, allow_lower_assurance: false }), hasCode('INV-501-HARDWARE'));
 const session = x.broker.open(e, x.policy); assert.equal(session.payload.secure_mode, false);
 assert.throws(() => x.broker.deliver(session.payload.session_id, h.p(), { amount: 5 }, 'other-purpose'), hasCode('INV-403-PERCEPTION'));
 assert.throws(() => x.broker.deliver(session.payload.session_id, h.p(), { amount: 'a'.repeat(65536) }, 'review'), hasCode('INV-413-BODY'));
 const stale = x.attestation(); h.advance(60001); assert.throws(() => x.broker.open(stale, x.policy), hasCode('INV-403-ATTESTATION'));
});
