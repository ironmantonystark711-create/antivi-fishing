import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { PerceptionBroker } from '../src/perception.mjs';
import { generateKey, signed } from '../src/crypto.mjs';

function fixture(maxSessions = 2) {
  const issuer = generateKey(), keys = { [issuer.key_id]: { public_key: issuer.public_key } }; let now = 100000;
  const broker = new PerceptionBroker({ attestationKeys: keys, auditKey: generateKey(), clock: () => now, measurements: ['simulation:1'], maxSessions });
  const display = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  const principal = { tenant_id: 'synthetic', subject_id: 'reviewer', device_id: 'device-1' }, policy = { require_hardware: false, allow_lower_assurance: true, fields: ['amount'], purpose: 'review', ttl_ms: 1000 };
  const envelope = () => signed({ challenge: broker.challenge(principal.tenant_id, principal.subject_id, principal.device_id), measurement: 'simulation', firmware: '1', display_key: display, assurance: 'SIMULATED' }, issuer, 'device-attestation');
  const open = () => broker.open(envelope(), policy).payload.session_id;
  return { broker, keys, issuer, principal, policy, envelope, open, advance: value => { now += value; } };
}

test('PER-007 KEY-011: existing sessions lose output immediately on attestor, firmware or device revocation', () => {
  for (const revoke of [h => { h.keys[h.issuer.key_id].revoked = true; }, h => h.broker.revokeMeasurement('simulation', '1'), h => h.broker.revokeDevice('synthetic', 'device-1')]) {
    const h = fixture(), id = h.open(); assert.equal(h.broker.deliver(id, h.principal, { amount: 1 }, 'review').payload.secure_mode, false);
    revoke(h); assert.throws(() => h.broker.deliver(id, h.principal, { amount: 1 }, 'review')); assert.throws(h.open);
  }
});
test('PER-003 PER-006 PER-007: scope, purpose, clock rollback and expired sessions cannot release output', () => {
  const h = fixture(), id = h.open();
  for (const principal of [{ ...h.principal, tenant_id: 'other' }, { ...h.principal, device_id: 'device-2' }, { ...h.principal, subject_id: 'other' }]) assert.throws(() => h.broker.deliver(id, principal, { amount: 1 }, 'review'));
  assert.throws(() => h.broker.deliver(id, h.principal, { amount: 1 }, 'unapproved'));
  h.advance(-1); assert.throws(() => h.broker.deliver(id, h.principal, { amount: 1 }, 'review'));
  h.advance(1001); assert.throws(() => h.broker.deliver(id, h.principal, { amount: 1 }, 'review'));
});
test('PER-006 PER-009 PER-010: bounded fallback recovers capacity and rejects weak display keys or hardware claims', () => {
  const h = fixture(1); h.open(); assert.throws(h.open); h.advance(1000); assert.ok(h.open());
  const x = fixture(), envelope = x.envelope();
  assert.throws(() => x.broker.open(envelope, { ...x.policy, require_hardware: true }));
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => x.broker.open(signed({ ...envelope.payload, display_key: weak }, x.issuer, 'device-attestation'), x.policy));
  assert.ok(x.broker.open(envelope, x.policy));
});
