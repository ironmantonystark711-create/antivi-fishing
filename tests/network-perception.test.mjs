import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, privateDecrypt, createDecipheriv } from 'node:crypto';
import { fixture, runtimeInput } from './helpers.mjs';
import { LocalNetworkGate } from '../src/network.mjs';
import { PerceptionBroker } from '../src/perception.mjs';
import { signed } from '../src/crypto.mjs';
import { canonical } from '../src/canonical.mjs';
function network(h) {
 const cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
 const gate = new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), clock: h.now, maxEntries: 2, policyDigest: cap.payload.policy_digest, snapshot: h.setup.config.tenants.acme.runtime_snapshot.config });
 let delivered = 0; gate.register('erp-service', p => { delivered++; return { received: p }; }); gate.importCapability(cap);
 const request = { capability_id: cap.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: 'request-1' };
 return { gate, cap, request, delivered: () => delivered };
}
test('NET-001 NET-002 NET-003 NET-007 NET-009 RUN-001: local process dispatch requires exact tenant/device/service capability, even offline', t => {
 const h = fixture(t), n = network(h);
 for (const changed of [{ destination: 'peer-workstation' }, { tenant_id: 'globex' }, { device_id: 'moved-device' }, { subject_id: 'attacker' }, { port: 22 }, { protocol: 'tcp' }]) assert.equal(n.gate.send({ ...n.request, ...changed }, {}).decision, 'DENY');
 assert.equal(n.delivered(), 0); assert.equal(n.gate.send(n.request, { action: 'ping' }).decision, 'ALLOW'); assert.equal(n.delivered(), 1);
 // Close the entire control plane. Cached local enforcement remains operational without it.
 h.close(); assert.equal(n.gate.send({ ...n.request, request_id: 'request-2' }, {}).decision, 'ALLOW');
 assert.equal(n.gate.send(n.request, {}).code, 'INV-409-REPLAY');
});
test('NET-004 NET-005 NET-006 NET-010 RUN-004 RUN-008 RUN-009: rate, quarantine, revocation, exhaustion and containment counters', t => {
 const h = fixture(t), n = network(h);
 for (let i = 0; i < 20; i++) assert.equal(n.gate.send({ ...n.request, request_id: `r-${i}` }, {}).decision, 'ALLOW');
 assert.equal(n.gate.send({ ...n.request, request_id: 'rate-excess' }, {}).code, 'INV-429-RATE'); n.gate.quarantine('operator-device');
 assert.equal(n.gate.send({ ...n.request, request_id: 'quarantine' }, {}).code, 'INV-403-QUARANTINE'); assert.equal(n.gate.send({ ...n.request, destination: 'peer-workstation', request_id: 'peer' }, {}).decision, 'DENY');
 assert.equal(n.gate.report().events.at(-1).reason, 'HEALTH_LOST'); assert.equal(n.delivered(), 20);
 const x = network(h); x.gate.revoke(x.cap.payload.capability_id); assert.equal(x.gate.send(x.request, {}).code, 'INV-401-CAPABILITY'); x.gate.withdraw(); assert.equal(x.gate.send(x.request, {}).code, 'INV-503-CONFIG');
});
test('PER-001 PER-003 PER-006 PER-007 PER-009 PER-010: software transport contract encrypts only allowed fields and never claims hardware assurance', t => {
 const h = fixture(t), key = h.setup.issuerKeys.acme.governance, broker = new PerceptionBroker({ attestationKeys: h.f.tenant('acme').issuers, auditKey: h.f.keys('acme').audit, clock: h.now, measurements: ['display-sim:1'] });
 const display = generateKeyPairSync('rsa', { modulusLength: 2048 }); const challenge = broker.challenge('acme', 'operator', 'operator-device');
 const attestation = signed({ challenge, measurement: 'display-sim', firmware: '1', display_key: display.publicKey.export({ type: 'spki', format: 'pem' }), assurance: 'SIMULATED' }, key, 'device-attestation');
 const policy = { require_hardware: false, allow_lower_assurance: true, fields: ['amount'], purpose: 'review', ttl_ms: 1000 };
 assert.throws(() => broker.open(attestation, { ...policy, require_hardware: true })); const session = broker.open(attestation, policy); assert.equal(session.payload.secure_mode, false); assert.throws(() => broker.open(attestation, policy));
 const result = broker.deliver(session.payload.session_id, h.p(), { amount: 'CONFIDENTIAL-TEST-100', other: 'NEVER-RELEASE' }, 'review'); assert.doesNotMatch(JSON.stringify(result), /CONFIDENTIAL-TEST-100|NEVER-RELEASE/);
 const p = result.payload, unwrapped = privateDecrypt({ key: display.privateKey, oaepHash: 'sha256' }, Buffer.from(p.encrypted_key, 'base64url')), decipher = createDecipheriv('aes-256-gcm', unwrapped, Buffer.from(p.iv, 'base64url')); decipher.setAAD(Buffer.from(canonical(p.aad))); decipher.setAuthTag(Buffer.from(p.tag, 'base64url'));
 const plaintext = JSON.parse(Buffer.concat([decipher.update(Buffer.from(p.ciphertext, 'base64url')), decipher.final()])); assert.deepEqual(plaintext, { amount: 'CONFIDENTIAL-TEST-100' });
 assert.throws(() => broker.deliver(session.payload.session_id, h.p('operator', 'globex'), {}, 'review')); h.advance(1001); assert.throws(() => broker.deliver(session.payload.session_id, h.p(), {}, 'review'));
});
