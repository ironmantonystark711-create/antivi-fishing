import { randomBytes, randomUUID, createCipheriv, publicEncrypt } from 'node:crypto';
import { digest, clone, canonical } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { requireThat } from './errors.mjs';
import { fields, uniqueStrings, integer, identifier, text } from './schema.mjs';
// Software-side protected transport harness. Never claims OS-resistant plaintext or trusted physical input.
export class PerceptionBroker {
  #challenges = new Map(); #sessions = new Map(); #revokedMeasurements = new Set();
  constructor({ attestationKeys, auditKey, clock = Date.now, measurements, isRevoked = () => false }) { this.keys = attestationKeys; this.auditKey = auditKey; this.clock = clock; this.measurements = new Set(measurements); this.isRevoked = isRevoked; }
  challenge(tenant, subject, device) {
    identifier(tenant); identifier(subject); identifier(device);
    const now = this.clock(); for (const [id, c] of this.#challenges) if (c.expires_at <= now) this.#challenges.delete(id);
    requireThat(this.#challenges.size < 256, 'INV-429-CAPACITY', 'Attestation challenge capacity reached', 429);
    const c = { format: 'IF-ATTESTATION-1', challenge_id: randomUUID(), tenant_id: tenant, subject_id: subject, device_id: device, nonce: randomBytes(32).toString('hex'), issued_at: now, expires_at: now + 60000 }; this.#challenges.set(c.challenge_id, c); return clone(c);
  }
  open(envelope, policy) {
    fields(policy, ['require_hardware', 'allow_lower_assurance', 'fields', 'purpose', 'ttl_ms']); uniqueStrings(policy.fields, 'display fields', 16); requireThat(policy.fields.length > 0, 'INV-400-SCHEMA', 'Explicit nonempty display field scope required'); text(policy.purpose, 'display purpose', 128); integer(policy.ttl_ms, 'display TTL', 1000, 60000);
    requireThat(policy.require_hardware === false && policy.allow_lower_assurance === true, 'INV-501-HARDWARE', 'Real trusted hardware unavailable; no Secure Perception guarantee', 501);
    const a = verifySigned(envelope, this.keys, 'device-attestation'); fields(a, ['challenge', 'measurement', 'firmware', 'display_key', 'assurance']);
    const c = this.#challenges.get(a.challenge.challenge_id), now = this.clock();
    requireThat(c && digest(c) === digest(a.challenge) && c.expires_at > now && a.assurance === 'SIMULATED' && this.measurements.has(`${a.measurement}:${a.firmware}`), 'INV-403-ATTESTATION', 'Attestation, freshness or version trust failed', 403);
    requireThat(!this.#revokedMeasurements.has(`${a.measurement}:${a.firmware}`) && !this.isRevoked('issuer', envelope.protected.key_id) && !this.isRevoked('device', c.device_id), 'INV-403-ATTESTATION', 'Attestation authority, device or firmware revoked', 403);
    for (const [id, session] of this.#sessions) if (session.expires_at <= now) this.#sessions.delete(id);
    requireThat(this.#sessions.size < 256, 'INV-429-CAPACITY', 'Protected-session capacity reached', 429);
    requireThat(typeof a.display_key === 'string' && a.display_key.length < 8192, 'INV-400-SCHEMA', 'Attested encryption key required');
    // Verify usable RSA-OAEP SPKI before consuming challenge.
    publicEncrypt({ key: a.display_key, oaepHash: 'sha256' }, randomBytes(32)); this.#challenges.delete(c.challenge_id);
    const session = { ...c, session_id: randomUUID(), attestation_key_id: envelope.protected.key_id, measurement: `${a.measurement}:${a.firmware}`, display_key: a.display_key, fields: clone(policy.fields), purpose: policy.purpose, expires_at: now + policy.ttl_ms, assurance: 'LOWER_ASSURANCE_SOFTWARE_SIMULATION', secure_mode: false };
    this.#sessions.set(session.session_id, session); return signed({ session_id: session.session_id, tenant_id: c.tenant_id, assurance: session.assurance, secure_mode: false, expires_at: session.expires_at }, this.auditKey, 'perception-session');
  }
  deliver(id, principal, content, purpose) {
    const s = this.#sessions.get(id); requireThat(s && s.tenant_id === principal.tenant_id && s.subject_id === principal.subject_id && s.expires_at > this.clock() && purpose === s.purpose, 'INV-403-PERCEPTION', 'Protected output scope or time denied', 403);
    requireThat(!this.#revokedMeasurements.has(s.measurement) && this.measurements.has(s.measurement) && this.keys[s.attestation_key_id] && !this.keys[s.attestation_key_id].revoked && !this.isRevoked('issuer', s.attestation_key_id) && !this.isRevoked('device', s.device_id), 'INV-403-ATTESTATION', 'Protected session authority or firmware revoked', 403);
    requireThat(content && typeof content === 'object' && !Array.isArray(content) && Buffer.byteLength(canonical(content)) <= 65536, 'INV-413-BODY', 'Protected content exceeds bounded structured profile', 413);
    const selected = Object.fromEntries(s.fields.filter(f => Object.hasOwn(content, f)).map(f => [f, content[f]])), key = randomBytes(32), iv = randomBytes(12), aad = { session_id: id, tenant_id: s.tenant_id, fields: s.fields, purpose };
    const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(canonical(aad))); const ciphertext = Buffer.concat([cipher.update(canonical(selected)), cipher.final()]);
    const wrappedKey = publicEncrypt({ key: s.display_key, oaepHash: 'sha256' }, key); key.fill(0);
    return signed({ format: 'IF-PERCEPTION-OUTPUT-1', aad, encrypted_key: wrappedKey.toString('base64url'), iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url'), assurance: s.assurance, secure_mode: false }, this.auditKey, 'perception-output');
  }
  revokeMeasurement(measurement, firmware) { text(measurement, 'measurement', 128); text(firmware, 'firmware', 128); const id = `${measurement}:${firmware}`; this.#revokedMeasurements.add(id); for (const [key, session] of this.#sessions) if (session.measurement === id) this.#sessions.delete(key); }
  close(id) { this.#sessions.delete(id); }
}
