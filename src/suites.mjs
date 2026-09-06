import { requireThat } from './errors.mjs';
// Versioned, closed registry. No caller-supplied algorithms or executable extensions.
export const SUITES = Object.freeze({
  Ed25519: Object.freeze({ id: 'Ed25519', version: 1, key_type: 'ed25519', digest: null, hash: 'sha256', encryption: 'aes-256-gcm', deprecated_at: null, sign_until: null, verify_until: null }),
  'ECDSA-P256-SHA256-v1': Object.freeze({ id: 'ECDSA-P256-SHA256-v1', version: 1, key_type: 'ec', curve: 'prime256v1', digest: 'sha256', hash: 'sha256', encryption: 'aes-256-gcm', deprecated_at: null, sign_until: null, verify_until: null })
});
export const ALGORITHM_INVENTORY = Object.freeze(Object.values(SUITES).map(s => Object.freeze({ id: s.id, version: s.version, uses: ['signature', 'audit', 'capability'], transition: 'Approved only through a signed migration policy; no marketing security claim.', post_quantum: false })));
export function suite(id, operation = 'verify', now = Date.now(), policy = {}) {
  const s = Object.hasOwn(SUITES, id) ? SUITES[id] : null;
  requireThat(s && ['sign', 'verify'].includes(operation), 'INV-401-SIGNATURE', 'Unsupported cryptographic suite', 401);
  requireThat(policy === undefined || (policy && typeof policy === 'object' && !Array.isArray(policy)), 'INV-401-SIGNATURE', 'Invalid cryptographic suite policy', 401);
  const selected = policy[id] ?? s;
  requireThat(selected && typeof selected === 'object' && (selected.id === undefined || selected.id === id), 'INV-401-SIGNATURE', 'Invalid cryptographic suite policy', 401);
  const cutoff = selected[`${operation}_until`];
  requireThat(cutoff == null || now < cutoff, 'INV-401-SIGNATURE', 'Cryptographic suite no longer permitted', 401);
  if (operation === 'sign' && selected.not_before != null) requireThat(now >= selected.not_before, 'INV-401-SIGNATURE', 'Cryptographic suite is not active yet', 401);
  return s;
}
export function migrationPolicy(from, to, notBefore, signUntil, verifyUntil = null) {
  suite(from); suite(to); requireThat(from !== to && Number.isSafeInteger(notBefore) && Number.isSafeInteger(signUntil) && signUntil > notBefore && (verifyUntil === null || (Number.isSafeInteger(verifyUntil) && verifyUntil > signUntil)), 'INV-400-SCHEMA', 'Invalid cryptographic migration');
  return { format: 'IF-CRYPTO-MIGRATION-1', from, to, not_before: notBefore, suites: { [from]: { id: from, deprecated_at: notBefore, sign_until: signUntil, verify_until: verifyUntil }, [to]: { id: to, not_before: notBefore, deprecated_at: null, sign_until: null, verify_until: null } }, preserve_historical_verification: true };
}
