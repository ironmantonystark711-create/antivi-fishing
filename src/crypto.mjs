import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { canonical, digest, clone, parseStrict } from './canonical.mjs';
import { requireThat } from './errors.mjs';
import { suite } from './suites.mjs';
const privateCache = new WeakMap(), publicCache = new Map();
function privateObject(key) { let cached = privateCache.get(key); if (!cached || cached.source !== key.private_key) { cached = { source: key.private_key, value: createPrivateKey(key.private_key) }; privateCache.set(key, cached); } return cached.value; }
function publicObject(pem) { if (!publicCache.has(pem)) { if (publicCache.size >= 256) publicCache.delete(publicCache.keys().next().value); publicCache.set(pem, createPublicKey(pem)); } return publicCache.get(pem); }

function requireSuiteKey(key, profile) {
  requireThat(key.asymmetricKeyType === profile.key_type && (!profile.curve || key.asymmetricKeyDetails?.namedCurve === profile.curve), 'INV-401-SIGNATURE', 'Key does not match cryptographic suite', 401);
}

export function generateKey(suiteId = 'Ed25519') {
  const s = suite(suiteId, 'sign');
  if (s.hybrid) {
    const classical = generateKey('Ed25519'), pq = generateKey('ML-DSA-65-v1');
    const public_key = canonical({ classical: classical.public_key, pq: pq.public_key }), private_key = canonical({ classical: classical.private_key, pq: pq.private_key });
    return { key_id: digest(public_key).slice(0, 32), suite: suiteId, private_key, public_key };
  }
  const { privateKey, publicKey } = generateKeyPairSync(s.key_type, s.curve ? { namedCurve: s.curve } : {});
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  return { suite: suiteId, key_id: digest({ public_key: pub }).slice(0, 32), public_key: pub, private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}
export function signed(payload, key, purpose, options = {}) {
  const s = suite(key.suite ?? 'Ed25519', 'sign', options.now ?? Date.now(), options.policy);
  const privateKey = s.hybrid ? null : privateObject(key); if (privateKey) requireSuiteKey(privateKey, s);
  const protectedHeader = { profile: 'IF-CJSON-1', suite: s.id, key_id: key.key_id, purpose };
  const message = Buffer.from(canonical({ protected: protectedHeader, payload }));
  let signature;
  if (s.hybrid) {
    const parts = parseStrict(key.private_key); requireThat(Object.keys(parts).sort().join(',') === 'classical,pq', 'INV-401-SIGNATURE', 'Invalid hybrid key', 401);
    const a = createPrivateKey(parts.classical), b = createPrivateKey(parts.pq); requireSuiteKey(a, suite('Ed25519')); requireSuiteKey(b, suite('ML-DSA-65-v1'));
    signature = Buffer.concat([sign(null, message, a), sign(null, message, b)]);
  } else signature = sign(s.digest, message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { protected: protectedHeader, payload: clone(payload), signature: signature.toString('base64url') };
}
export function verifySigned(envelope, publicKeys, purpose, options = {}) {
  requireThat(envelope && Object.keys(envelope).sort().join() === 'payload,protected,signature', 'INV-401-SIGNATURE', 'Invalid signed envelope', 401);
  const h = envelope.protected;
  requireThat(h && Object.keys(h).sort().join() === 'key_id,profile,purpose,suite' && h.profile === 'IF-CJSON-1' && h.purpose === purpose, 'INV-401-SIGNATURE', 'Unsupported signature context', 401);
  const s = suite(h.suite, 'verify', options.now ?? Date.now(), options.policy);
  const key = Object.hasOwn(publicKeys, h.key_id) ? publicKeys[h.key_id] : null;
  requireThat(key && !key.revoked, 'INV-401-SIGNATURE', 'Signer unavailable', 401);
  requireThat(typeof envelope.signature === 'string' && new RegExp(`^[A-Za-z0-9_-]{${Math.ceil(s.signature_bytes * 4 / 3)}}$`).test(envelope.signature), 'INV-401-SIGNATURE', 'Invalid signature encoding', 401);
  requireThat(Buffer.from(envelope.signature, 'base64url').toString('base64url') === envelope.signature, 'INV-401-SIGNATURE', 'Noncanonical signature encoding', 401);
  let ok = false;
  try {
    const message = Buffer.from(canonical({ protected: h, payload: envelope.payload })), signature = Buffer.from(envelope.signature, 'base64url');
    if (s.hybrid) {
      const parts = parseStrict(key.public_key); requireThat(Object.keys(parts).sort().join(',') === 'classical,pq', 'INV-401-SIGNATURE', 'Invalid hybrid key', 401);
      const a = publicObject(parts.classical), b = publicObject(parts.pq); requireSuiteKey(a, suite('Ed25519')); requireSuiteKey(b, suite('ML-DSA-65-v1'));
      ok = verify(null, message, a, signature.subarray(0, 64)) && verify(null, message, b, signature.subarray(64));
    } else { const publicKey = publicObject(key.public_key); requireSuiteKey(publicKey, s); ok = verify(s.digest, message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature); }
  } catch { ok = false; }
  requireThat(ok, 'INV-401-SIGNATURE', 'Signature verification failed', 401);
  return envelope.payload;
}
export function encrypt(value, key, aad) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(canonical(value), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map(b => b.toString('base64url')).join('.');
}
export function decrypt(value, key, aad) {
  const [iv, tag, data] = value.split('.').map(x => Buffer.from(x, 'base64url'));
  const decipher = createDecipheriv('aes-256-gcm', key, iv); decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}
export function secretEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a), bb = Buffer.from(b); return aa.length === bb.length && timingSafeEqual(aa, bb);
}
