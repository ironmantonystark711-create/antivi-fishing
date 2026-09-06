import { createHmac, timingSafeEqual } from 'node:crypto';
import { clone, digest, canonical } from './canonical.mjs';
import { requireThat } from './errors.mjs';
import { fields, identifier, oneOf, text, uniqueStrings } from './schema.mjs';
export function protectOutput(rows, context, policy, key) {
  const copy = clone(rows);
  if (!policy || !policy.enabled) return { rows: copy, watermark: null };
  fields(policy, ['enabled', 'lawful_basis', 'mode']); oneOf(policy.mode, ['metadata', 'visible'], 'watermark mode');
  requireThat(typeof policy.lawful_basis === 'string' && policy.lawful_basis.length > 0, 'INV-451-PRIVACY', 'Watermarking requires explicit lawful basis', 451);
  fields(context, ['tenant_id', 'subject_id', 'session_id', 'destination']); identifier(context.tenant_id, 'tenant'); identifier(context.subject_id, 'subject'); text(context.session_id, 'session', 128); text(context.destination, 'destination', 256);
  const metadata = { format: 'IF-OUTPUT-ATTRIBUTION-1', tenant_id: context.tenant_id, subject_id: context.subject_id, session_id: context.session_id, destination: context.destination, content_digest: digest(copy), policy_digest: digest(policy) };
  const tag = createHmac('sha256', key).update(canonical(metadata)).digest('hex');
  return { rows: copy, watermark: { metadata, tag, visible_label: policy.mode === 'visible' ? `Authorised session ${context.session_id} · ${tag.slice(0, 12)}` : null } };
}
export function verifyOutputAttribution(rows, watermark, policy, key) {
  requireThat(watermark && typeof watermark === 'object', 'INV-400-ATTRIBUTION', 'Output attribution is required');
  fields(watermark, ['metadata', 'tag', 'visible_label']);
  const metadata = watermark.metadata;
  fields(metadata, ['format', 'tenant_id', 'subject_id', 'session_id', 'destination', 'content_digest', 'policy_digest']);
  requireThat(metadata.format === 'IF-OUTPUT-ATTRIBUTION-1' && /^[a-f0-9]{64}$/.test(metadata.content_digest) && /^[a-f0-9]{64}$/.test(metadata.policy_digest), 'INV-400-ATTRIBUTION', 'Invalid output attribution metadata');
  identifier(metadata.tenant_id, 'tenant'); identifier(metadata.subject_id, 'subject'); text(metadata.session_id, 'session', 128); text(metadata.destination, 'destination', 256);
  requireThat(metadata.content_digest === digest(rows) && metadata.policy_digest === digest(policy), 'INV-409-ATTRIBUTION', 'Output or policy attribution mismatch', 409);
  const expected = createHmac('sha256', key).update(canonical(metadata)).digest('hex');
  const supplied = typeof watermark.tag === 'string' ? Buffer.from(watermark.tag, 'hex') : Buffer.alloc(0);
  const actual = Buffer.from(expected, 'hex');
  requireThat(supplied.length === actual.length && timingSafeEqual(supplied, actual), 'INV-401-ATTRIBUTION', 'Output attribution signature invalid', 401);
  const expectedLabel = policy.mode === 'visible' ? `Authorised session ${metadata.session_id} · ${expected.slice(0, 12)}` : null;
  requireThat(watermark.visible_label === expectedLabel, 'INV-409-ATTRIBUTION', 'Output attribution label mismatch', 409);
  return { valid: true, metadata: clone(metadata) };
}
export function shieldRows(rows, input, key) {
  fields(input, ['remove', 'mask', 'tokenize', 'aggregate']); for (const k of ['remove', 'mask', 'tokenize']) uniqueStrings(input[k], k, 64);
  requireThat(typeof input.aggregate === 'boolean', 'INV-400-SCHEMA', 'Aggregation selection required');
  if (input.aggregate) return { row_count: rows.length };
  return rows.map(row => Object.fromEntries(Object.entries(row).filter(([k]) => !input.remove.includes(k)).map(([k, v]) => [k, input.mask.includes(k) ? '[REDACTED]' : input.tokenize.includes(k) ? createHmac('sha256', key).update(canonical({ field: k, value: v })).digest('hex') : clone(v)])));
}
export function applyShield(rows, transformation, key) {
  fields(transformation, ['columns', 'exclusions']); uniqueStrings(transformation.columns, 'shield columns', 64); uniqueStrings(transformation.exclusions, 'shield exclusions', 64);
  requireThat(transformation.columns.length > 0 && transformation.columns.every(column => !transformation.exclusions.includes(column)), 'INV-451-POLICY', 'SHIELD transformation must retain only allowed fields', 451);
  return shieldRows(rows, { remove: Object.keys(rows[0] ?? {}).filter(column => !transformation.columns.includes(column)), mask: [], tokenize: [], aggregate: false }, key);
}
