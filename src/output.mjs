import { createHmac } from 'node:crypto';
import { clone, digest, canonical } from './canonical.mjs';
import { requireThat } from './errors.mjs';
import { fields, oneOf, uniqueStrings } from './schema.mjs';
export function protectOutput(rows, context, policy, key) {
  const copy = clone(rows);
  if (!policy || !policy.enabled) return { rows: copy, watermark: null };
  fields(policy, ['enabled', 'lawful_basis', 'mode']); oneOf(policy.mode, ['metadata', 'visible'], 'watermark mode');
  requireThat(typeof policy.lawful_basis === 'string' && policy.lawful_basis.length > 0, 'INV-451-PRIVACY', 'Watermarking requires explicit lawful basis', 451);
  const metadata = { format: 'IF-OUTPUT-ATTRIBUTION-1', tenant_id: context.tenant_id, subject_id: context.subject_id, session_id: context.session_id, destination: context.destination, content_digest: digest(copy), policy_digest: digest(policy) };
  const tag = createHmac('sha256', key).update(canonical(metadata)).digest('hex');
  return { rows: copy, watermark: { metadata, tag, visible_label: policy.mode === 'visible' ? `Authorised session ${context.session_id} · ${tag.slice(0, 12)}` : null } };
}
export function shieldRows(rows, input, key) {
  fields(input, ['remove', 'mask', 'tokenize', 'aggregate']); for (const k of ['remove', 'mask', 'tokenize']) uniqueStrings(input[k], k, 64);
  requireThat(typeof input.aggregate === 'boolean', 'INV-400-SCHEMA', 'Aggregation selection required');
  if (input.aggregate) return { row_count: rows.length };
  return rows.map(row => Object.fromEntries(Object.entries(row).filter(([k]) => !input.remove.includes(k)).map(([k, v]) => [k, input.mask.includes(k) ? '[REDACTED]' : input.tokenize.includes(k) ? createHmac('sha256', key).update(canonical({ field: k, value: v })).digest('hex') : clone(v)])));
}
