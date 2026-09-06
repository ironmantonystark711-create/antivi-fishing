import { digest } from './canonical.mjs';
import { signed } from './crypto.mjs';
import { oneOf, text } from './schema.mjs';

const projectionFields = {
  finance: ['action_type', 'decision', 'status', 'reason', 'certificate_id'],
  security: ['code', 'status', 'reason', 'config_digest', 'version'],
  privacy: ['legal_hold', 'logical_deletion_only', 'original_digest'],
  technical: ['capsule_digest', 'certificate_digest', 'evidence_digest', 'decision_digest', 'outcome_digest', 'config_digest', 'version']
};
export function auditView(f, p, role, purpose) {
  oneOf(role, Object.keys(projectionFields), 'audit projection'); text(purpose, 'audit purpose', 256);
  f.authorize(p, [`audit_${role}`]);
  return f.transaction(p, now => {
    f.store.audit(p.tenant_id, 'AUDIT_VIEW_ACCESSED', p.subject_id, `projection:${role}`, { purpose_digest: digest(purpose) }, now);
    const rows = f.store.db.prepare('SELECT hash,envelope FROM audit WHERE tenant=? ORDER BY seq LIMIT 1000').all(p.tenant_id);
    const entries = rows.map(row => { const e = JSON.parse(row.envelope).payload; return { sequence: e.sequence, time: e.time, type: e.type, ...(role === 'security' ? { actor: e.actor } : {}), ...(role === 'finance' ? { reference: e.reference } : {}), ...(role === 'technical' ? { source_digest: row.hash } : {}), metadata: Object.fromEntries(Object.entries(e.metadata).filter(([k]) => projectionFields[role].includes(k))) }; });
    return signed({ format: 'IF-AUDIT-PROJECTION-1', tenant_id: p.tenant_id, role, purpose_digest: digest(purpose), issued_at: now, entries, truncated: rows.length === 1000, full_chain: false }, f.keys(p.tenant_id).audit, 'audit-projection');
  });
}
