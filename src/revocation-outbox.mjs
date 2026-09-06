import { clone } from './canonical.mjs';
import { integer, identifier } from './schema.mjs';
import { requireThat } from './errors.mjs';

const recordId = sequence => `r-${String(sequence).padStart(16, '0')}`;

export class RuntimeRevocationOutbox {
  constructor(fabric) { this.f = fabric; }
  enqueue(tenant, envelope, payload, now) {
    if (!['capability', 'subject', 'key'].includes(payload.kind)) return null;
    const state = this.f.store.get(tenant, 'runtime-revocation-state', 'sequence') ?? { sequence: 0 }, sequence = state.sequence + 1;
    this.f.store.put(tenant, 'runtime-revocation-state', 'sequence', { sequence, updated_at: now }, now);
    const record = { sequence, envelope: clone(envelope), created_at: now };
    this.f.store.insert(tenant, 'runtime-revocation-outbox', recordId(sequence), record, now);
    return record;
  }
  read(tenant, after = 0, limit = 64) {
    integer(after, 'revocation cursor', 0); integer(limit, 'revocation limit', 1, 256);
    const rows = this.f.store.statement('SELECT id FROM records WHERE tenant=? AND kind=? AND id>? ORDER BY id ASC LIMIT ?').all(tenant, 'runtime-revocation-outbox', recordId(after), limit);
    return rows.map(row => this.f.store.must(tenant, 'runtime-revocation-outbox', row.id)).map(clone);
  }
  acknowledge(tenant, gateId, sequence, now) {
    identifier(gateId); integer(sequence, 'revocation sequence', 1);
    requireThat(this.f.store.get(tenant, 'runtime-revocation-outbox', recordId(sequence)), 'INV-404-NOT-FOUND', 'Revocation sequence not found', 404);
    const record = { gate_id: gateId, sequence, acknowledged_at: now };
    this.f.store.put(tenant, 'runtime-revocation-ack', `${gateId}:${recordId(sequence)}`, record, now);
    return record;
  }
}
