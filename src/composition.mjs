import { randomUUID } from 'node:crypto';
import { clone, digest } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, integer } from './schema.mjs';
import { requireThat } from './errors.mjs';

export function flattenComposition(tree) {
  fields(tree, ['root', 'nodes']); identifier(tree.root);
  requireThat(tree.nodes && Object.keys(tree.nodes).length <= 64, 'INV-400-COMPOSITION', 'Composition is bounded to 64 nodes');
  const visited = new Set(), active = new Set(), leaves = [];
  function walk(id, depth) {
    requireThat(depth <= 8 && !active.has(id) && !visited.has(id), 'INV-400-COMPOSITION', 'Cycles, shared children and excess depth are forbidden');
    identifier(id); const node = tree.nodes[id]; requireThat(node, 'INV-400-COMPOSITION', 'Missing child authority');
    active.add(id); visited.add(id);
    if (node.kind === 'action') { fields(node, ['kind', 'capsule_id']); identifier(node.capsule_id); leaves.push(node.capsule_id); }
    else { fields(node, ['kind', 'children']); requireThat(node.kind === 'all' && Array.isArray(node.children) && node.children.length > 0 && node.children.length <= 16, 'INV-400-COMPOSITION', 'Only explicit all-child sequential composition is permitted'); node.children.forEach(child => walk(child, depth + 1)); }
    active.delete(id);
  }
  walk(tree.root, 0);
  requireThat(visited.size === Object.keys(tree.nodes).length && leaves.length <= 32 && new Set(leaves).size === leaves.length, 'INV-400-COMPOSITION', 'Hidden, duplicated or excessive actions are forbidden');
  return leaves;
}
export class Compositions {
  constructor(fabric) { this.f = fabric; }
  describe(t, tree) {
    return flattenComposition(tree).map(id => {
      const r = this.f.store.must(t, 'capsule', id);
      return { capsule_id: id, capsule_digest: digest(r.capsule), evidence_graph_digest: this.f.graph(t, r).digest, policy_digest: digest(this.f.policy(t)), action: clone(r.capsule) };
    });
  }
  create(p, input, key) {
    this.f.authorize(p, ['operator', 'policy_admin']); fields(input, ['tree', 'expires_at']);
    return this.f.transaction(p, now => this.f.store.idempotent(p.tenant_id, 'composition', key, digest(input), () => {
      const children = this.describe(p.tenant_id, input.tree);
      integer(input.expires_at, 'batch expiry', now + 1, Math.min(now + 300000, ...children.map(c => c.action.expires_at)));
      const totals = {}, mutableResources = new Set();
      for (const child of children) {
        this.f.ensureMutable(this.f.store.must(p.tenant_id, 'capsule', child.capsule_id));
        requireThat(child.action.action.type !== 'policy.change', 'INV-403-SCOPE', 'Root policy activation cannot be combined with another action', 403);
        const unit = child.action.requested_state.currency ?? 'units'; totals[unit] = (totals[unit] ?? 0) + child.action.quantity; integer(totals[unit], 'aggregate quantity', 1);
        if (child.action.action.type !== 'data.export') {
          const resource = child.action.action.target_resource;
          requireThat(!mutableResources.has(resource), 'INV-409-BATCH', 'A batch cannot contain dependent mutations of one resource', 409); mutableResources.add(resource);
        }
      }
      const payload = { format: 'IF-COMPOSITION-1', composition_id: randomUUID(), tenant_id: p.tenant_id, tree: clone(input.tree), children, aggregate: totals, semantics: 'all-children-exact-atomic', issued_at: now, expires_at: input.expires_at };
      const envelope = signed(payload, this.f.keys(p.tenant_id).execution, 'composition');
      this.f.store.insert(p.tenant_id, 'composition', payload.composition_id, { envelope, started: false }, now);
      this.f.store.audit(p.tenant_id, 'COMPOSITION_CREATED', p.subject_id, payload.composition_id, { composition_digest: digest(envelope), child_count: children.length }, now); return envelope;
    }));
  }
  current(t, id) {
    const r = this.f.store.must(t, 'composition', id), c = verifySigned(r.envelope, this.f.executionPublic(t), 'composition');
    requireThat(c.tenant_id === t && c.expires_at > this.f.clock() && digest(c.children) === digest(this.describe(t, c.tree)), 'INV-409-BATCH', 'Batch expired or a child, evidence or policy changed', 409); return c;
  }
  challenge(p, id) {
    this.f.authorize(p, ['approver', 'custodian']); const c = this.current(p.tenant_id, id);
    return { format: 'IF-BATCH-APPROVAL-1', tenant_id: p.tenant_id, composition_id: id, composition_digest: digest(c), signer_id: Object.entries(this.f.identities(p.tenant_id)).find(([, x]) => x.subject_id === p.subject_id)[0], children: c.children.map(x => this.f.approvalChallenge(p, x.capsule_id)), aggregate: c.aggregate, approved_at: this.f.clock(), expires_at: c.expires_at };
  }
  approve(p, envelope) {
    this.f.authorize(p, ['approver', 'custodian']);
    return this.f.transaction(p, now => {
      const x = verifySigned(envelope, this.f.identities(p.tenant_id), 'batch-approval');
      fields(x, ['format', 'tenant_id', 'composition_id', 'composition_digest', 'signer_id', 'children', 'aggregate', 'approved_at', 'expires_at']);
      const c = this.current(p.tenant_id, x.composition_id), who = this.f.identities(p.tenant_id)[envelope.protected.key_id];
      requireThat(x.format === 'IF-BATCH-APPROVAL-1' && x.tenant_id === p.tenant_id && x.signer_id === envelope.protected.key_id && who.subject_id === p.subject_id && x.composition_digest === digest(c) && digest(x.aggregate) === digest(c.aggregate), 'INV-403-SCOPE', 'Batch approval binding failed', 403);
      integer(x.approved_at, 'batch approval time', now - 300000, now); integer(x.expires_at, 'batch approval expiry', now + 1, c.expires_at);
      requireThat(Array.isArray(x.children) && x.children.length === c.children.length, 'INV-409-BATCH', 'Every child must be visible and signed', 409);
      for (let i = 0; i < c.children.length; i++) {
        const child = x.children[i], expected = c.children[i], record = this.f.store.must(p.tenant_id, 'capsule', expected.capsule_id);
        fields(child, ['tenant_id', 'capsule_id', 'capsule_digest', 'evidence_graph_digest', 'policy_digest', 'signer_id', 'approved_at', 'expires_at']); this.f.ensureMutable(record);
        requireThat(child.tenant_id === p.tenant_id && child.signer_id === x.signer_id && child.capsule_id === expected.capsule_id && child.capsule_digest === expected.capsule_digest && child.evidence_graph_digest === expected.evidence_graph_digest && child.policy_digest === expected.policy_digest && record.capsule.actor.subject_id !== p.subject_id && !record.approvals.some(a => a.payload.signer_id === x.signer_id), 'INV-409-BATCH', 'Batch child or separation binding failed', 409);
        integer(child.approved_at, 'child approval time', now - 300000, now); integer(child.expires_at, 'child expiry', now + 1, record.capsule.expires_at);
        record.approvals.push({ payload: { ...clone(child), expires_at: Math.min(child.expires_at, x.expires_at) }, batch_envelope: clone(envelope) });
        this.f.store.put(p.tenant_id, 'capsule', child.capsule_id, record, now);
      }
      this.f.store.audit(p.tenant_id, 'EXACT_BATCH_APPROVED', p.subject_id, c.composition_id, { approval_digest: digest(envelope), child_count: c.children.length }, now);
      return { accepted: true, actions: c.children.length };
    });
  }
  resolve(t, approval) {
    const x = verifySigned(approval.batch_envelope, this.f.identities(t), 'batch-approval'), c = this.current(t, x.composition_id);
    requireThat(x.composition_digest === digest(c) && x.expires_at > this.f.clock(), 'INV-409-BATCH', 'Batch no longer current', 409);
    const child = x.children.find(a => a.capsule_id === approval.payload.capsule_id);
    requireThat(child && digest({ ...child, expires_at: Math.min(child.expires_at, x.expires_at) }) === digest(approval.payload), 'INV-409-BATCH', 'Batch child signature mismatch', 409); return approval.payload;
  }
  execute(p, input) {
    this.f.authorize(p, ['operator', 'policy_admin']); fields(input, ['composition_id', 'certificates']);
    const c = this.current(p.tenant_id, input.composition_id);
    requireThat(Array.isArray(input.certificates) && input.certificates.length === c.children.length, 'INV-412-EVIDENCE', 'Missing child certificate', 412);
    for (let i = 0; i < c.children.length; i++) {
      const cert = verifySigned(input.certificates[i], this.f.executionPublic(p.tenant_id), 'action-certificate');
      requireThat(cert.capsule_id === c.children[i].capsule_id && cert.capsule_digest === c.children[i].capsule_digest && c.children[i].action.action.type !== 'policy.change', 'INV-403-SCOPE', 'Composed authority cannot exceed children', 403);
    }
    const reservation = this.f.reserveBatch(p, input.certificates, c.composition_id), outcomes = [];
    let status = 'VERIFIED', reason = 'ATOMIC_BATCH_RECONCILED';
    try {
      const raw = this.f.target.executeBatch(reservation.reservations.map(({ capsule, cert }) => ({ capsule, transaction_id: cert.certificate_id })), reservation.now);
      for (let i = 0; i < reservation.reservations.length; i++) outcomes.push(this.f.finish(p, reservation.reservations[i].cert, raw[i], 'VERIFIED', 'ATOMIC_BATCH_RECONCILED'));
      if (outcomes.some(out => out.payload.status !== 'VERIFIED')) { status = 'UNCERTAIN'; reason = 'TARGET_BATCH_RESPONSE_INVALID'; }
    } catch (error) {
      status = 'UNCERTAIN'; reason = error.code ?? 'TARGET_BATCH_UNCONFIRMED';
      for (const { cert } of reservation.reservations) outcomes.push(this.f.finish(p, cert, null, 'UNCERTAIN', error.code ?? 'TARGET_BATCH_UNCONFIRMED'));
    }
    return this.recordOutcome(p, c.composition_id, reservation.reservations.map(({ cert }) => cert.certificate_id), outcomes, status, reason);
  }
  recordOutcome(p, compositionId, certificateIds, outcomes, status, reason) {
    return this.f.transaction(p, now => {
      const composition = this.f.store.must(p.tenant_id, 'composition', compositionId);
      requireThat(composition.started && digest(composition.certificate_ids) === digest(certificateIds), 'INV-409-BATCH', 'Composition reservation is unavailable', 409);
      const payload = { format: 'IF-COMPOSITION-OUTCOME-1', composition_id: compositionId, tenant_id: p.tenant_id, certificate_ids: certificateIds, status, reason, atomic: true, outcome_digests: outcomes.map(digest), recorded_at: now };
      const envelope = signed(payload, this.f.keys(p.tenant_id).audit, 'composition-outcome');
      composition.status = status; composition.completed_at = now; this.f.store.put(p.tenant_id, 'composition', compositionId, composition, now);
      this.f.store.put(p.tenant_id, 'composition-outcome', compositionId, { envelope }, now); this.f.store.audit(p.tenant_id, 'COMPOSITION_OUTCOME', p.subject_id, compositionId, { status, reason, outcome_digest: digest(envelope) }, now); return { ...payload, outcomes: clone(outcomes), envelope };
    });
  }
  reconcile(p, compositionId) {
    this.f.authorize(p, ['operator', 'security', 'policy_admin']); identifier(compositionId, 'composition id');
    const record = this.f.store.must(p.tenant_id, 'composition', compositionId), batch = verifySigned(record.envelope, this.f.executionPublic(p.tenant_id), 'composition');
    requireThat(batch.composition_id === compositionId && record.started && Array.isArray(record.certificate_ids) && record.certificate_ids.length === batch.children.length, 'INV-409-BATCH', 'Composition was not durably reserved', 409);
    const outcomes = record.certificate_ids.map(certificateId => this.f.reconcile(p, certificateId));
    const statuses = outcomes.map(outcome => outcome.payload.status);
    const status = statuses.every(value => value === 'VERIFIED') ? 'VERIFIED' : statuses.every(value => value === 'FAILED') ? 'FAILED' : 'UNCERTAIN';
    const reason = status === 'VERIFIED' ? 'ATOMIC_BATCH_RECONCILED' : status === 'FAILED' ? 'ATOMIC_BATCH_REJECTED' : 'TARGET_BATCH_UNCONFIRMED';
    return this.recordOutcome(p, compositionId, record.certificate_ids, outcomes, status, reason);
  }
}
