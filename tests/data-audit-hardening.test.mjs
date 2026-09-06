import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { protectOutput, verifyOutputAttribution } from '../src/output.mjs';
import { verifyAudit } from '../src/store.mjs';

test('EVD-003 EVD-006 EVD-010 EVD-011: signed evidence requires purpose-limited provenance and safe AI classification', t => {
  const h = fixture(t), r = h.proposed(), base = h.evidence(r);
  for (const mutation of [
    p => delete p.verification_method,
    p => delete p.acquisition_purpose,
    p => p.provenance = 'unstructured provenance',
    p => { p.provenance.source_type = 'ai_extraction'; p.advisory = false; }
  ]) {
    const payload = clone(base.payload); payload.evidence_id = crypto.randomUUID(); mutation(payload);
    assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed(payload, h.setup.issuerKeys.acme.bank, 'evidence')), e => ['INV-400-SCHEMA', 'INV-403-SCOPE'].includes(e?.code));
  }
  const direct = h.f.store.must('acme', 'evidence', base.payload.evidence_id);
  assert.equal(direct.payload.provenance.source_type, 'direct');
  assert.equal(direct.payload.provenance.transformations.length, 0);
});

test('EVD-007 EVD-008 EVD-009: stale, revoked, and conflicting evidence produce distinct fail-closed reasons', t => {
  const h = fixture(t), stale = h.proposed(); h.evidence(stale, { expiry: h.now() + 1 }); h.evidence(stale, { issuer: 'registry', expiry: h.now() + 600000 }); h.advance(2);
  assert.ok(h.f.evaluate(h.p(), stale.capsule.capsule_id).reasons.some(x => x.code === 'EVIDENCE_EXPIRED'));
  const revoked = h.proposed(), evidence = h.evidence(revoked); h.evidence(revoked, { issuer: 'registry' }); h.f.revoke(h.p('security'), { kind: 'evidence', id: evidence.payload.evidence_id, reason: 'Synthetic source revocation' });
  assert.ok(h.f.evaluate(h.p(), revoked.capsule.capsule_id).reasons.some(x => x.code === 'EVIDENCE_REVOKED'));
  const conflict = h.proposed(); h.evidence(conflict); h.evidence(conflict, { issuer: 'registry' }); h.evidence(conflict, { issuer: 'governance', claim: 'conflict' });
  assert.ok(h.f.evaluate(h.p(), conflict.capsule.capsule_id).reasons.some(x => x.code === 'EVIDENCE_CONFLICT'));
});

test('DAT-011: output attribution validates source and policy without mutating protected rows', () => {
  const rows = [{ id: 'row-1', name: 'Synthetic Ada' }], policy = { enabled: true, lawful_basis: 'Controlled security investigation', mode: 'visible' }, key = Buffer.alloc(32, 7);
  const output = protectOutput(rows, { tenant_id: 'acme', subject_id: 'operator', session_id: 'session-1', destination: 'customer-vault' }, policy, key);
  assert.equal(verifyOutputAttribution(output.rows, output.watermark, policy, key).valid, true);
  assert.deepEqual(rows, [{ id: 'row-1', name: 'Synthetic Ada' }]);
  for (const mutation of [w => w.tag = '0'.repeat(64), w => w.metadata.subject_id = 'attacker', w => w.visible_label = 'forged']) {
    const forged = clone(output.watermark); mutation(forged);
    assert.throws(() => verifyOutputAttribution(output.rows, forged, policy, key));
  }
  assert.throws(() => protectOutput(rows, { tenant_id: 'acme', subject_id: 'operator', session_id: '', destination: 'customer-vault' }, policy, key), hasCode('INV-400-SCHEMA'));
});

test('AUD-005 AUD-008 AUD-010: exports need pinned trust and projections exclude unassigned roles', t => {
  const h = fixture(t); h.proposed(); const bundle = h.f.exportAudit(h.p('auditor'), 'Independent verification');
  assert.equal(verifyAudit(bundle, bundle.public_keys).valid, true);
  const malformed = clone(bundle); malformed.entries[0].unexpected = true;
  assert.throws(() => verifyAudit(malformed, bundle.public_keys), hasCode('INV-400-AUDIT'));
  assert.throws(() => h.f.auditView(h.p(), 'finance', 'Unassigned role attempt'), hasCode('INV-403-ROLE'));
  const projection = h.f.auditView(h.p('finance-reviewer'), 'finance', 'Finance reconciliation');
  assert.equal(projection.payload.purpose_digest, digest('Finance reconciliation'));
  assert.ok(projection.payload.entries.every(entry => !Object.hasOwn(entry, 'actor') && !Object.hasOwn(entry, 'source_digest')));
});

test('DAT-012 AUD-006: customer retention instructions cap evidence retention and preserve legal holds', t => {
  const h = fixture(t);
  h.f.retentionInstruction(h.p('security'), { action_type: 'finance.beneficiary.create', legal_basis: 'Customer retention instruction', customer_instruction_digest: digest('synthetic customer instruction'), evidence_retention_ms: 10, audit_retention_ms: 1000 });
  const r = h.proposed(), evidence = h.evidence(r), stored = h.f.store.must('acme', 'evidence', evidence.payload.evidence_id);
  assert.equal(stored.retention_until, h.now() + 10);
  h.f.retention(h.p('security'), { evidence_id: evidence.payload.evidence_id, legal_hold: true }); h.advance(11);
  assert.equal(h.f.retentionSweep(h.p('security')).held, 1);
  h.f.retention(h.p('security'), { evidence_id: evidence.payload.evidence_id, legal_hold: false }); h.f.cancel(h.p(), r.capsule.capsule_id);
  assert.equal(h.f.retentionSweep(h.p('security')).deleted, 1);
  assert.ok(h.f.store.list('acme', 'retention-policy-history').length === 1);
});
