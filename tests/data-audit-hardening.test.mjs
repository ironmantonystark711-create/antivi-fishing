import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { protectOutput, verifyOutputAttribution } from '../src/output.mjs';
import { verifyAudit } from '../src/store.mjs';
import { proposal } from '../src/schema.mjs';

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

test('DAT-005 POL-004 DAT-011: SHIELD creates a new reduced capsule that needs independent evidence and authority before execution', t => {
  const h = fixture(t), policy = clone(h.f.policy('acme'));
  policy.runtime.watermark = { enabled: true, lawful_basis: 'Customer-approved export attribution', mode: 'visible' }; policy.rules['data.export'].approval_threshold = 1; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const requested = { dataset: 'dataset-1', columns: ['id', 'name', 'passport'], row_ids: ['row-1'], max_rows: 1, classification: 'internal', jurisdiction: 'EU' };
  const input = proposal('data.export', h.actor(), h.f.target.state('acme', 'dataset-1'), requested, h.now(), { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Controlled export' }, destination: 'customer-vault' });
  const record = h.f.propose(h.p(), input, crypto.randomUUID()), originalEvidence = h.evidence(record, { kind: 'dataset_authority' });
  assert.equal(h.f.evaluate(h.p(), record.capsule.capsule_id).decision, 'SHIELD'); h.approve(record, 1);
  assert.throws(() => h.f.certificate(h.p(), record.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
  const shielded = h.f.createShieldedProposal(h.p(), record.capsule.capsule_id);
  assert.notEqual(shielded.capsule.capsule_id, record.capsule.capsule_id); assert.notEqual(shielded.capsule_digest, record.capsule_digest); assert.notEqual(shielded.capsule.nonce, record.capsule.nonce); assert.deepEqual(shielded.capsule.requested_state.columns, ['id', 'name']); assert.equal(shielded.evidence.length, 0); assert.equal(shielded.approvals.length, 0);
  assert.throws(() => h.f.createShieldedProposal(h.p(), record.capsule.capsule_id), hasCode('INV-409-REPLAY'));
  assert.throws(() => h.f.attachEvidence(h.p(), shielded.capsule.capsule_id, originalEvidence), hasCode('INV-403-SCOPE'));
  assert.equal(h.f.evaluate(h.p(), shielded.capsule.capsule_id).decision, 'ESCROW'); h.evidence(shielded, { kind: 'dataset_authority' }); assert.equal(h.f.evaluate(h.p(), shielded.capsule.capsule_id).decision, 'ESCROW'); h.approve(shielded, 1); assert.equal(h.f.evaluate(h.p(), shielded.capsule.capsule_id).decision, 'ALLOW');
  const certificate = h.f.certificate(h.p(), shielded.capsule.capsule_id), outcome = h.f.execute(h.p(), certificate);
  assert.equal(outcome.payload.status, 'VERIFIED'); assert.deepEqual(Object.keys(outcome.payload.output[0]), ['id', 'name']); assert.equal(Object.hasOwn(outcome.payload.output[0], 'passport'), false);
  assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-409-REPLAY')); const changedScope = clone(certificate); changedScope.payload.constraints.requested_digest = digest({ columns: ['id', 'name', 'passport'] }); assert.throws(() => h.f.execute(h.p(), changedScope), hasCode('INV-401-SIGNATURE'));
  assert.equal(h.f.store.must('acme', 'capsule', record.capsule.capsule_id).capsule.requested_state.columns.includes('passport'), true); assert.equal(shielded.shield_parent.capsule_id, record.capsule.capsule_id);
  assert.equal(verifyOutputAttribution(outcome.payload.output, outcome.payload.watermark, policy.runtime.watermark, h.f.store.key('acme')).valid, true);
});

test('DAT-012: local evidence erasure removes the prior ciphertext from live database and WAL storage', t => {
  const h = fixture(t);
  h.f.retentionInstruction(h.p('security'), { action_type: 'finance.beneficiary.create', legal_basis: 'Customer erasure instruction', customer_instruction_digest: digest('erase evidence'), evidence_retention_ms: 1, audit_retention_ms: 1000 });
  const r = h.proposed(), evidence = h.evidence(r), row = h.f.store.statement('SELECT value FROM records WHERE tenant=? AND kind=? AND id=?').get('acme', 'evidence', evidence.payload.evidence_id);
  h.f.cancel(h.p(), r.capsule.capsule_id); h.advance(2);
  const result = h.f.retentionSweep(h.p('security')); assert.equal(result.deleted, 1); assert.equal(result.complete_payload_erasure, true); assert.equal(result.erasure_method, 'SQLITE_SECURE_DELETE_WAL_CHECKPOINT_VACUUM');
  for (const file of ['fabric.db', 'fabric.db-wal']) if (existsSync(join(h.directory, file))) assert.equal(readFileSync(join(h.directory, file)).includes(Buffer.from(row.value)), false);
});
