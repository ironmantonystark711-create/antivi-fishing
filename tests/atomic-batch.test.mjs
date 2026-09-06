import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
function batch(h) {
  const children = [h.proposed(), h.proposed()];
  for (const r of children) { h.evidence(r); h.evidence(r, { issuer: 'registry' }); }
  const tree = { root: 'all', nodes: { all: { kind: 'all', children: ['a', 'b'] }, a: { kind: 'action', capsule_id: children[0].capsule.capsule_id }, b: { kind: 'action', capsule_id: children[1].capsule.capsule_id } } };
  const c = h.f.compositions.create(h.p(), { tree, expires_at: h.now() + 60000 }, randomUUID());
  for (const subject of ['custodian-1', 'custodian-2']) h.f.compositions.approve(h.p(subject), signed(h.f.compositions.challenge(h.p(subject), c.payload.composition_id), h.setup.custodianKeys.acme[subject], 'batch-approval'));
  return { children, input: { composition_id: c.payload.composition_id, certificates: children.map(r => h.f.certificate(h.p(), r.capsule.capsule_id)) } };
}
test('ACT-012 COM-005 UX-006: atomic batch commits every exact child and rejects replay, missing or reversed authority', t => {
  const h = fixture(t), b = batch(h);
  assert.throws(() => h.f.compositions.execute(h.p(), { ...b.input, certificates: b.input.certificates.slice(0, 1) }), hasCode('INV-412-EVIDENCE'));
  assert.throws(() => h.f.compositions.execute(h.p(), { ...b.input, certificates: [...b.input.certificates].reverse() }), hasCode('INV-403-SCOPE'));
  const out = h.f.compositions.execute(h.p(), b.input); assert.equal(out.status, 'VERIFIED'); assert.equal(out.atomic, true);
  for (const r of b.children) assert.equal(h.f.target.state('acme', r.capsule.action.target_resource).version, 1);
  assert.throws(() => h.f.compositions.execute(h.p(), b.input), hasCode('INV-409-REPLAY'));
});
for (const fault of ['child-1', 'before-commit', 'after-commit', 'process-crash']) test(`COM-005 COM-012 ACT-012: atomic ${fault} preserves all-or-none state and durable replay protection`, t => {
  const h = fixture(t), b = batch(h);
  if (fault === 'process-crash') assert.throws(() => h.f.compositions.execute(h.p(), b.input, { fault }), /Simulated process death/);
  else assert.equal(h.f.compositions.execute(h.p(), b.input, { fault }).status, 'INCOMPLETE_RECONCILE_CHILDREN');
  const expectedVersion = fault === 'after-commit' ? 1 : 0;
  for (const r of b.children) assert.equal(h.f.target.state('acme', r.capsule.action.target_resource).version, expectedVersion);
  h.close(); const recovered = new h.f.constructor(h.setup.config, h.directory, h.now); t.after(() => recovered.close());
  assert.throws(() => recovered.compositions.execute(h.p(), b.input), hasCode('INV-409-REPLAY'));
  const out = recovered.compositions.reconcile(h.p(), b.input.composition_id);
  assert.equal(out.status, fault === 'after-commit' ? 'VERIFIED' : 'INCOMPLETE_RECONCILE_CHILDREN');
  for (const r of b.children) assert.equal(recovered.target.state('acme', r.capsule.action.target_resource).version, expectedVersion);
});
test('COM-005 COM-004 ACT-012: stale last child rolls back all reservations, not just target writes', t => {
  const h = fixture(t), b = batch(h), last = b.children[1];
  h.f.target.seed('acme', last.capsule.action.target_resource, { unexpected: true });
  assert.throws(() => h.f.compositions.execute(h.p(), b.input), hasCode('INV-409-STATE'));
  assert.equal(h.f.target.state('acme', b.children[0].capsule.action.target_resource).version, 0);
  for (const c of b.input.certificates) assert.equal(h.f.store.must('acme', 'certificate', c.payload.certificate_id).consumed, false);
  assert.equal(h.f.store.must('acme', 'composition', b.input.composition_id).started, false);
});
test('COM-005 NFR-SEC-005: another tenant cannot execute or reconcile a batch', t => {
  const h = fixture(t), b = batch(h);
  assert.throws(() => h.f.compositions.execute(h.p('operator', 'globex'), b.input), hasCode('INV-404-NOT-FOUND'));
  h.f.compositions.execute(h.p(), b.input);
  assert.throws(() => h.f.compositions.reconcile(h.p('operator', 'globex'), b.input.composition_id), hasCode('INV-404-NOT-FOUND'));
});
