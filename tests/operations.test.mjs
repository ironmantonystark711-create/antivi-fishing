import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
function incident(h) { return h.f.operations.createIncident(h.p('security'), { title: 'Synthetic scoped incident', severity: 'HIGH', detected_at: h.now(), evidence_digest: digest('observed failure') }); }
test('NFR-OPS-003: five-minute acknowledgement SLO escalates once and enforces owner and tenant boundaries', t => {
 const h = fixture(t), r = incident(h);
 assert.throws(() => h.f.operations.acknowledge(h.p(), r.incident_id), hasCode('INV-403-ROLE')); assert.throws(() => h.f.operations.acknowledge(h.p('security', 'globex'), r.incident_id), hasCode('INV-404-NOT-FOUND'));
 h.advance(299999); assert.equal(h.f.operations.escalate(h.p('security')).escalated.length, 0); h.advance(1);
 assert.deepEqual(h.f.operations.escalate(h.p('security')).escalated, [r.incident_id]); assert.equal(h.f.operations.escalate(h.p('security')).escalated.length, 0);
 assert.equal(h.f.operations.acknowledge(h.p('security'), r.incident_id).acknowledged, true); assert.throws(() => h.f.operations.acknowledge(h.p('security'), r.incident_id), hasCode('INV-409-STATE'));
});
test('NFR-OPS-004: customer-visible incident lifecycle survives restart and cannot skip containment or corrective-action evidence', t => {
 const h = fixture(t), r = incident(h), transition = state => ({ incident_id: r.incident_id, expected_state: h.f.operations.incident(h.p('security'), r.incident_id).state, state, evidence_digest: digest(state), summary: `Synthetic evidence for ${state}`, ...(state === 'CLOSED' ? { corrective_action: { owner: 'security', action: 'Synthetic tested correction', evidence_digest: digest('corrective test'), implemented_at: h.now() } } : {}) });
 assert.throws(() => h.f.operations.transition(h.p('security'), transition('CLOSED')), hasCode('INV-409-STATE'));
 const contained = transition('CONTAINED'); h.f.operations.transition(h.p('security'), contained); assert.throws(() => h.f.operations.transition(h.p('security'), contained), hasCode('INV-409-STATE'));
 for (const state of ['RECOVERED', 'ROOT_CAUSE']) h.f.operations.transition(h.p('security'), transition(state));
 const invalidClose = transition('CLOSED'); delete invalidClose.corrective_action; assert.throws(() => h.f.operations.transition(h.p('security'), invalidClose), hasCode('INV-400-SCHEMA'));
 h.f.operations.transition(h.p('security'), transition('CLOSED'));
 h.close(); const f = new h.f.constructor(h.setup.config, h.directory, h.now); t.after(() => f.close());
 const result = f.operations.incident(h.p('auditor'), r.incident_id); assert.equal(result.state, 'CLOSED'); assert.equal(result.events.length, 5);
 assert.throws(() => f.operations.incident(h.p('auditor', 'globex'), r.incident_id), hasCode('INV-404-NOT-FOUND'));
});
