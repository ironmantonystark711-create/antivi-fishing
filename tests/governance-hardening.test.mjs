import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
import { clone, digest } from '../src/canonical.mjs';

const tree = ids => ({ root: 'root', nodes: { root: { kind: 'all', children: ids.map((_, index) => `child-${index}`) }, ...Object.fromEntries(ids.map((id, index) => [`child-${index}`, { kind: 'action', capsule_id: id }])) } });
const attachAuthority = (h, record) => { h.evidence(record); h.evidence(record, { issuer: 'registry' }); };
function approveBatch(h, composition, records) {
  for (let index = 1; index <= 2; index++) {
    const principal = h.p(`custodian-${index}`), challenge = h.f.compositions.challenge(principal, composition.payload.composition_id);
    h.f.compositions.approve(principal, signed(challenge, h.setup.custodianKeys.acme[principal.subject_id], 'batch-approval'));
  }
  return records.map(record => h.f.certificate(h.p(), record.capsule.capsule_id));
}
function promotePolicy(h, policy, simulation) {
  for (const stage of ['staging', 'canary', 'production']) {
    const challenge = h.f.policyPromotionChallenge(h.p('policy-admin'), { candidate: policy, reviewed_commit: 'a'.repeat(40), stage, simulation_id: simulation.simulation_id, expires_at: h.now() + 300000 });
    const signatures = Object.values(h.setup.custodianKeys.acme).slice(0, 3).map(key => signed(challenge, key, 'policy-promotion'));
    h.f.promotePolicy(h.p('policy-admin'), { challenge, signatures });
  }
}
function activatePolicy(h, policy) {
  const record = h.proposed('policy.change', { policy }, { policy_version: h.f.policy('acme').version, action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Governed policy deployment' } });
  promotePolicy(h, policy, h.f.simulate(h.p('policy-admin'), policy)); h.advance(120001);
  h.evidence(record, { kind: 'governance_review' }); h.evidence(record, { issuer: 'registry', kind: 'governance_review' }); h.approve(record, 3);
  return h.f.execute(h.p(), h.f.certificate(h.p(), record.capsule.capsule_id));
}

test('COM-005 ACT-012: an atomic batch failure leaves no target mutation and records every child as uncertain', t => {
  const h = fixture(t), records = [h.proposed(), h.proposed()]; records.forEach(record => attachAuthority(h, record));
  const composition = h.f.compositions.create(h.p(), { tree: tree(records.map(record => record.capsule.capsule_id)), expires_at: h.now() + 60000 }, crypto.randomUUID());
  const certificates = approveBatch(h, composition, records), original = h.f.target.executeBatch.bind(h.f.target);
  h.f.target.executeBatch = (...args) => original(...args, { kind: 'before-commit', index: 1 });
  const result = h.f.compositions.execute(h.p(), { composition_id: composition.payload.composition_id, certificates });
  assert.equal(result.status, 'INCOMPLETE_RECONCILE_CHILDREN');
  assert.equal(result.atomic, true); assert.equal(result.outcomes.length, 2);
  for (const [index, certificate] of certificates.entries()) {
    assert.equal(result.outcomes[index].payload.status, 'UNCERTAIN');
    assert.equal(h.f.store.must('acme', 'certificate', certificate.payload.certificate_id).status, 'UNCERTAIN');
    assert.equal(h.f.target.state('acme', records[index].capsule.action.target_resource).version, 0);
  }
});

test('ACT-012 POL-009: policy activation cannot be hidden inside a batch', t => {
  const h = fixture(t), next = clone(h.f.policy('acme')); next.version++;
  const policyChange = h.proposed('policy.change', { policy: next }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Attempt batched policy change' } });
  const ordinary = h.proposed(); attachAuthority(h, policyChange); attachAuthority(h, ordinary);
  assert.throws(() => h.f.compositions.create(h.p(), { tree: tree([policyChange.capsule.capsule_id, ordinary.capsule.capsule_id]), expires_at: h.now() + 60000 }, crypto.randomUUID()), hasCode('INV-403-SCOPE'));
});

test('POL-008 POL-010 POL-014: activation respects the staged window and preserves immutable rollback history and revocations', t => {
  const h = fixture(t), baseline = clone(h.f.policy('acme')), future = clone(baseline);
  future.version = 2; future.not_before = h.now() + 180000;
  const futureAction = h.proposed('policy.change', { policy: future }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Stage future policy' } });
  promotePolicy(h, future, h.f.simulate(h.p('policy-admin'), future)); h.advance(120001); h.evidence(futureAction, { kind: 'governance_review' }); h.evidence(futureAction, { issuer: 'registry', kind: 'governance_review' }); h.approve(futureAction, 3);
  assert.throws(() => h.f.certificate(h.p(), futureAction.capsule.capsule_id), hasCode('INV-412-EVIDENCE'));
  h.advance(60000); assert.equal(h.f.execute(h.p(), h.f.certificate(h.p(), futureAction.capsule.capsule_id)).payload.status, 'VERIFIED');
  assert.equal(h.f.policy('acme').version, 2);
  const revokedKeyId = Object.values(h.setup.custodianKeys.acme)[4].key_id;
  h.f.revoke(h.p('security'), { kind: 'key', id: revokedKeyId, reason: 'Compromised after deployment' });
  const rollback = clone(baseline); rollback.version = 3; rollback.not_before = h.now(); rollback.expires_at += 600000;
  assert.equal(activatePolicy(h, rollback).payload.status, 'VERIFIED');
  const history = h.f.store.list('acme', 'policy-history', 10);
  assert.deepEqual(history.map(entry => entry.version).sort(), [1, 2, 3]);
  assert.equal(history.find(entry => entry.version === 3).rollback_of_version, 1);
  assert.equal(h.f.revoked('acme', 'key', revokedKeyId), true);
  assert.ok(h.f.store.auditExport('acme', h.now()).entries.some(entry => entry.envelope.payload.type === 'POLICY_ROLLED_BACK'));
});

test('POL-013: emergency simulation validates at its persisted transaction time and expiry notifies security', t => {
  const h = fixture(t), { record } = h.ready();
  const policy = { format: 'IF-EMERGENCY-1', emergency_id: 'incident-observable', tenant_id: 'acme', actions: [record.capsule.action.type], resources: [record.capsule.action.target_resource], max_quantity: 1, deny: true, issued_at: h.now(), expires_at: h.now() + 1000, reason_digest: digest('controlled incident') };
  const signatures = Object.values(h.setup.custodianKeys.acme).slice(0, 3).map(key => signed(policy, key, 'emergency-policy'));
  h.f.emergencies.simulate(h.p('policy-admin'), policy); h.f.emergencies.activate(h.p('policy-admin'), { policy, signatures });
  h.advance(1001); assert.deepEqual(h.f.emergencies.sweep(h.p('security')), { expired: 1 });
  assert.ok(h.f.store.list('acme', 'notification').some(note => note.type === 'EMERGENCY_EXPIRED' && note.reference === policy.emergency_id));
});

test('POL-008: policy promotion rejects skipped stages, foreign signers, stale reports and tampered reviewed commits', t => {
  const h = fixture(t), candidate = clone(h.f.policy('acme')), simulation = h.f.simulate(h.p('policy-admin'), { ...candidate, version: 2 });
  candidate.version = 2;
  const input = { candidate, reviewed_commit: 'b'.repeat(40), stage: 'production', simulation_id: simulation.simulation_id, expires_at: h.now() + 300000 };
  const production = h.f.policyPromotionChallenge(h.p('policy-admin'), input), signatures = Object.values(h.setup.custodianKeys.acme).slice(0, 3).map(key => signed(production, key, 'policy-promotion'));
  assert.throws(() => h.f.promotePolicy(h.p('policy-admin'), { challenge: production, signatures }), hasCode('INV-404-NOT-FOUND'));
  const staging = h.f.policyPromotionChallenge(h.p('policy-admin'), { ...input, stage: 'staging' });
  const foreign = signed(staging, Object.values(h.setup.custodianKeys.globex)[0], 'policy-promotion');
  assert.throws(() => h.f.promotePolicy(h.p('policy-admin'), { challenge: staging, signatures: [foreign, ...Object.values(h.setup.custodianKeys.acme).slice(0, 2).map(key => signed(staging, key, 'policy-promotion'))] }), hasCode('INV-401-SIGNATURE'));
  const altered = clone(staging); altered.reviewed_commit = 'c'.repeat(40);
  assert.throws(() => h.f.promotePolicy(h.p('policy-admin'), { challenge: altered, signatures: Object.values(h.setup.custodianKeys.acme).slice(0, 3).map(key => signed(staging, key, 'policy-promotion')) }), hasCode('INV-403-SCOPE'));
  h.advance(300001);
  assert.throws(() => h.f.promotePolicy(h.p('policy-admin'), { challenge: staging, signatures: Object.values(h.setup.custodianKeys.acme).slice(0, 3).map(key => signed(staging, key, 'policy-promotion')) }), hasCode('INV-400-SCHEMA'));
});

test('POL-008: stale simulations and newly revoked promotion custodians invalidate production promotion', t => {
  const h = fixture(t), candidate = clone(h.f.policy('acme')); candidate.version = 2;
  const simulation = h.f.simulate(h.p('policy-admin'), candidate);
  h.advance(86400001);
  assert.throws(() => h.f.policyPromotionChallenge(h.p('policy-admin'), { candidate, reviewed_commit: 'a'.repeat(40), stage: 'staging', simulation_id: simulation.simulation_id, expires_at: h.now() + 300000 }), hasCode('INV-409-STATE'));
  const fresh = h.f.simulate(h.p('policy-admin'), candidate); promotePolicy(h, candidate, fresh);
  const revokedKeyId = Object.values(h.setup.custodianKeys.acme)[0].key_id;
  h.f.revoke(h.p('security'), { kind: 'key', id: revokedKeyId, reason: 'Custodian revoked after promotion' });
  assert.throws(() => h.f.promotions.current('acme', digest(candidate), 'production', h.now()), hasCode('INV-401-SIGNATURE'));
});

test('NFR-OPS-003 NFR-OPS-004: high-severity alerts enforce owner acknowledgement and incidents cannot skip recovery stages', t => {
  const h = fixture(t), alert = h.f.operations.alert(h.p('security'), { alert_id: 'alert-1', severity: 'critical', owner: 'security', acknowledgement_slo_ms: 1000, escalation_slo_ms: 2000, summary_digest: digest('target integrity alarm') });
  assert.equal(alert.status, 'OPEN'); assert.throws(() => h.f.operations.acknowledge(h.p('operator'), alert.alert_id), hasCode('INV-403-ROLE'));
  h.advance(1001); assert.deepEqual(h.f.operations.sweepAlerts(h.p('security')), { overdue: 1, escalated: 0 }); assert.equal(h.f.store.must('acme', 'alert', alert.alert_id).status, 'ACKNOWLEDGEMENT_OVERDUE');
  h.advance(1000); assert.deepEqual(h.f.operations.sweepAlerts(h.p('security')), { overdue: 0, escalated: 1 }); assert.equal(h.f.operations.acknowledge(h.p('security'), alert.alert_id).status, 'ACKNOWLEDGED');
  const incident = h.f.operations.incident(h.p('security'), { incident_id: 'incident-1', alert_id: alert.alert_id, customer_visible: true, summary_digest: digest('customer-impacting integrity event') });
  assert.throws(() => h.f.operations.transitionIncident(h.p('security'), { incident_id: incident.incident_id, status: 'RECOVERED', evidence_digest: digest('skipped containment') }), hasCode('INV-409-STATE'));
  for (const status of ['CONTAINED', 'RECOVERED', 'ROOT_CAUSE', 'CORRECTIVE_ACTION', 'CLOSED']) h.f.operations.transitionIncident(h.p('security'), { incident_id: incident.incident_id, status, evidence_digest: digest(status) });
  assert.equal(h.f.store.must('acme', 'incident', incident.incident_id).status, 'CLOSED');
  assert.equal(h.f.store.list('acme', 'incident-event', 10).length, 6);
  assert.ok(h.f.store.list('acme', 'notification').some(note => note.type === 'ALERT_ESCALATED'));
  assert.ok(h.f.store.list('acme', 'notification').some(note => note.type === 'INCIDENT_CUSTOMER_NOTICE'));
});

test('NFR-OPS-005: deployment must progress staging to canary to production and rollback retains current policy/key integrity', t => {
  const h = fixture(t), integrity = { policy_digest: digest(h.f.policy('acme')), execution_key_id: h.f.keys('acme').execution.key_id };
  const stage = (deployment_id, artifact_digest, reviewed_commit) => {
    for (const step of ['staging', 'canary', 'production']) h.f.operations.stageDeployment(h.p('security'), { deployment_id, artifact_digest, reviewed_commit, stage: step, ...integrity });
  };
  const a = digest('artifact-a'), b = digest('artifact-b');
  assert.throws(() => h.f.operations.stageDeployment(h.p('security'), { deployment_id: 'release-a', artifact_digest: a, reviewed_commit: 'a'.repeat(40), stage: 'production', ...integrity }), hasCode('INV-404-NOT-FOUND'));
  assert.throws(() => h.f.operations.stageDeployment(h.p('security'), { deployment_id: 'release-a', artifact_digest: a, reviewed_commit: 'a'.repeat(40), stage: 'staging', policy_digest: digest('wrong-policy'), execution_key_id: integrity.execution_key_id }), hasCode('INV-409-STATE'));
  stage('release-a', a, 'a'.repeat(40)); stage('release-b', b, 'b'.repeat(40));
  assert.equal(h.f.operations.rollbackDeployment(h.p('security'), { target_deployment_id: 'release-a', reason_digest: digest('canary regression') }).deployment_id, 'release-a');
  assert.throws(() => h.f.operations.rollbackDeployment(h.p('security'), { target_deployment_id: 'release-a', reason_digest: digest('replay') }), hasCode('INV-409-STATE'));
});
