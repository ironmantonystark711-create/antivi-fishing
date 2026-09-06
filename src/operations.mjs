import { clone, digest } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, integer, oneOf, text } from './schema.mjs';
import { requireThat } from './errors.mjs';

const HIGH_SEVERITY = ['high', 'critical'];
const INCIDENT_STEPS = { DETECTED: 'CONTAINED', CONTAINED: 'RECOVERED', RECOVERED: 'ROOT_CAUSE', ROOT_CAUSE: 'CORRECTIVE_ACTION', CORRECTIVE_ACTION: 'CLOSED' };
const DEPLOYMENT_STAGES = ['staging', 'canary', 'production'];

function digestValue(value, name) { requireThat(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value), 'INV-400-SCHEMA', `Invalid ${name}`); }
function attestationTime(value, name, now) { integer(value, name, now - 86400000, now); }
function attestationExpiry(value, name, now) { integer(value, name, now + 1, now + 604800000); }
function trustedIssuer(fabric, tenant, envelope, purpose, requiredKind) {
  const payload = verifySigned(envelope, fabric.tenant(tenant).issuers, purpose), issuer = fabric.tenant(tenant).issuers[envelope.protected.key_id];
  requireThat(!fabric.revoked(tenant, 'issuer', envelope.protected.key_id) && !fabric.revoked(tenant, 'key', envelope.protected.key_id) && issuer.kinds.includes(requiredKind), 'INV-403-SCOPE', `Signer is not authorised for ${requiredKind}`, 403); return payload;
}
export function verifyReleaseEvidence(fabric, tenant, evidence, expected, now) {
  fields(evidence, ['build', 'review', 'observation']);
  const build = trustedIssuer(fabric, tenant, evidence.build, 'release-build', 'build_provenance');
  fields(build, ['format', 'tenant_id', 'source_commit', 'artifact_digest', 'tests_digest', 'runner_id', 'built_at', 'expires_at']);
  const review = verifySigned(evidence.review, fabric.identities(tenant), 'release-review'), reviewer = fabric.identities(tenant)[evidence.review.protected.key_id];
  fields(review, ['format', 'tenant_id', 'release_id', 'source_commit', 'artifact_digest', 'tests_digest', 'policy_digest', 'execution_key_id', 'stage', 'environment', 'reviewed_at', 'expires_at']);
  const observation = trustedIssuer(fabric, tenant, evidence.observation, 'release-observation', 'test_result');
  fields(observation, ['format', 'tenant_id', 'release_id', 'source_commit', 'artifact_digest', 'policy_digest', 'execution_key_id', 'stage', 'environment', 'observed_at', 'expires_at', 'status']);
  for (const value of [build.artifact_digest, build.tests_digest, review.artifact_digest, review.tests_digest, review.policy_digest, observation.artifact_digest, observation.policy_digest]) digestValue(value, 'release digest');
  for (const value of [build.source_commit, review.source_commit, observation.source_commit]) requireThat(/^[a-f0-9]{40,64}$/.test(value), 'INV-400-SCHEMA', 'Release source commit must be immutable');
  for (const [value, name] of [[build.built_at, 'build time'], [review.reviewed_at, 'review time'], [observation.observed_at, 'observation time']]) attestationTime(value, name, now);
  for (const [value, name] of [[build.expires_at, 'build expiry'], [review.expires_at, 'review expiry'], [observation.expires_at, 'observation expiry']]) attestationExpiry(value, name, now);
  requireThat(build.format === 'IF-BUILD-ATTESTATION-1' && build.tenant_id === tenant && review.format === 'IF-RELEASE-REVIEW-1' && review.tenant_id === tenant && reviewer?.roles.includes('custodian') && observation.format === 'IF-RELEASE-OBSERVATION-1' && observation.tenant_id === tenant && observation.status === 'HEALTHY', 'INV-412-EVIDENCE', 'Release evidence requires trusted build, customer review, and healthy observation', 412);
  requireThat(evidence.build.protected.key_id !== evidence.observation.protected.key_id && build.source_commit === expected.source_commit && review.source_commit === expected.source_commit && observation.source_commit === expected.source_commit && build.artifact_digest === expected.artifact_digest && review.artifact_digest === expected.artifact_digest && observation.artifact_digest === expected.artifact_digest && review.tests_digest === build.tests_digest && review.release_id === expected.release_id && observation.release_id === expected.release_id && review.policy_digest === expected.policy_digest && observation.policy_digest === expected.policy_digest && review.execution_key_id === expected.execution_key_id && observation.execution_key_id === expected.execution_key_id && review.stage === expected.stage && observation.stage === expected.stage && review.environment === expected.environment && observation.environment === expected.environment, 'INV-412-EVIDENCE', 'Release evidence is not bound to this exact build, review, and observed environment', 412);
  return { evidence_digest: digest(evidence), build_digest: digest(evidence.build), review_digest: digest(evidence.review), observation_digest: digest(evidence.observation), tests_digest: build.tests_digest, reviewer_subject_id: reviewer.subject_id };
}

export class Operations {
  constructor(fabric) { this.f = fabric; }
  alert(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['alert_id', 'severity', 'owner', 'acknowledgement_slo_ms', 'escalation_slo_ms', 'summary_digest']);
    identifier(input.alert_id, 'alert id'); oneOf(input.severity, ['low', 'medium', ...HIGH_SEVERITY], 'alert severity'); text(input.owner, 'alert owner', 128); integer(input.acknowledgement_slo_ms, 'acknowledgement SLO', 1000, 604800000); integer(input.escalation_slo_ms, 'escalation SLO', input.acknowledgement_slo_ms, 604800000);
    requireThat(/^[a-f0-9]{64}$/.test(input.summary_digest), 'INV-400-SCHEMA', 'Alert summary must be a digest');
    return this.f.transaction(p, now => {
      const owner = this.f.identity({ tenant_id: p.tenant_id, subject_id: input.owner });
      requireThat(owner.roles.includes('security'), 'INV-403-ROLE', 'High-severity alert owner must be security operations', 403);
      const record = { ...clone(input), tenant_id: p.tenant_id, status: 'OPEN', detected_at: now, acknowledged_at: null, escalated_at: null };
      this.f.store.insert(p.tenant_id, 'alert', record.alert_id, record, now); this.f.store.audit(p.tenant_id, 'ALERT_DETECTED', p.subject_id, record.alert_id, { severity: record.severity, owner: record.owner, acknowledgement_slo_ms: record.acknowledgement_slo_ms, escalation_slo_ms: record.escalation_slo_ms }, now); return record;
    });
  }
  acknowledge(p, alertId) {
    this.f.authorize(p, ['security']); identifier(alertId, 'alert id');
    return this.f.transaction(p, now => {
      const alert = this.f.store.must(p.tenant_id, 'alert', alertId);
      requireThat(alert.owner === p.subject_id && ['OPEN', 'ACKNOWLEDGEMENT_OVERDUE', 'ESCALATED'].includes(alert.status), 'INV-403-ROLE', 'Only the assigned owner may acknowledge this alert', 403);
      alert.status = 'ACKNOWLEDGED'; alert.acknowledged_at = now; this.f.store.put(p.tenant_id, 'alert', alertId, alert, now); this.f.store.audit(p.tenant_id, 'ALERT_ACKNOWLEDGED', p.subject_id, alertId, { within_slo: now <= alert.detected_at + alert.acknowledgement_slo_ms }, now); return alert;
    });
  }
  sweepAlerts(p) {
    this.f.authorize(p, ['security']);
    return this.f.transaction(p, now => {
      let overdue = 0, escalated = 0;
      for (const alert of this.f.store.list(p.tenant_id, 'alert', 10000)) if (HIGH_SEVERITY.includes(alert.severity) && alert.status === 'OPEN' && alert.detected_at + alert.acknowledgement_slo_ms <= now && alert.detected_at + alert.escalation_slo_ms > now) {
        alert.status = 'ACKNOWLEDGEMENT_OVERDUE'; this.f.store.put(p.tenant_id, 'alert', alert.alert_id, alert, now); this.f.store.audit(p.tenant_id, 'ALERT_ACKNOWLEDGEMENT_OVERDUE', 'alert-monitor', alert.alert_id, { owner: alert.owner, acknowledgement_slo_ms: alert.acknowledgement_slo_ms }, now); overdue++;
      }
      for (const alert of this.f.store.list(p.tenant_id, 'alert', 10000)) if (HIGH_SEVERITY.includes(alert.severity) && ['OPEN', 'ACKNOWLEDGEMENT_OVERDUE'].includes(alert.status) && alert.detected_at + alert.escalation_slo_ms <= now) {
        alert.status = 'ESCALATED'; alert.escalated_at = now; this.f.store.put(p.tenant_id, 'alert', alert.alert_id, alert, now); this.f.store.insert(p.tenant_id, 'notification', `alert-escalated:${alert.alert_id}`, { type: 'ALERT_ESCALATED', owner: alert.owner, reference: alert.alert_id, created_at: now, acknowledged: false }, now); this.f.store.audit(p.tenant_id, 'ALERT_ESCALATED', 'alert-monitor', alert.alert_id, { owner: alert.owner, acknowledgement_slo_breached: now > alert.detected_at + alert.acknowledgement_slo_ms }, now); escalated++;
      }
      return { overdue, escalated };
    });
  }
  incident(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['incident_id', 'alert_id', 'customer_visible', 'summary_digest']); identifier(input.incident_id, 'incident id'); identifier(input.alert_id, 'alert id'); requireThat(typeof input.customer_visible === 'boolean' && /^[a-f0-9]{64}$/.test(input.summary_digest), 'INV-400-SCHEMA', 'Invalid incident');
    return this.f.transaction(p, now => {
      const alert = this.f.store.must(p.tenant_id, 'alert', input.alert_id); requireThat(HIGH_SEVERITY.includes(alert.severity), 'INV-409-STATE', 'Only high-severity alerts create tracked incidents', 409);
      const record = { ...clone(input), tenant_id: p.tenant_id, status: 'DETECTED', detected_at: now, contained_at: null, recovered_at: null, root_cause_at: null, corrective_action_at: null, closed_at: null };
      this.f.store.insert(p.tenant_id, 'incident', record.incident_id, record, now); this.f.store.insert(p.tenant_id, 'incident-event', `${record.incident_id}:DETECTED`, { incident_id: record.incident_id, status: 'DETECTED', actor: p.subject_id, evidence_digest: record.summary_digest, at: now }, now); this.f.store.audit(p.tenant_id, 'INCIDENT_DETECTED', p.subject_id, record.incident_id, { alert_id: record.alert_id, customer_visible: record.customer_visible }, now);
      if (record.customer_visible) this.f.store.insert(p.tenant_id, 'notification', `incident-detected:${record.incident_id}`, { type: 'INCIDENT_CUSTOMER_NOTICE', owner: 'security', reference: record.incident_id, created_at: now, acknowledged: false }, now);
      return record;
    });
  }
  transitionIncident(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['incident_id', 'status', 'evidence_digest']); identifier(input.incident_id, 'incident id'); oneOf(input.status, Object.values(INCIDENT_STEPS), 'incident status'); requireThat(/^[a-f0-9]{64}$/.test(input.evidence_digest), 'INV-400-SCHEMA', 'Incident transition requires evidence digest');
    return this.f.transaction(p, now => {
      const incident = this.f.store.must(p.tenant_id, 'incident', input.incident_id); requireThat(INCIDENT_STEPS[incident.status] === input.status, 'INV-409-STATE', 'Incident transition is out of order', 409);
      incident.status = input.status; incident[`${input.status.toLowerCase()}_at`] = now; this.f.store.put(p.tenant_id, 'incident', incident.incident_id, incident, now); this.f.store.insert(p.tenant_id, 'incident-event', `${incident.incident_id}:${input.status}`, { incident_id: incident.incident_id, status: input.status, actor: p.subject_id, evidence_digest: input.evidence_digest, at: now }, now); this.f.store.audit(p.tenant_id, `INCIDENT_${input.status}`, p.subject_id, incident.incident_id, { evidence_digest: input.evidence_digest }, now); return incident;
    });
  }
  stageDeployment(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['deployment_id', 'artifact_digest', 'reviewed_commit', 'stage', 'environment', 'policy_digest', 'execution_key_id', 'evidence']); identifier(input.deployment_id, 'deployment id'); oneOf(input.stage, DEPLOYMENT_STAGES, 'deployment stage'); identifier(input.environment, 'deployment environment'); text(input.execution_key_id, 'execution key id', 128);
    requireThat(/^[a-f0-9]{64}$/.test(input.artifact_digest) && /^[a-f0-9]{40,64}$/.test(input.reviewed_commit) && /^[a-f0-9]{64}$/.test(input.policy_digest), 'INV-400-SCHEMA', 'Deployment integrity identifiers are invalid');
    return this.f.transaction(p, now => {
      requireThat(input.policy_digest === digest(this.f.policy(p.tenant_id)) && input.execution_key_id === this.f.keys(p.tenant_id).execution.key_id, 'INV-409-STATE', 'Deployment integrity no longer matches active policy or key', 409);
      requireThat(!this.f.revoked(p.tenant_id, 'artifact', input.artifact_digest) && !this.f.revoked(p.tenant_id, 'deployment', input.deployment_id), 'INV-403-QUARANTINE', 'Deployment artifact or release is revoked', 403);
      const verified = verifyReleaseEvidence(this.f, p.tenant_id, input.evidence, { release_id: input.deployment_id, source_commit: input.reviewed_commit, artifact_digest: input.artifact_digest, policy_digest: input.policy_digest, execution_key_id: input.execution_key_id, stage: input.stage, environment: input.environment }, now);
      requireThat(verified.reviewer_subject_id !== p.subject_id, 'INV-403-SCOPE', 'Deployment author cannot self-review a release', 403);
      const previous = DEPLOYMENT_STAGES[DEPLOYMENT_STAGES.indexOf(input.stage) - 1];
      if (previous) { const prior = this.deployment(p.tenant_id, input.deployment_id, previous); requireThat(prior.artifact_digest === input.artifact_digest && prior.reviewed_commit === input.reviewed_commit && prior.policy_digest === input.policy_digest && prior.execution_key_id === input.execution_key_id && prior.build_digest === verified.build_digest && prior.tests_digest === verified.tests_digest, 'INV-409-STATE', 'Deployment stage integrity differs from the reviewed predecessor', 409); }
      const payload = { ...clone(input), ...verified, tenant_id: p.tenant_id, staged_at: now, staged_by: p.subject_id };
      const envelope = signed(payload, this.f.keys(p.tenant_id).audit, 'deployment-attestation'); this.f.store.insert(p.tenant_id, 'deployment', `${input.deployment_id}:${input.stage}`, { envelope }, now);
      this.f.store.put(p.tenant_id, 'release-evidence', verified.evidence_digest, { binding: { release_id: input.deployment_id, source_commit: input.reviewed_commit, artifact_digest: input.artifact_digest, policy_digest: input.policy_digest, execution_key_id: input.execution_key_id, stage: input.stage, environment: input.environment }, evidence: clone(input.evidence), verified_at: now }, now);
      if (input.stage === 'production') this.f.store.put(p.tenant_id, 'deployment-active', 'current', { deployment_id: input.deployment_id, artifact_digest: input.artifact_digest, reviewed_commit: input.reviewed_commit, policy_digest: input.policy_digest, execution_key_id: input.execution_key_id, activated_at: now }, now);
      this.f.store.audit(p.tenant_id, 'DEPLOYMENT_STAGED', p.subject_id, input.deployment_id, { stage: input.stage, artifact_digest: input.artifact_digest, reviewed_commit: input.reviewed_commit, evidence_digest: verified.evidence_digest }, now); return envelope;
    });
  }
  deployment(tenant, deploymentId, stage) { const stored = this.f.store.must(tenant, 'deployment', `${deploymentId}:${stage}`); return verifySigned(stored.envelope, this.f.keyLifecycle.publicMaterial(tenant, 'audit'), 'deployment-attestation'); }
  rollbackDeployment(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['target_deployment_id', 'reason_digest', 'approvals']); identifier(input.target_deployment_id, 'target deployment id'); requireThat(/^[a-f0-9]{64}$/.test(input.reason_digest), 'INV-400-SCHEMA', 'Rollback reason must be a digest');
    return this.f.transaction(p, now => {
      const active = this.f.store.must(p.tenant_id, 'deployment-active', 'current'), target = this.deployment(p.tenant_id, input.target_deployment_id, 'production');
      const storedEvidence = this.f.store.get(p.tenant_id, 'release-evidence', target.evidence_digest);
      requireThat(active.deployment_id !== target.deployment_id && target.policy_digest === digest(this.f.policy(p.tenant_id)) && target.execution_key_id === this.f.keys(p.tenant_id).execution.key_id && storedEvidence && !this.f.revoked(p.tenant_id, 'artifact', target.artifact_digest) && !this.f.revoked(p.tenant_id, 'deployment', target.deployment_id), 'INV-409-STATE', 'Rollback target is unverified, revoked, or weakens active integrity', 409);
      verifyReleaseEvidence(this.f, p.tenant_id, storedEvidence.evidence, storedEvidence.binding, now);
      requireThat(Array.isArray(input.approvals) && input.approvals.length >= 3 && input.approvals.length <= 5, 'INV-400-SCHEMA', 'Rollback needs a bounded customer quorum');
      const signers = new Set(), domains = new Set();
      for (const envelope of input.approvals) { const approval = verifySigned(envelope, this.f.identities(p.tenant_id), 'deployment-rollback'), who = this.f.identities(p.tenant_id)[envelope.protected.key_id]; fields(approval, ['format', 'tenant_id', 'target_deployment_id', 'active_deployment_id', 'artifact_digest', 'policy_digest', 'execution_key_id', 'reason_digest', 'expires_at']); requireThat(approval.format === 'IF-DEPLOYMENT-ROLLBACK-1' && approval.tenant_id === p.tenant_id && approval.target_deployment_id === target.deployment_id && approval.active_deployment_id === active.deployment_id && approval.artifact_digest === target.artifact_digest && approval.policy_digest === target.policy_digest && approval.execution_key_id === target.execution_key_id && approval.reason_digest === input.reason_digest && approval.expires_at > now && who.roles.includes('custodian'), 'INV-403-SCOPE', 'Rollback approval is not exact customer authority', 403); signers.add(envelope.protected.key_id); domains.add(who.failure_domain); }
      requireThat(signers.size >= 3 && domains.size >= 3, 'INV-403-QUORUM', 'Rollback needs three independent customer custodians', 403);
      const rollback = { deployment_id: target.deployment_id, artifact_digest: target.artifact_digest, reviewed_commit: target.reviewed_commit, policy_digest: target.policy_digest, execution_key_id: target.execution_key_id, activated_at: now, rollback_of: active.deployment_id, reason_digest: input.reason_digest };
      this.f.store.put(p.tenant_id, 'deployment-active', 'current', rollback, now); this.f.store.insert(p.tenant_id, 'deployment-rollback', `${active.deployment_id}:${target.deployment_id}`, rollback, now); this.f.store.audit(p.tenant_id, 'DEPLOYMENT_ROLLED_BACK', p.subject_id, target.deployment_id, { rollback_of: active.deployment_id, reason_digest: input.reason_digest }, now); return rollback;
    });
  }
}
