import { randomUUID } from 'node:crypto';
import { clone, digest } from './canonical.mjs';
import { fields, identifier, text, oneOf } from './schema.mjs';
import { requireThat } from './errors.mjs';
const TRANSITIONS = { DETECTED: ['CONTAINED'], CONTAINED: ['RECOVERED'], RECOVERED: ['ROOT_CAUSE'], ROOT_CAUSE: ['CLOSED'], CLOSED: [] };
export class Operations {
  constructor(fabric) { this.f = fabric; }
  acknowledge(p, id) {
    this.f.authorize(p, ['security']); identifier(id);
    return this.f.transaction(p, now => {
      const n = this.f.store.must(p.tenant_id, 'notification', id);
      requireThat(!n.acknowledged, 'INV-409-STATE', 'Notification already acknowledged', 409);
      requireThat(n.owner === 'security' || n.owner === p.subject_id, 'INV-403-SCOPE', 'Only assigned security owner can acknowledge', 403);
      n.acknowledged = true; n.acknowledged_by = p.subject_id; n.acknowledged_at = now;
      this.f.store.put(p.tenant_id, 'notification', id, n, now); this.f.store.audit(p.tenant_id, 'ALERT_ACKNOWLEDGED', p.subject_id, id, { elapsed_ms: now - n.created_at }, now); return n;
    });
  }
  escalate(p) {
    this.f.authorize(p, ['security']);
    return this.f.transaction(p, now => {
      const escalated = [];
      for (const n of this.f.store.list(p.tenant_id, 'notification', 10000)) {
        if (n.acknowledged || n.escalated_at || now - n.created_at < 300000) continue;
        n.escalated_at = now; n.escalation_owner = 'customer-security-lead'; n.acknowledgement_slo_ms = 300000;
        this.f.store.put(p.tenant_id, 'notification', n.reference, n, now);
        this.f.store.audit(p.tenant_id, 'ALERT_ESCALATED', 'slo-monitor', n.reference, { owner: n.escalation_owner, overdue_ms: now - n.created_at - 300000 }, now); escalated.push(n.reference);
      }
      return { escalated, acknowledgement_slo_ms: 300000, delivery: 'LOCAL_DURABLE_QUEUE', external_delivery_configured: false };
    });
  }
  createIncident(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['title', 'severity', 'detected_at', 'evidence_digest']); text(input.title, 'incident title', 256); oneOf(input.severity, ['HIGH', 'CRITICAL'], 'incident severity');
    requireThat(Number.isSafeInteger(input.detected_at) && input.detected_at <= this.f.clock() && input.detected_at > 0 && /^[a-f0-9]{64}$/.test(input.evidence_digest), 'INV-400-SCHEMA', 'Valid detection time and immutable evidence required');
    return this.f.transaction(p, now => {
      const id = randomUUID(), record = { ...clone(input), incident_id: id, tenant_id: p.tenant_id, owner: p.subject_id, state: 'DETECTED', events: [{ state: 'DETECTED', at: now, actor: p.subject_id, evidence_digest: input.evidence_digest }] };
      this.f.store.insert(p.tenant_id, 'incident', id, record, now); this.f.store.insert(p.tenant_id, 'notification', id, { type: 'SECURITY_INCIDENT', owner: p.subject_id, reference: id, created_at: now, acknowledged: false }, now);
      this.f.store.audit(p.tenant_id, 'INCIDENT_DETECTED', p.subject_id, id, { severity: input.severity, evidence_digest: input.evidence_digest }, now); return record;
    });
  }
  transition(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['incident_id', 'expected_state', 'state', 'evidence_digest', 'summary'], ['corrective_action']); identifier(input.incident_id); text(input.summary, 'transition summary', 2048);
    requireThat(/^[a-f0-9]{64}$/.test(input.evidence_digest), 'INV-400-SCHEMA', 'Immutable transition evidence required');
    return this.f.transaction(p, now => {
      const r = this.f.store.must(p.tenant_id, 'incident', input.incident_id);
      requireThat(r.owner === p.subject_id, 'INV-403-SCOPE', 'Incident transition requires assigned owner', 403);
      requireThat(r.state === input.expected_state && TRANSITIONS[r.state].includes(input.state), 'INV-409-STATE', 'Incident states cannot be skipped, replayed or regressed', 409);
      if (input.state === 'CLOSED') {
        fields(input.corrective_action, ['owner', 'action', 'evidence_digest', 'implemented_at']);
        text(input.corrective_action.owner, 'corrective-action owner', 128); text(input.corrective_action.action, 'corrective action', 2048);
        requireThat(/^[a-f0-9]{64}$/.test(input.corrective_action.evidence_digest) && Number.isSafeInteger(input.corrective_action.implemented_at) && input.corrective_action.implemented_at <= now && input.corrective_action.implemented_at >= r.detected_at, 'INV-412-EVIDENCE', 'Completed corrective-action evidence required before closure', 412);
        r.corrective_action = clone(input.corrective_action);
      }
      r.state = input.state; r.events.push({ state: r.state, at: now, actor: p.subject_id, summary: input.summary, evidence_digest: input.evidence_digest });
      this.f.store.put(p.tenant_id, 'incident', r.incident_id, r, now); this.f.store.audit(p.tenant_id, 'INCIDENT_TRANSITION', p.subject_id, r.incident_id, { state: r.state, event_digest: digest(r.events.at(-1)) }, now); return r;
    });
  }
  monitor() {
    const result = [];
    for (const tenant of Object.keys(this.f.config.tenants)) {
      const owner = Object.values(this.f.identities(tenant)).find(who => who.roles.includes('security') && !who.revoked);
      if (owner) result.push(this.escalate({ tenant_id: tenant, subject_id: owner.subject_id }));
    }
    return result;
  }
  incident(p, id) { this.f.authorize(p, ['security', 'auditor']); return this.f.store.must(p.tenant_id, 'incident', identifier(id)); }
}
