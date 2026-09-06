import { clone, digest } from './canonical.mjs';
import { verifySigned } from './crypto.mjs';
import { fields, oneOf, integer } from './schema.mjs';
import { validatePolicy } from './policy.mjs';
import { requireThat } from './errors.mjs';
const STAGES = ['DEVELOPMENT', 'SHADOW', 'CANARY'];
export class PolicyLifecycle {
  constructor(fabric) { this.f = fabric; }
  stage(p, input) {
    this.f.authorize(p, ['policy_admin']); fields(input, ['candidate', 'stage', 'evidence']); validatePolicy(input.candidate); oneOf(input.stage, STAGES, 'policy stage');
    return this.f.transaction(p, now => {
      const candidate = input.candidate, active = this.f.policy(p.tenant_id), id = digest(candidate), prior = this.f.store.get(p.tenant_id, 'policy-stage', id);
      requireThat(candidate.tenant_id === p.tenant_id && candidate.version === active.version + 1 && candidate.expires_at > now, 'INV-409-STATE', 'Stage the next current tenant policy only', 409);
      requireThat(STAGES.indexOf(input.stage) === (prior ? STAGES.indexOf(prior.stage) + 1 : 0), 'INV-409-STAGE', 'Policy stages cannot be skipped, repeated or downgraded', 409);
      const e = verifySigned(input.evidence, this.f.tenant(p.tenant_id).issuers, 'policy-stage');
      fields(e, ['tenant_id', 'candidate_digest', 'baseline_digest', 'stage', 'review_commit', 'test_result_digest', 'passed', 'tested_at', 'expires_at']);
      const issuer = this.f.tenant(p.tenant_id).issuers[input.evidence.protected.key_id];
      requireThat(issuer.channel === 'authoritative' && issuer.kinds.includes('governance_review') && !this.f.revoked(p.tenant_id, 'issuer', input.evidence.protected.key_id) && !this.f.revoked(p.tenant_id, 'key', input.evidence.protected.key_id), 'INV-403-SCOPE', 'Non-revoked customer review authority required', 403);
      requireThat(e.tenant_id === p.tenant_id && e.candidate_digest === id && e.baseline_digest === digest(active) && e.stage === input.stage && e.passed === true && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(e.review_commit) && /^[a-f0-9]{64}$/.test(e.test_result_digest), 'INV-412-EVIDENCE', 'Stage evidence must bind exact reviewed candidate, baseline and passing tests', 412);
      integer(e.tested_at, 'stage evidence time', now - 3600000, now); integer(e.expires_at, 'stage evidence expiry', now + 1, e.tested_at + 86400000);
      const simulation = this.f.store.list(p.tenant_id, 'simulation', 10000).find(x => x.candidate_digest === id && x.baseline_digest === e.baseline_digest);
      requireThat(simulation, 'INV-412-EVIDENCE', 'Simulate exact candidate before staging', 412);
      const history = [...(prior?.history ?? []), clone(input.evidence)];
      const out = { candidate: clone(candidate), candidate_digest: id, baseline_digest: e.baseline_digest, stage: input.stage, history, updated_at: now };
      this.f.store.put(p.tenant_id, 'policy-stage', id, out, now); this.f.store.audit(p.tenant_id, 'POLICY_STAGED', p.subject_id, id, { stage: input.stage, evidence_digest: digest(input.evidence), review_commit: e.review_commit }, now); return out;
    });
  }
  ready(t, candidate, now) {
    const r = this.f.store.get(t, 'policy-stage', digest(candidate));
    if (!r || r.stage !== 'CANARY' || r.baseline_digest !== digest(this.f.policy(t)) || r.history.length !== 3) return false;
    return r.history.every((envelope, i) => {
      try {
        const id = envelope.protected.key_id, e = verifySigned(envelope, this.f.tenant(t).issuers, 'policy-stage');
        const issuer = this.f.tenant(t).issuers[id];
        return issuer.channel === 'authoritative' && issuer.kinds.includes('governance_review') && e.tested_at <= now && !this.f.revoked(t, 'issuer', id) && !this.f.revoked(t, 'key', id) && e.expires_at > now && e.passed === true && e.stage === STAGES[i] && e.candidate_digest === digest(candidate) && e.baseline_digest === r.baseline_digest;
      } catch { return false; }
    });
  }
  archive(t, active, next, certificate, now) {
    this.f.store.put(t, 'policy-history', String(active.version), { policy: clone(active), retired_at: now }, now);
    this.f.store.put(t, 'policy-history', String(next.version), { policy: clone(next), activated_at: now, certificate_id: certificate.certificate_id }, now);
    this.f.store.audit(t, 'POLICY_ACTIVATED', 'commit-gate', certificate.certificate_id, { prior_digest: digest(active), policy_digest: digest(next), version: next.version }, now);
  }
  rollbackCandidate(p, version) {
    this.f.authorize(p, ['policy_admin']); integer(version, 'historical policy version', 1);
    const old = this.f.store.must(p.tenant_id, 'policy-history', String(version)).policy, active = this.f.policy(p.tenant_id);
    requireThat(version < active.version, 'INV-409-STATE', 'Rollback must reference a prior policy', 409);
    // This is a proposal, not authority. Re-simulation, staged review, delay and
    // exact customer quorum are required just as for any other policy change.
    const next = { ...clone(old), version: active.version + 1, not_before: this.f.clock() };
    validatePolicy(next); return { candidate: next, activation: false, revocations_preserved: true };
  }
}
