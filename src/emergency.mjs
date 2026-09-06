import { randomUUID } from 'node:crypto';
import { clone, digest } from './canonical.mjs';
import { verifySigned } from './crypto.mjs';
import { fields, identifier, integer, uniqueStrings } from './schema.mjs';
import { requireThat } from './errors.mjs';
import { SCHEMAS } from './schema.mjs';

export class EmergencyPolicies {
  constructor(fabric) { this.f = fabric; }
  validate(t, x, now) {
    fields(x, ['format', 'emergency_id', 'tenant_id', 'actions', 'resources', 'max_quantity', 'deny', 'issued_at', 'expires_at', 'reason_digest']);
    requireThat(x.format === 'IF-EMERGENCY-1' && x.tenant_id === t && typeof x.deny === 'boolean' && /^[a-f0-9]{64}$/.test(x.reason_digest), 'INV-400-SCHEMA', 'Invalid emergency policy'); identifier(x.emergency_id);
    uniqueStrings(x.actions, 'emergency actions', 8); uniqueStrings(x.resources, 'emergency resources', 32);
    requireThat(x.actions.length > 0 && x.resources.length > 0 && x.actions.every(a => Object.hasOwn(SCHEMAS, a) && a !== 'policy.change') && x.resources.every(r => r !== '*' && /^[A-Za-z0-9_.:-]+$/.test(r)), 'INV-451-POLICY', 'Emergency authority must name exact non-root actions and resources', 451);
    integer(x.issued_at, 'emergency issue time', now - 300000, now); integer(x.expires_at, 'emergency expiry', now + 1, x.issued_at + 3600000); integer(x.max_quantity, 'emergency quantity', 1, 1e12); return x;
  }
  simulate(p, x) {
    this.f.authorize(p, ['policy_admin', 'security']); this.validate(p.tenant_id, x, this.f.clock());
    return this.f.transaction(p, now => { const out = { simulation_id: randomUUID(), emergency_digest: digest(x), baseline_digest: digest(this.f.policy(p.tenant_id)), affected: this.f.store.list(p.tenant_id, 'capsule').filter(r => x.actions.includes(r.capsule.action.type) && x.resources.includes(r.capsule.action.target_resource)).map(r => ({ capsule_id: r.capsule.capsule_id, restricted: x.deny || r.capsule.quantity > x.max_quantity })), activation: false }; this.f.store.insert(p.tenant_id, 'emergency-simulation', out.emergency_digest, out, now); return out; });
  }
  activate(p, input) {
    this.f.authorize(p, ['policy_admin']); fields(input, ['policy', 'signatures']);
    return this.f.transaction(p, now => {
      const x = this.validate(p.tenant_id, input.policy, now), simulation = this.f.store.must(p.tenant_id, 'emergency-simulation', digest(x));
      requireThat(simulation.baseline_digest === digest(this.f.policy(p.tenant_id)), 'INV-409-STATE', 'Re-simulate against current policy', 409);
      const signers = new Set(), domains = new Set(); requireThat(Array.isArray(input.signatures) && input.signatures.length <= 5, 'INV-400-SCHEMA', 'Bounded customer quorum required');
      for (const sig of input.signatures) { const payload = verifySigned(sig, this.f.identities(p.tenant_id), 'emergency-policy'), who = this.f.identities(p.tenant_id)[sig.protected.key_id]; requireThat(who.roles.includes('custodian') && digest(payload) === digest(x), 'INV-403-SCOPE', 'Exact customer emergency authorization required', 403); signers.add(sig.protected.key_id); domains.add(who.failure_domain); }
      requireThat(signers.size >= 3 && domains.size >= 3, 'INV-403-QUORUM', 'Emergency activation needs three independent custodians', 403);
      this.f.store.insert(p.tenant_id, 'emergency', x.emergency_id, { policy: clone(x), signatures: clone(input.signatures), status: 'ACTIVE' }, now);
      this.f.store.audit(p.tenant_id, 'EMERGENCY_ACTIVATED', p.subject_id, x.emergency_id, { policy_digest: digest(x), expires_at: x.expires_at, notification: 'CUSTOMER_SECURITY' }, now);
      this.f.store.insert(p.tenant_id, 'notification', x.emergency_id, { type: 'EMERGENCY_ACTIVATED', owner: 'security', reference: x.emergency_id, created_at: now, acknowledged: false }, now); return { status: 'ACTIVE', expires_at: x.expires_at, root_bypass: false };
    });
  }
  restriction(t, capsule, now) { return this.f.store.list(t, 'emergency', 10000).find(r => r.status === 'ACTIVE' && r.policy.expires_at > now && r.policy.actions.includes(capsule.action.type) && r.policy.resources.includes(capsule.action.target_resource) && (r.policy.deny || capsule.quantity > r.policy.max_quantity)); }
  sweep(p) { this.f.authorize(p, ['security', 'policy_admin']); return this.f.transaction(p, now => { let expired = 0; for (const r of this.f.store.list(p.tenant_id, 'emergency', 10000)) if (r.status === 'ACTIVE' && r.policy.expires_at <= now) { r.status = 'EXPIRED'; this.f.store.put(p.tenant_id, 'emergency', r.policy.emergency_id, r, now); this.f.store.audit(p.tenant_id, 'EMERGENCY_EXPIRED', 'expiry-monitor', r.policy.emergency_id, { restored: 'BASE_POLICY_ONLY', revocations_preserved: true }, now); expired++; } return { expired }; }); }
}
