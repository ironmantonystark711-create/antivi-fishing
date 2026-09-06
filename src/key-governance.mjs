import { randomUUID } from 'node:crypto';
import { generateKey, verifySigned } from './crypto.mjs';
import { digest, clone } from './canonical.mjs';
import { fields, oneOf, integer } from './schema.mjs';
import { suite } from './suites.mjs';
import { requireThat } from './errors.mjs';

// Software custody adapter. Customer signatures are supplied externally; root
// private keys are never accepted by this API or reconstructed by the gate.
export class KeyGovernance {
  constructor(fabric) { this.f = fabric; }
  prepare(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['purpose', 'suite', 'not_before']);
    oneOf(input.purpose, ['execution', 'audit'], 'rotatable key purpose'); suite(input.suite, 'sign');
    return this.f.transaction(p, now => {
      requireThat(!this.f.store.get(p.tenant_id, 'retired-suite', `${input.purpose}:${input.suite}`), 'INV-451-POLICY', 'Retired signing suite cannot be reactivated', 451);
      integer(input.not_before, 'rotation delay', now + 60000, now + 86400000);
      const old = this.f.keys(p.tenant_id)[input.purpose], next = generateKey(input.suite);
      const payload = { format: 'IF-KEY-ROTATION-1', rotation_id: randomUUID(), tenant_id: p.tenant_id, purpose: input.purpose, prior_key_id: old.key_id, prior_suite: old.suite, next_key_id: next.key_id, next_public_key: next.public_key, next_suite: next.suite, policy_digest: digest(this.f.policy(p.tenant_id)), requested_by: p.subject_id, issued_at: now, not_before: input.not_before, expires_at: input.not_before + 3600000, preserve_audit_history: true };
      this.f.store.insert(p.tenant_id, 'key-rotation', payload.rotation_id, { payload, private_material: next, status: 'PREPARED' }, now);
      this.f.store.audit(p.tenant_id, 'KEY_ROTATION_PREPARED', p.subject_id, payload.rotation_id, { public_transition_digest: digest(payload), not_before: payload.not_before }, now);
      return payload;
    });
  }
  activate(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['rotation_id', 'signatures']);
    const activated = this.f.transaction(p, now => {
      const r = this.f.store.must(p.tenant_id, 'key-rotation', input.rotation_id), x = r.payload;
      requireThat(r.status === 'PREPARED', 'INV-409-REPLAY', 'Key rotation already consumed', 409);
      requireThat(now >= x.not_before && now < x.expires_at, 'INV-423-DEFER', 'Key rotation is outside its authorised activation window', 423);
      requireThat(x.tenant_id === p.tenant_id && this.f.keys(p.tenant_id)[x.purpose].key_id === x.prior_key_id && digest(this.f.policy(p.tenant_id)) === x.policy_digest, 'INV-409-STATE', 'Key or policy changed since rotation review', 409);
      requireThat(Array.isArray(input.signatures) && input.signatures.length >= 3 && input.signatures.length <= 5, 'INV-403-QUORUM', 'Three customer custodians required', 403);
      const signers = new Set(), domains = new Set(), identities = this.f.identities(p.tenant_id);
      for (const sig of input.signatures) {
        const payload = verifySigned(sig, identities, 'key-rotation'), who = identities[sig.protected.key_id];
        requireThat(who.roles.includes('custodian') && who.subject_id !== x.requested_by && !signers.has(sig.protected.key_id) && digest(payload) === digest(x), 'INV-403-QUORUM', 'Exact independent customer key ceremony required', 403);
        signers.add(sig.protected.key_id); domains.add(who.failure_domain);
      }
      requireThat(domains.size >= 3, 'INV-403-QUORUM', 'Three independent custodian domains required', 403);
      requireThat(!this.f.store.get(p.tenant_id, 'retired-suite', `${x.purpose}:${x.next_suite}`) && !this.f.revoked(p.tenant_id, 'key', x.next_key_id), 'INV-451-POLICY', 'Retired suite or revoked key cannot be activated', 451);
      const key = r.private_material;
      requireThat(key.key_id === x.next_key_id && key.public_key === x.next_public_key && key.suite === x.next_suite, 'INV-503-CONFIG', 'Prepared key material does not match approved transition', 503);
      // Signed by the previous audit key, this record links the new verification
      // material. Consumers must pin/verify this transition, not trust bundle keys.
      this.f.store.audit(p.tenant_id, 'CUSTOMER_KEY_ROTATED', p.subject_id, x.rotation_id, { transition: x, approvals: input.signatures }, now);
      if (x.purpose === 'audit') {
        const old = this.f.keys(p.tenant_id).audit;
        this.f.store.put(p.tenant_id, 'audit-public-key', old.key_id, { key_id: old.key_id, public_key: old.public_key, suite: old.suite }, now);
        this.f.store.put(p.tenant_id, 'audit-public-key', key.key_id, { key_id: key.key_id, public_key: key.public_key, suite: key.suite }, now);
      }
      if (x.prior_suite !== x.next_suite) this.f.store.put(p.tenant_id, 'retired-suite', `${x.purpose}:${x.prior_suite}`, { suite: x.prior_suite, retired_at: now, historical_verification: true }, now);
      this.f.store.put(p.tenant_id, 'active-key', x.purpose, key, now);
      r.status = 'ACTIVATED'; r.signatures = clone(input.signatures); delete r.private_material;
      this.f.store.put(p.tenant_id, 'key-rotation', x.rotation_id, r, now);
      this.f.store.insert(p.tenant_id, 'notification', x.rotation_id, { type: 'KEY_ROTATION', owner: 'security', reference: x.rotation_id, created_at: now, acknowledged: false }, now);
      return { key, transition: x };
    });
    this.f.tenant(p.tenant_id).keys[activated.transition.purpose] = activated.key;
    if (activated.transition.purpose === 'audit') this.f.store.auditKeys[p.tenant_id] = activated.key;
    return { status: 'ACTIVATED', transition: activated.transition, historical_verification_preserved: true };
  }
  publicHistory(p) {
    this.f.authorize(p, ['security', 'auditor']);
    return this.f.store.list(p.tenant_id, 'key-rotation', 10000).filter(r => r.status === 'ACTIVATED').map(r => ({ payload: r.payload, signatures: r.signatures }));
  }
}
