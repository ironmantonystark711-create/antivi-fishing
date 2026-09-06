import { randomUUID } from 'node:crypto';
import { clone, digest } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, integer, oneOf, text, uniqueStrings } from './schema.mjs';
import { requireThat } from './errors.mjs';

const OPERATIONS = ['MFA_RESET', 'AUTHENTICATOR_ENROLL', 'ACCOUNT_RECOVERY'];

export class IdentityLifecycle {
  constructor(fabric) { this.f = fabric; }
  base(t, subject) {
    const found = Object.entries(this.f.tenant(t).identities).find(([, value]) => value.subject_id === subject);
    requireThat(found, 'INV-401-AUTH', 'Authentication required', 401);
    return { key_id: found[0], identity: found[1] };
  }
  effective(t, subject) {
    const { key_id, identity } = this.base(t, subject), state = this.f.store.get(t, 'identity-state', subject);
    return { ...clone(identity), ...(state ?? {}), identity_key_id: key_id, revoked: this.f.revoked(t, 'key', key_id) || this.f.revoked(t, 'subject', subject), authenticators: state?.authenticators ?? [clone(identity.authenticator)] };
  }
  all(t) { return Object.fromEntries(Object.keys(this.f.tenant(t).identities).map(keyId => { const identity = this.f.tenant(t).identities[keyId]; return [keyId, { ...this.effective(t, identity.subject_id), revoked: this.f.revoked(t, 'key', keyId) || this.f.revoked(t, 'subject', identity.subject_id) }]; })); }
  assertAssured(t, subject, device, now) {
    const identity = this.effective(t, subject), authenticator = identity.authenticators.find(a => a.id === identity.authenticator?.id) ?? identity.authenticator;
    requireThat(!identity.revoked, 'INV-401-AUTH', 'Identity signing key is revoked', 401);
    requireThat(identity.device_id === device && identity.health_expires_at > now, 'INV-403-HEALTH', 'Configured device health evidence expired or mismatched', 403);
    const hardwareRequired = this.f.config.identity_assurance?.require_hardware_backed === true;
    requireThat(authenticator && authenticator.phishing_resistant === true && (!hardwareRequired || (authenticator.hardware_backed === true && identity.hardware_backed === true)) && authenticator.status !== 'RESET_REQUIRED' && authenticator.enrolled_at <= now, 'INV-401-AUTH', hardwareRequired ? 'Phishing-resistant hardware-backed authentication is required' : 'Phishing-resistant authentication is required', 401);
    requireThat(identity.component?.trusted === true && this.f.tenant(t).key_governance.trusted_component_firmware.includes(identity.component.firmware) && !this.f.revoked(t, 'component', `${identity.component.id}:${identity.component.firmware}`), 'INV-403-HEALTH', 'Trusted component is unavailable', 403);
    return identity;
  }
  sessionEpoch(t, subject) { return this.effective(t, subject).session_epoch ?? 0; }
  sessionValid(t, subject, epoch) { return Number.isSafeInteger(epoch) && epoch === this.sessionEpoch(t, subject) && !this.effective(t, subject).revoked; }
  issueJit(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['subject_id', 'scope', 'device_id', 'ttl_ms', 'reason']); identifier(input.subject_id); uniqueStrings(input.scope, 'JIT scope', 16); identifier(input.device_id); integer(input.ttl_ms, 'JIT TTL', 1000, 300000); text(input.reason, 'JIT reason');
    return this.f.transaction(p, now => {
      this.assertAssured(p.tenant_id, input.subject_id, input.device_id, now);
      const payload = { ...clone(input), jit_id: randomUUID(), tenant_id: p.tenant_id, issued_by: p.subject_id, session_epoch: this.sessionEpoch(p.tenant_id, input.subject_id), issued_at: now, expires_at: now + input.ttl_ms };
      const envelope = signed(payload, this.f.keys(p.tenant_id).execution, 'identity-jit');
      this.f.store.insert(p.tenant_id, 'identity-jit', payload.jit_id, envelope, now);
      this.f.store.audit(p.tenant_id, 'JIT_PRIVILEGE_ISSUED', p.subject_id, payload.jit_id, { subject_id: input.subject_id, scope_digest: digest(input.scope), reason_digest: digest(input.reason) }, now);
      return envelope;
    });
  }
  consumeJit(p, envelope, scope, device) {
    text(scope, 'JIT scope'); identifier(device, 'JIT device');
    return this.f.transaction(p, now => {
      const payload = verifySigned(envelope, this.f.executionPublic(p.tenant_id), 'identity-jit');
      requireThat(payload.tenant_id === p.tenant_id && payload.subject_id === p.subject_id && payload.device_id === device && payload.scope.includes(scope) && payload.expires_at > now && payload.session_epoch === this.sessionEpoch(p.tenant_id, p.subject_id) && !this.f.revoked(p.tenant_id, 'jit', payload.jit_id) && !this.f.revoked(p.tenant_id, 'key', envelope.protected.key_id), 'INV-403-SCOPE', 'JIT privilege is unavailable or out of scope', 403);
      const stored = this.f.store.must(p.tenant_id, 'identity-jit', payload.jit_id);
      requireThat(digest(stored) === digest(envelope), 'INV-401-SIGNATURE', 'JIT privilege does not match its durable grant', 401);
      this.assertAssured(p.tenant_id, p.subject_id, device, now);
      this.f.store.put(p.tenant_id, 'identity-jit', payload.jit_id, { ...stored, consumed_at: now }, now);
      this.f.store.audit(p.tenant_id, 'JIT_PRIVILEGE_USED', p.subject_id, payload.jit_id, { scope }, now);
      return clone(payload);
    });
  }
  request(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['operation', 'subject_id', 'new_authenticator', 'proofing_level', 'recovery_domains', 'out_of_band_receipt_digest', 'reason']); oneOf(input.operation, OPERATIONS, 'identity lifecycle operation'); identifier(input.subject_id); integer(input.proofing_level, 'proofing level', 1, 5); uniqueStrings(input.recovery_domains, 'recovery domains', 5); requireThat(/^[a-f0-9]{64}$/.test(input.out_of_band_receipt_digest), 'INV-400-SCHEMA', 'Out-of-band receipt digest required'); text(input.reason, 'identity lifecycle reason');
    requireThat(input.operation === 'AUTHENTICATOR_ENROLL' ? input.new_authenticator && typeof input.new_authenticator === 'object' : input.new_authenticator === null, 'INV-400-SCHEMA', 'Only enrolment may include a new authenticator');
    if (input.new_authenticator) { fields(input.new_authenticator, ['id', 'phishing_resistant', 'hardware_backed']); identifier(input.new_authenticator.id); requireThat(input.new_authenticator.phishing_resistant === true && typeof input.new_authenticator.hardware_backed === 'boolean', 'INV-401-AUTH', 'Enrolled authenticators must be phishing resistant'); }
    return this.f.transaction(p, now => {
      const current = this.effective(p.tenant_id, input.subject_id);
      requireThat(input.proofing_level >= current.proofing_level && input.recovery_domains.length >= 2, 'INV-401-AUTH', 'Recovery assurance is weaker than the recovered identity', 401);
      const request = { ...clone(input), request_id: randomUUID(), tenant_id: p.tenant_id, requested_by: p.subject_id, requested_at: now, status: 'PENDING', approvals: [] };
      this.f.store.insert(p.tenant_id, 'identity-lifecycle', request.request_id, request, now);
      this.f.store.audit(p.tenant_id, 'IDENTITY_LIFECYCLE_REQUESTED', p.subject_id, request.request_id, { operation: request.operation, subject_id: request.subject_id, reason_digest: digest(request.reason) }, now);
      return clone(request);
    });
  }
  challenge(p, requestId) {
    this.f.authorize(p, ['approver', 'custodian']); const request = this.f.store.must(p.tenant_id, 'identity-lifecycle', requestId); requireThat(request.status === 'PENDING', 'INV-409-STATE', 'Identity lifecycle request is closed', 409);
    const { key_id } = this.base(p.tenant_id, p.subject_id);
    return { tenant_id: p.tenant_id, request_id: requestId, request_digest: digest(request), signer_id: key_id, approved_at: this.f.clock(), expires_at: this.f.clock() + 300000 };
  }
  approve(p, envelope) {
    this.f.authorize(p, ['approver', 'custodian']); return this.f.transaction(p, now => {
      const payload = verifySigned(envelope, this.all(p.tenant_id), 'identity-lifecycle-approval'); fields(payload, ['tenant_id', 'request_id', 'request_digest', 'signer_id', 'approved_at', 'expires_at']);
      const request = this.f.store.must(p.tenant_id, 'identity-lifecycle', payload.request_id), signer = this.all(p.tenant_id)[payload.signer_id];
      requireThat(request.status === 'PENDING' && payload.tenant_id === p.tenant_id && signer?.subject_id === p.subject_id && signer.subject_id !== request.subject_id && payload.request_digest === digest(request), 'INV-403-SCOPE', 'Identity approval scope mismatch', 403);
      integer(payload.approved_at, 'approval time', now - 300000, now + 5000); integer(payload.expires_at, 'approval expiry', now + 1, now + 300000);
      requireThat(!request.approvals.some(a => a.payload.signer_id === payload.signer_id), 'INV-409-REPLAY', 'Duplicate identity lifecycle approval', 409);
      request.approvals.push(clone(envelope)); this.f.store.put(p.tenant_id, 'identity-lifecycle', request.request_id, request, now);
      this.f.store.audit(p.tenant_id, 'IDENTITY_LIFECYCLE_APPROVED', p.subject_id, request.request_id, { signer_id: payload.signer_id, approval_digest: digest(envelope) }, now);
      return { accepted: true, approvals: request.approvals.length };
    });
  }
  complete(p, requestId) {
    this.f.authorize(p, ['security']); return this.f.transaction(p, now => {
      const request = this.f.store.must(p.tenant_id, 'identity-lifecycle', requestId); requireThat(request.status === 'PENDING', 'INV-409-STATE', 'Identity lifecycle request is closed', 409);
      const eligible = new Set(), domains = new Set();
      for (const approval of request.approvals) { try { const a = verifySigned(approval, this.all(p.tenant_id), 'identity-lifecycle-approval'), identity = this.all(p.tenant_id)[a.signer_id]; if (a.expires_at > now && identity && !domains.has(identity.failure_domain)) { eligible.add(a.signer_id); domains.add(identity.failure_domain); } } catch {} }
      requireThat(eligible.size >= 2 && domains.size >= 2, 'INV-412-EVIDENCE', 'Two independent protected identity approvals are required', 412);
      const old = this.effective(p.tenant_id, request.subject_id), next = clone(old);
      if (request.operation === 'MFA_RESET') next.authenticators = next.authenticators.map(a => ({ ...a, status: 'RESET_REQUIRED' }));
      if (request.operation === 'AUTHENTICATOR_ENROLL') next.authenticators.push({ ...request.new_authenticator, enrolled_at: now, status: 'ACTIVE' });
      if (request.operation === 'ACCOUNT_RECOVERY') { next.recovered_at = now; next.recovery_proofing_level = request.proofing_level; next.authenticators = next.authenticators.map(a => ({ ...a, status: 'RESET_REQUIRED' })); }
      next.session_epoch = (old.session_epoch ?? 0) + 1; next.session_invalidated_at = now;
      this.f.store.put(p.tenant_id, 'identity-state', request.subject_id, next, now); request.status = 'COMPLETED'; request.completed_at = now; this.f.store.put(p.tenant_id, 'identity-lifecycle', requestId, request, now);
      this.f.store.audit(p.tenant_id, 'IDENTITY_LIFECYCLE_COMPLETED', p.subject_id, requestId, { operation: request.operation, subject_id: request.subject_id, approvals: eligible.size }, now);
      return clone(request);
    });
  }
}
