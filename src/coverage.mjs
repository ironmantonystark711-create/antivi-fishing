import { digest, clone } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, oneOf, integer, text } from './schema.mjs';
import { requireThat } from './errors.mjs';

const requiredNegativeTests = ['no-certificate', 'wrong-tenant', 'state-race', 'replay', 'direct-bypass'];
function connectorVersion(value) {
  text(value, 'connector version', 64);
  requireThat(/^\d+(?:\.\d+){0,3}$/.test(value), 'INV-400-SCHEMA', 'Connector version must use canonical numeric components');
  const parts = value.split('.').map(Number);
  requireThat(parts.every(Number.isSafeInteger), 'INV-400-SCHEMA', 'Connector version component is out of range');
  return parts;
}
function isDowngrade(next, current) {
  const a = connectorVersion(next), b = connectorVersion(current), size = Math.max(a.length, b.length);
  for (let i = 0; i < size; i++) { if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0); }
  return false;
}

export function declarePath(input, now) {
  fields(input, ['path_id', 'action_type', 'target', 'environment', 'connector_version', 'owner', 'status', 'max_age_ms', 'configuration_digest'], ['bypass_test_plan']);
  for (const f of ['path_id', 'target', 'owner']) identifier(input[f], f);
  for (const f of ['action_type', 'environment']) text(input[f], f, 128); connectorVersion(input.connector_version);
  oneOf(input.status, ['MONITORED', 'UNKNOWN'], 'manually declared status'); integer(input.max_age_ms, 'maximum evidence age', 1000, 2592000000);
  requireThat(/^[a-f0-9]{64}$/.test(input.configuration_digest), 'INV-400-SCHEMA', 'Configuration digest is required');
  if (input.bypass_test_plan) {
    fields(input.bypass_test_plan, ['owner', 'cases']); identifier(input.bypass_test_plan.owner, 'bypass test owner');
    requireThat(Array.isArray(input.bypass_test_plan.cases) && new Set(input.bypass_test_plan.cases).size === input.bypass_test_plan.cases.length && requiredNegativeTests.every(name => input.bypass_test_plan.cases.includes(name)), 'INV-400-SCHEMA', 'Bypass plan must assign every required negative test');
  }
  requireThat(input.environment === 'simulation' || input.bypass_test_plan, 'INV-412-COVERAGE', 'Non-simulation coverage requires an assigned bypass-test plan', 412);
  return { ...input, declared_at: now, evidence_at: null, evidence_digest: null, technical_validation: null };
}
export function coverageManifest(tenant, paths, now, key) {
  const effective = paths.map(p => ({ ...p, effective_status: p.evidence_at !== null && (now - p.evidence_at > p.max_age_ms || (p.evidence_expires_at != null && p.evidence_expires_at <= now)) ? 'UNKNOWN' : p.status, next_action: p.status === 'ENFORCED' ? 'Revalidate before evidence expires; verify all bypass paths.' : 'Attach independently executed technical bypass evidence.' }));
  // This distribution provides a simulator, not target-wide total mediation.
  return signed({ format: 'IF-COVERAGE-MANIFEST-1', locally_enforced: effective.length > 0 && effective.every(p => p.effective_status === 'ENFORCED' && p.environment === 'simulation'), tenant_id: tenant, issued_at: now, profile: 'software-engineering', guarantee: false, assurance: 'NO_PRODUCTION_ENFORCEMENT_GUARANTEE', reason: 'Real target coverage and independent bypass assessment have not been supplied.', paths: effective, scope_digest: digest(effective) }, key, 'coverage');
}

export class CoverageLifecycle {
  constructor(fabric) { this.f = fabric; }
  closeActiveInterval(t, pathId, now, reason) {
    const active = this.f.store.list(t, 'coverage-history', 10000).find(item => item.path_id === pathId && item.effective_from !== null && item.effective_until === null);
    if (active) { active.effective_until = now; active.interval_close_reason = reason; this.f.store.put(t, 'coverage-history', active.history_id, active, now); }
  }
  history(t, path, now, reason) {
    const id = `${path.path_id}:${now}:${this.f.store.db.prepare('SELECT count(*) AS n FROM records WHERE tenant=? AND kind=?').get(t, 'coverage-history').n}`;
    this.f.store.insert(t, 'coverage-history', id, { ...path, history_id: id, recorded_at: now, reason, effective_from: path.status === 'ENFORCED' ? now : null, effective_until: null }, now);
    this.f.store.audit(t, 'COVERAGE_TRANSITION', 'coverage-mapper', path.path_id, { status: path.status, reason, configuration_digest: path.configuration_digest }, now);
  }
  drift(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['path_id', 'configuration_digest', 'connector_version']);
    requireThat(/^[a-f0-9]{64}$/.test(input.configuration_digest), 'INV-400-SCHEMA', 'Configuration digest required'); connectorVersion(input.connector_version);
    return this.f.transaction(p, now => { const r = this.f.store.must(p.tenant_id, 'coverage', input.path_id); requireThat(!isDowngrade(input.connector_version, r.connector_version), 'INV-409-LIFECYCLE', 'Connector downgrade requires a new declared path and bypass assessment', 409); if (r.configuration_digest !== input.configuration_digest || r.connector_version !== input.connector_version) { this.closeActiveInterval(p.tenant_id, r.path_id, now, 'CONFIGURATION_OR_CONNECTOR_DRIFT'); Object.assign(r, input, { status: 'UNKNOWN', evidence_at: null, technical_validation: null }); this.f.store.put(p.tenant_id, 'coverage', input.path_id, r, now); this.history(p.tenant_id, r, now, 'CONFIGURATION_OR_CONNECTOR_DRIFT'); } return r; });
  }
  revalidate(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['path_id', 'evidence']);
    return this.f.transaction(p, now => {
      const r = this.f.store.must(p.tenant_id, 'coverage', input.path_id), e = verifySigned(input.evidence, this.f.tenant(p.tenant_id).issuers, 'coverage-test');
      fields(e, ['format', 'tenant_id', 'path_id', 'configuration_digest', 'connector_version', 'tested_at', 'expires_at', 'credential_owner', 'permissions', 'negative_tests', 'environment', 'target']);
      const issuer = this.f.tenant(p.tenant_id).issuers[input.evidence.protected.key_id];
      requireThat(issuer.channel === 'authoritative' && issuer.kinds.includes('governance_review') && !this.f.revoked(p.tenant_id, 'issuer', input.evidence.protected.key_id) && !this.f.revoked(p.tenant_id, 'key', input.evidence.protected.key_id), 'INV-403-SCOPE', 'Trusted non-revoked technical assessor required', 403);
      requireThat(e.format === 'IF-COVERAGE-TEST-1' && e.tenant_id === p.tenant_id && e.path_id === r.path_id && e.target === r.target && e.configuration_digest === r.configuration_digest && e.connector_version === r.connector_version && e.environment === r.environment && e.credential_owner === 'root-gate', 'INV-409-COVERAGE', 'Technical evidence does not match declared scope', 409);
      integer(e.tested_at, 'test time', now - r.max_age_ms, now); integer(e.expires_at, 'test expiry', now + 1, e.tested_at + r.max_age_ms);
      const testedNames = Array.isArray(e.negative_tests) ? e.negative_tests.map(x => x?.name) : [];
      requireThat(Array.isArray(e.permissions) && e.permissions.length === 2 && new Set(e.permissions).size === 2 && ['read', 'exact-mutation'].every(permission => e.permissions.includes(permission)) && Array.isArray(e.negative_tests) && new Set(testedNames).size === testedNames.length && testedNames.length === requiredNegativeTests.length && requiredNegativeTests.every(name => e.negative_tests.some(x => x.name === name && x.rejected === true && /^[a-f0-9]{64}$/.test(x.result_digest))), 'INV-412-COVERAGE', 'All assigned bypass tests and least-privilege evidence must pass', 412);
      this.closeActiveInterval(p.tenant_id, r.path_id, now, 'REVALIDATED'); r.status = 'ENFORCED'; r.evidence_at = e.tested_at; r.evidence_expires_at = e.expires_at; r.evidence_digest = digest(input.evidence); r.technical_validation = clone(input.evidence);
      this.f.store.put(p.tenant_id, 'coverage', r.path_id, r, now); this.history(p.tenant_id, r, now, 'TECHNICAL_TESTS_VERIFIED'); return r;
    });
  }
  refresh(p) {
    return this.f.transaction(p, now => { let stale = 0; for (const r of this.f.store.list(p.tenant_id, 'coverage', 10000)) {
      const assessorKey = r.technical_validation?.protected?.key_id;
      const invalid = r.status === 'ENFORCED' && (now - r.evidence_at > r.max_age_ms || r.evidence_expires_at <= now || !assessorKey || this.f.revoked(p.tenant_id, 'issuer', assessorKey) || this.f.revoked(p.tenant_id, 'key', assessorKey));
      if (invalid) { const reason = assessorKey && (this.f.revoked(p.tenant_id, 'issuer', assessorKey) || this.f.revoked(p.tenant_id, 'key', assessorKey)) ? 'ASSESSOR_REVOKED' : 'STALE_EVIDENCE'; this.closeActiveInterval(p.tenant_id, r.path_id, now, reason); r.status = 'UNKNOWN'; this.f.store.put(p.tenant_id, 'coverage', r.path_id, r, now); this.history(p.tenant_id, r, now, reason); this.f.store.put(p.tenant_id, 'coverage-task', r.path_id, { path_id: r.path_id, owner: r.owner, reason: 'REVALIDATION_REQUIRED', created_at: now }, now); stale++; }
    } return { stale }; });
  }
}
