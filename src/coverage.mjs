import { digest, clone } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, oneOf, integer, text, SCHEMAS } from './schema.mjs';
import { requireThat } from './errors.mjs';

export const BYPASS_TESTS = Object.freeze(['no-certificate', 'wrong-tenant', 'state-race', 'replay', 'direct-bypass']);

export function declarePath(input, now) {
  fields(input, ['path_id', 'action_type', 'target', 'environment', 'connector_version', 'owner', 'status', 'max_age_ms', 'configuration_digest']);
  for (const f of ['path_id', 'target', 'owner']) identifier(input[f], f);
  requireThat(Object.hasOwn(SCHEMAS, input.action_type), 'INV-400-SCHEMA', 'Coverage action must use a supported schema');
  for (const f of ['action_type', 'environment', 'connector_version']) text(input[f], f, 128);
  oneOf(input.status, ['MONITORED', 'UNKNOWN'], 'manually declared status'); integer(input.max_age_ms, 'maximum evidence age', 1000, 2592000000);
  requireThat(/^[a-f0-9]{64}$/.test(input.configuration_digest), 'INV-400-SCHEMA', 'Configuration digest is required');
  return { ...input, declared_at: now, evidence_at: null, evidence_digest: null, technical_validation: null, bypass_plan: BYPASS_TESTS.map(name => ({ name, owner: input.owner, status: 'NOT_EXECUTED' })) };
}
export function coverageManifest(tenant, paths, now, key) {
  const effective = paths.map(p => ({ ...p, effective_status: p.evidence_at !== null && (now - p.evidence_at > p.max_age_ms || (p.evidence_expires_at != null && p.evidence_expires_at <= now)) ? 'UNKNOWN' : p.status, next_action: p.status === 'ENFORCED' ? 'Revalidate before evidence expires; verify all bypass paths.' : 'Attach independently executed technical bypass evidence.' }));
  // This distribution provides a simulator, not target-wide total mediation.
  return signed({ format: 'IF-COVERAGE-MANIFEST-1', locally_enforced: effective.length > 0 && effective.every(p => p.effective_status === 'ENFORCED' && p.environment === 'simulation'), tenant_id: tenant, issued_at: now, profile: 'software-engineering', guarantee: false, assurance: 'NO_PRODUCTION_ENFORCEMENT_GUARANTEE', reason: 'Real target coverage and independent bypass assessment have not been supplied.', paths: effective, scope_digest: digest(effective) }, key, 'coverage');
}

export class CoverageLifecycle {
  constructor(fabric) { this.f = fabric; }
  history(t, path, now, reason) {
    const id = `${path.path_id}:${now}:${this.f.store.db.prepare('SELECT count(*) AS n FROM records WHERE tenant=? AND kind=?').get(t, 'coverage-history').n}`;
    this.f.store.insert(t, 'coverage-history', id, { ...path, recorded_at: now, reason }, now);
    this.f.store.audit(t, 'COVERAGE_TRANSITION', 'coverage-mapper', path.path_id, { status: path.status, reason, configuration_digest: path.configuration_digest }, now);
  }
  drift(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['path_id', 'configuration_digest', 'connector_version']);
    requireThat(/^[a-f0-9]{64}$/.test(input.configuration_digest), 'INV-400-SCHEMA', 'Configuration digest required'); text(input.connector_version, 'connector version');
    return this.f.transaction(p, now => { const r = this.f.store.must(p.tenant_id, 'coverage', input.path_id); if (r.configuration_digest !== input.configuration_digest || r.connector_version !== input.connector_version) { Object.assign(r, input, { status: 'UNKNOWN', evidence_at: null, technical_validation: null }); this.f.store.put(p.tenant_id, 'coverage', input.path_id, r, now); this.history(p.tenant_id, r, now, 'CONFIGURATION_OR_CONNECTOR_DRIFT'); } return r; });
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
      requireThat(Array.isArray(e.permissions) && e.permissions.length > 0 && e.permissions.every(x => ['read', 'exact-mutation'].includes(x)) && Array.isArray(e.negative_tests) && BYPASS_TESTS.every(name => e.negative_tests.some(x => x.name === name && x.rejected === true && /^[a-f0-9]{64}$/.test(x.result_digest))), 'INV-412-COVERAGE', 'All assigned bypass tests and least-privilege evidence must pass', 412);
      r.bypass_plan = BYPASS_TESTS.map(name => ({ name, owner: r.owner, status: 'PASS', result_digest: e.negative_tests.find(test => test.name === name).result_digest }));
      r.status = 'ENFORCED'; r.evidence_at = e.tested_at; r.evidence_expires_at = e.expires_at; r.evidence_digest = digest(input.evidence); r.technical_validation = clone(input.evidence);
      this.f.store.put(p.tenant_id, 'coverage', r.path_id, r, now); this.f.store.remove(p.tenant_id, 'coverage-task', r.path_id); this.history(p.tenant_id, r, now, 'TECHNICAL_TESTS_VERIFIED'); return r;
    });
  }
  inventory(t) {
    // Never truncate a manifest: an omitted uncovered path would create a false claim.
    return this.f.store.statement('SELECT id FROM records WHERE tenant=? AND kind=? ORDER BY id').all(t, 'coverage').map(row => this.f.store.must(t, 'coverage', row.id));
  }
  refresh(p) {
    return this.f.transaction(p, now => {
      let stale = 0;
      for (const r of this.inventory(p.tenant_id)) {
        if (r.status !== 'ENFORCED') continue;
        const id = r.technical_validation?.protected?.key_id;
        const issuer = this.f.tenant(p.tenant_id).issuers[id];
        let reason = null;
        if (now - r.evidence_at >= r.max_age_ms || r.evidence_expires_at <= now) reason = 'STALE_EVIDENCE';
        else if (!issuer || issuer.revoked || this.f.revoked(p.tenant_id, 'issuer', id) || this.f.revoked(p.tenant_id, 'key', id)) reason = 'ASSESSOR_REVOKED';
        else {
          try { verifySigned(r.technical_validation, this.f.tenant(p.tenant_id).issuers, 'coverage-test'); }
          catch { reason = 'EVIDENCE_UNVERIFIABLE'; }
        }
        if (!reason) continue;
        r.status = 'UNKNOWN';
        this.f.store.put(p.tenant_id, 'coverage', r.path_id, r, now);
        this.history(p.tenant_id, r, now, reason);
        this.f.store.put(p.tenant_id, 'coverage-task', r.path_id, { path_id: r.path_id, owner: r.owner, reason, created_at: now }, now);
        stale++;
      }
      return { stale };
    });
  }
  timeline(p, pathId) {
    this.f.authorize(p, ['security', 'auditor']); identifier(pathId);
    this.f.store.must(p.tenant_id, 'coverage', pathId); this.refresh(p);
    const rows = this.f.store.statement('SELECT id FROM records WHERE tenant=? AND kind=? ORDER BY created,rowid').all(p.tenant_id, 'coverage-history').map(row => this.f.store.must(p.tenant_id, 'coverage-history', row.id)).filter(row => row.path_id === pathId);
    return rows.map((row, index) => ({ ...row, valid_from: row.recorded_at, valid_until: Math.min(rows[index + 1]?.recorded_at ?? Number.MAX_SAFE_INTEGER, row.status === 'ENFORCED' ? Math.min(row.evidence_at + row.max_age_ms, row.evidence_expires_at) : Number.MAX_SAFE_INTEGER), production_guarantee: false }));
  }
}
