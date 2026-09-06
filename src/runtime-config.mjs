import { existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { digest, clone } from './canonical.mjs';
import { verifySigned, signed } from './crypto.mjs';
import { fields, integer, oneOf } from './schema.mjs';
import { requireThat } from './errors.mjs';

export function runtimeConfiguration(tenant, gate, now) {
  return { format: 'IF-RUNTIME-CONFIG-1', tenant_id: tenant, gate_id: gate, version: 1, issued_at: now, expires_at: now + 7 * 86400000, fail_policy: 'cached-allow', cache_entries: 256, reload_interval_ms: 1000, remediation_services: ['security-remediation'], environment: 'simulation' };
}
export function signRuntimeConfiguration(config, custodians) { return { config: clone(config), signatures: custodians.map(k => signed(config, k, 'runtime-config')) }; }
export function verifyRuntimeConfiguration(snapshot, identities, tenant, gate, now) {
  requireThat(snapshot && Array.isArray(snapshot.signatures), 'INV-503-CONFIG', 'Signed runtime configuration required', 503);
  const c = snapshot.config;
  fields(c, ['format', 'tenant_id', 'gate_id', 'version', 'issued_at', 'expires_at', 'fail_policy', 'cache_entries', 'reload_interval_ms', 'remediation_services', 'environment']);
  requireThat(c.format === 'IF-RUNTIME-CONFIG-1' && c.tenant_id === tenant && c.gate_id === gate && c.issued_at <= now && c.expires_at > now, 'INV-503-CONFIG', 'Runtime configuration scope or validity failed', 503);
  integer(c.version, 'configuration version', 1); integer(c.cache_entries, 'cache entries', 1, 4096); integer(c.reload_interval_ms, 'reload interval', 100, 60000); oneOf(c.fail_policy, ['cached-allow', 'fail-closed'], 'failure policy');
  requireThat(c.environment === 'simulation' && Array.isArray(c.remediation_services) && c.remediation_services.length <= 8 && c.remediation_services.every(x => typeof x === 'string' && /^[a-z][a-z0-9-]*$/.test(x)), 'INV-503-CONFIG', 'Invalid runtime environment or remediation set', 503);
  const signers = new Set(), domains = new Set();
  for (const envelope of snapshot.signatures) {
    const p = verifySigned(envelope, identities, 'runtime-config'), who = identities[envelope.protected.key_id];
    requireThat(who.roles.includes('custodian') && digest(p) === digest(c), 'INV-503-CONFIG', 'Configuration requires exact customer approval', 503);
    signers.add(envelope.protected.key_id); domains.add(who.failure_domain);
  }
  requireThat(signers.size >= 3 && domains.size >= 3, 'INV-503-CONFIG', 'Configuration requires independent customer quorum', 503);
  return c;
}
export class RuntimeIntegrity {
  constructor(fabric) { this.f = fabric; this.path = join(fabric.directory, 'config.json'); this.hasFile = existsSync(this.path); this.accepted = new Map(); this.withdrawn = new Set(); }
  check(tenant) {
    const f = this.f, now = f.clock(), snapshot = f.tenant(tenant).runtime_snapshot;
    try {
      const fingerprint = digest(snapshot), prior = this.accepted.get(tenant);
      requireThat(!this.withdrawn.has(tenant), 'INV-503-CONFIG', 'Gate authority withdrawn; signed reload required', 503);
      const signerState = snapshot.signatures.map(e => { const id = e.protected.key_id, who = f.tenant(tenant).identities[id]; return { id, identity: who ?? null, revoked: f.revoked(tenant, 'key', id) || (who ? f.revoked(tenant, 'subject', who.subject_id) : true) }; });
      const signersDigest = JSON.stringify(signerState);
      requireThat(signerState.every(s => !s.revoked), 'INV-503-CONFIG', 'Runtime configuration signer revoked', 503);
      if (this.hasFile && (!prior || now >= prior.next_check)) {
        const disk = JSON.parse(readFileSync(this.path, 'utf8'));
        requireThat(digest(disk.tenants[tenant].runtime_snapshot) === fingerprint, 'INV-503-CONFIG', 'On-disk runtime configuration differs from accepted authority', 503);
      }
      if (prior?.digest === fingerprint && prior.signers === signersDigest && now < snapshot.config.expires_at) { if (now >= prior.next_check) prior.next_check = now + snapshot.config.reload_interval_ms; return snapshot.config; }
      const config = verifyRuntimeConfiguration(snapshot, f.identities(tenant), tenant, f.config.gate_id, now);
      requireThat(!prior || config.version >= prior.version, 'INV-503-CONFIG', 'Runtime configuration rollback rejected', 503);
      if (prior && prior.digest !== fingerprint) requireThat(config.version > prior.version, 'INV-503-CONFIG', 'Configuration must advance a version', 503);
      this.accepted.set(tenant, { digest: fingerprint, version: config.version, next_check: now + config.reload_interval_ms, signers: signersDigest }); return config;
    } catch (e) {
      if (!this.withdrawn.has(tenant)) { this.withdrawn.add(tenant); f.store.tx(() => f.store.audit(tenant, 'RUNTIME_AUTHORITY_WITHDRAWN', 'integrity-monitor', f.config.gate_id, { reason: 'CONFIGURATION_INTEGRITY' }, now)); }
      throw e;
    }
  }
  reload(principal, snapshot) {
    this.f.authorize(principal, ['security']);
    const t = principal.tenant_id, config = verifyRuntimeConfiguration(snapshot, this.f.identities(t), t, this.f.config.gate_id, this.f.clock());
    requireThat(config.version > (this.accepted.get(t)?.version ?? 0), 'INV-503-CONFIG', 'Signed reload must advance version', 503);
    if (this.hasFile) {
      const disk = JSON.parse(readFileSync(this.path, 'utf8')); disk.tenants[t].runtime_snapshot = clone(snapshot);
      const staged = `${this.path}.reload-${crypto.randomUUID()}`; writeFileSync(staged, JSON.stringify(disk), { mode: 0o600, flag: 'wx' }); renameSync(staged, this.path);
    }
    this.f.tenant(t).runtime_snapshot = clone(snapshot); this.withdrawn.delete(t);
    const value = this.check(t);
    this.f.store.tx(() => this.f.store.audit(t, 'RUNTIME_CONFIGURATION_RELOADED', principal.subject_id, this.f.config.gate_id, { version: config.version, config_digest: digest(config) }, this.f.clock()));
    return value;
  }
}
