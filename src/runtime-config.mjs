import { existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { digest, clone, parseStrict } from './canonical.mjs';
import { verifySigned, signed } from './crypto.mjs';
import { fields, integer, oneOf } from './schema.mjs';
import { requireThat } from './errors.mjs';

export function runtimeConfiguration(tenant, gate, now, endpointAttestors = []) {
  return {
    format: 'IF-RUNTIME-CONFIG-1', tenant_id: tenant, gate_id: gate, version: 1, issued_at: now, expires_at: now + 7 * 86400000,
    failure_policies: { 'data.read': 'fail-closed', 'service.connect': 'fail-closed' }, cache_entries: 256,
    control_rate_per_second: 30, revocation_slo_ms: 1000, reload_interval_ms: 1000, endpoint_health_slo_ms: 5000, endpoint_attestors: endpointAttestors,
    remediation_services: ['security-remediation'], environment: 'simulation'
  };
}
export function signRuntimeConfiguration(config, custodians) { return { config: clone(config), signatures: custodians.map(k => signed(config, k, 'runtime-config')) }; }
export function verifyRuntimeConfiguration(snapshot, identities, tenant, gate, now) {
  requireThat(snapshot && Array.isArray(snapshot.signatures) && snapshot.signatures.length >= 3 && snapshot.signatures.length <= 16, 'INV-503-CONFIG', 'Signed runtime configuration required', 503);
  const c = snapshot.config;
  fields(c, ['format', 'tenant_id', 'gate_id', 'version', 'issued_at', 'expires_at', 'failure_policies', 'cache_entries', 'control_rate_per_second', 'revocation_slo_ms', 'reload_interval_ms', 'endpoint_health_slo_ms', 'endpoint_attestors', 'remediation_services', 'environment']);
  requireThat(c.format === 'IF-RUNTIME-CONFIG-1' && c.tenant_id === tenant && c.gate_id === gate && c.issued_at <= now && c.expires_at > now, 'INV-503-CONFIG', 'Runtime configuration scope or validity failed', 503);
  integer(c.version, 'configuration version', 1); integer(c.cache_entries, 'cache entries', 1, 4096); integer(c.control_rate_per_second, 'control rate', 1, 10000); integer(c.revocation_slo_ms, 'revocation SLO', 1, 60000); integer(c.reload_interval_ms, 'reload interval', 100, 60000); integer(c.endpoint_health_slo_ms, 'endpoint health SLO', 100, 60000);
  fields(c.failure_policies, ['data.read', 'service.connect']);
  for (const [action, mode] of Object.entries(c.failure_policies)) oneOf(mode, ['cached-allow', 'fail-closed', 'constrained-open'], `${action} failure policy`);
  requireThat(c.environment === 'simulation' && Array.isArray(c.endpoint_attestors) && c.endpoint_attestors.length > 0 && c.endpoint_attestors.length <= 8 && new Set(c.endpoint_attestors).size === c.endpoint_attestors.length && c.endpoint_attestors.every(x => typeof x === 'string' && Object.hasOwn(identities, x)) && Array.isArray(c.remediation_services) && c.remediation_services.length <= 8 && c.remediation_services.every(x => typeof x === 'string' && /^[a-z][a-z0-9-]*$/.test(x)), 'INV-503-CONFIG', 'Invalid endpoint attestors, runtime environment or remediation set', 503);
  const signers = new Set(), domains = new Set();
  for (const envelope of snapshot.signatures) {
    const p = verifySigned(envelope, identities, 'runtime-config'), who = identities[envelope.protected.key_id];
    requireThat(who.roles.includes('custodian') && digest(p) === digest(c), 'INV-503-CONFIG', 'Configuration requires exact customer approval', 503);
    signers.add(envelope.protected.key_id); domains.add(who.failure_domain);
  }
  requireThat(signers.size === snapshot.signatures.length && signers.size >= 3 && domains.size >= 3, 'INV-503-CONFIG', 'Configuration requires independent customer quorum', 503);
  return c;
}
export class RuntimeIntegrity {
  constructor(fabric) { this.f = fabric; this.path = join(fabric.directory, 'config.json'); this.hasFile = existsSync(this.path); this.accepted = new Map(); this.withdrawn = new Set(); }
  persisted(tenant) {
    const state = this.f.store.get(tenant, 'runtime-config-state', 'active');
    if (state?.status === 'WITHDRAWN') this.withdrawn.add(tenant);
    return state;
  }
  remember(tenant, snapshot, config, signerDigest, now) {
    const state = { status: 'ACCEPTED', version: config.version, snapshot_digest: digest(snapshot), signer_digest: signerDigest, accepted_at: now };
    this.accepted.set(tenant, { digest: state.snapshot_digest, version: state.version, next_check: now + config.reload_interval_ms, signers: signerDigest });
    this.f.store.tx(() => this.f.store.put(tenant, 'runtime-config-state', 'active', state, now));
    return config;
  }
  withdraw(tenant, now) {
    const previous = this.f.store.get(tenant, 'runtime-config-state', 'active');
    if (this.withdrawn.has(tenant) || previous?.status === 'WITHDRAWN') { this.withdrawn.add(tenant); return; }
    this.withdrawn.add(tenant);
    this.f.store.tx(() => {
      this.f.store.put(tenant, 'runtime-config-state', 'active', { status: 'WITHDRAWN', prior_version: previous?.version ?? null, withdrawn_at: now, reason: 'CONFIGURATION_INTEGRITY' }, now);
      this.f.store.audit(tenant, 'RUNTIME_AUTHORITY_WITHDRAWN', 'integrity-monitor', this.f.config.gate_id, { reason: 'CONFIGURATION_INTEGRITY' }, now);
    });
  }
  check(tenant) {
    const f = this.f, now = f.clock(), snapshot = f.tenant(tenant).runtime_snapshot;
    try {
      const fingerprint = digest(snapshot), persisted = this.persisted(tenant), prior = this.accepted.get(tenant) ?? (persisted?.status === 'ACCEPTED' ? { digest: persisted.snapshot_digest, version: persisted.version, signers: persisted.signer_digest, next_check: 0 } : null);
      requireThat(!this.withdrawn.has(tenant), 'INV-503-CONFIG', 'Gate authority withdrawn; signed reload required', 503);
      const signerState = snapshot.signatures.map(e => { const id = e.protected.key_id, who = f.tenant(tenant).identities[id]; return { id, identity: who ?? null, revoked: f.revoked(tenant, 'key', id) || (who ? f.revoked(tenant, 'subject', who.subject_id) : true) }; });
      const signersDigest = JSON.stringify(signerState);
      requireThat(signerState.every(s => !s.revoked), 'INV-503-CONFIG', 'Runtime configuration signer revoked', 503);
      if (this.hasFile && (!prior || now >= prior.next_check)) {
        const disk = parseStrict(readFileSync(this.path, 'utf8'));
        requireThat(disk.tenants && disk.tenants[tenant], 'INV-503-CONFIG', 'On-disk runtime tenant configuration is missing', 503);
        requireThat(digest(disk.tenants[tenant].runtime_snapshot) === fingerprint, 'INV-503-CONFIG', 'On-disk runtime configuration differs from accepted authority', 503);
      }
      if (prior?.digest === fingerprint && prior.signers === signersDigest && now < snapshot.config.expires_at) { if (now >= prior.next_check) prior.next_check = now + snapshot.config.reload_interval_ms; return snapshot.config; }
      const config = verifyRuntimeConfiguration(snapshot, f.identities(tenant), tenant, f.config.gate_id, now);
      requireThat(!prior || config.version >= prior.version, 'INV-503-CONFIG', 'Runtime configuration rollback rejected', 503);
      if (prior && prior.digest !== fingerprint) requireThat(config.version > prior.version, 'INV-503-CONFIG', 'Configuration must advance a version', 503);
      return this.remember(tenant, snapshot, config, signersDigest, now);
    } catch (e) {
      this.withdraw(tenant, now);
      if (e?.code === 'INV-503-CONFIG') throw e;
      requireThat(false, 'INV-503-CONFIG', 'Runtime configuration integrity verification failed', 503);
    }
  }
  reload(principal, snapshot) {
    this.f.authorize(principal, ['security']);
    const t = principal.tenant_id, now = this.f.clock(), config = verifyRuntimeConfiguration(snapshot, this.f.identities(t), t, this.f.config.gate_id, now), persisted = this.persisted(t), prior = this.accepted.get(t) ?? persisted;
    requireThat(config.version > (prior?.version ?? prior?.prior_version ?? 0), 'INV-503-CONFIG', 'Signed reload must advance version', 503);
    if (this.hasFile) {
      const disk = parseStrict(readFileSync(this.path, 'utf8')); requireThat(disk.tenants && disk.tenants[t], 'INV-503-CONFIG', 'On-disk runtime tenant configuration is missing', 503); disk.tenants[t].runtime_snapshot = clone(snapshot);
      const staged = `${this.path}.reload-${randomUUID()}`; writeFileSync(staged, JSON.stringify(disk), { mode: 0o600, flag: 'wx' }); renameSync(staged, this.path);
    }
    const signerState = snapshot.signatures.map(e => ({ id: e.protected.key_id, identity: this.f.tenant(t).identities[e.protected.key_id] ?? null, revoked: false }));
    const signerDigest = JSON.stringify(signerState);
    this.f.tenant(t).runtime_snapshot = clone(snapshot); this.withdrawn.delete(t); this.remember(t, snapshot, config, signerDigest, now);
    this.f.store.tx(() => this.f.store.audit(t, 'RUNTIME_CONFIGURATION_RELOADED', principal.subject_id, this.f.config.gate_id, { version: config.version, config_digest: digest(config) }, now));
    return config;
  }
}
