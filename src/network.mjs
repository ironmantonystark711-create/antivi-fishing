import { verifySigned } from './crypto.mjs';
import { digest, clone, canonical } from './canonical.mjs';
import { requireThat } from './errors.mjs';
import { verifyRuntimeConfiguration } from './runtime-config.mjs';
import { fields, identifier, integer, oneOf } from './schema.mjs';

// This is a bounded policy gate; network-proxy.mjs supplies real local HTTP mediation.
export class LocalNetworkGate {
  #capabilities = new Map(); #capabilitySigners = new Map(); #routes = new Map(); #revoked = new Set(); #revokedSubjects = new Set(); #revokedKeys = new Set(); #configSigners = new Set(); #quarantined = new Set(); #health = new Map(); #containment = new Map(); #usage = new Map(); #config; #configDigest; #configVersionFloor = 0; #controlCalls = []; #revocationCursor = 0; #nextUsagePrune = 0;
  constructor({ tenant, gate, publicKeys, configurationKeys, revocationKeys, clock = Date.now, maxEntries = 256, policyDigest, snapshot }) {
    requireThat(Number.isInteger(maxEntries) && maxEntries > 0 && maxEntries <= 4096, 'INV-400-SCHEMA', 'Invalid network cache bound');
    requireThat(configurationKeys && typeof configurationKeys === 'object' && !Array.isArray(configurationKeys) && revocationKeys && typeof revocationKeys === 'object' && !Array.isArray(revocationKeys) && typeof policyDigest === 'string' && /^[a-f0-9]{64}$/.test(policyDigest), 'INV-503-CONFIG', 'Signed network gate configuration and policy binding are required', 503);
    this.tenant = tenant; this.gate = gate; this.keys = publicKeys; this.configurationKeys = configurationKeys; this.revocationKeys = revocationKeys; this.clock = clock; this.maxEntries = maxEntries; this.policyDigest = policyDigest; this.counters = {}; this.events = [];
    this.#installConfiguration(snapshot, false); this.maxEntries = Math.min(this.maxEntries, this.#config.cache_entries);
  }
  #record(event) {
    const capacity = Math.max(64, Math.min(4096, this.maxEntries * 4));
    if (this.events.length >= capacity) { this.events.shift(); this.counters.EVENT_RETENTION_DROPPED = (this.counters.EVENT_RETENTION_DROPPED ?? 0) + 1; }
    this.events.push(event);
  }
  #control() {
    const now = this.clock(), cutoff = now - 1000; this.#controlCalls = this.#controlCalls.filter(at => at > cutoff);
    requireThat(this.#controlCalls.length < (this.#config?.control_rate_per_second ?? 1), 'INV-429-RATE', 'Network gate control rate exceeded', 429);
    this.#controlCalls.push(now);
  }
  #reject(code) { this.counters[code] = (this.counters[code] ?? 0) + 1; return { decision: 'DENY', code, simulation: true }; }
  #installConfiguration(snapshot, requireAdvance) {
    const config = verifyRuntimeConfiguration(snapshot, this.configurationKeys, this.tenant, this.gate, this.clock()), fingerprint = digest(snapshot);
    requireThat(!requireAdvance || config.version > this.#configVersionFloor, 'INV-503-CONFIG', 'Network configuration rollback rejected', 503);
    requireThat(!requireAdvance || fingerprint !== this.#configDigest, 'INV-503-CONFIG', 'Network configuration must advance authority', 503);
    this.#config = clone(config); this.#configDigest = fingerprint; this.#configVersionFloor = config.version; this.#configSigners = new Set(snapshot.signatures.map(s => s.protected.key_id));
  }
  #pruneUsage(now) {
    for (const [id, usage] of this.#usage) {
      usage.calls = usage.calls.filter(c => c.at > now - 2592000000);
      for (const queue of usage.windows.values()) {
        while (queue.head < queue.items.length && queue.items[queue.head].at <= now - queue.duration_ms) { const destination = queue.items[queue.head++].destination, count = queue.destinations.get(destination) - 1; if (count) queue.destinations.set(destination, count); else queue.destinations.delete(destination); }
        if (queue.head * 2 >= queue.items.length) { queue.items = queue.items.slice(queue.head); queue.head = 0; }
      }
      for (const [requestId, expiresAt] of usage.seen) if (expiresAt <= now) usage.seen.delete(requestId);
      for (const [capabilityId, value] of usage.capCosts) if (value.expires_at <= now || !this.#capabilities.has(capabilityId)) usage.capCosts.delete(capabilityId);
      if (!usage.calls.length && !usage.seen.size && !usage.capCosts.size) this.#usage.delete(id);
    }
  }
  #window(usage, durationMs, now) {
    let queue = usage.windows.get(durationMs);
    if (!queue) { const items = usage.calls.filter(c => c.at > now - durationMs), destinations = new Map(); for (const item of items) destinations.set(item.destination, (destinations.get(item.destination) ?? 0) + 1); queue = { duration_ms: durationMs, items, head: 0, destinations }; usage.windows.set(durationMs, queue); }
    while (queue.head < queue.items.length && queue.items[queue.head].at <= now - durationMs) { const destination = queue.items[queue.head++].destination, count = queue.destinations.get(destination) - 1; if (count) queue.destinations.set(destination, count); else queue.destinations.delete(destination); }
    if (queue.head * 2 >= queue.items.length) { queue.items = queue.items.slice(queue.head); queue.head = 0; }
    return queue;
  }
  #ensureRevocationCapacity(set, id) {
    if (set.has(id)) return;
    if (set.size >= this.maxEntries) { this.withdraw(); requireThat(false, 'INV-503-GATE', 'Network revocation capacity exhausted', 503); }
    set.add(id);
  }
  #healthRequired(device, now) {
    const health = this.#health.get(device);
    if (health?.expires_at > now) return false;
    this.quarantine(device, 'HEALTH_ATTESTATION_EXPIRED'); return true;
  }
  register(service, handler) {
    this.#control();
    requireThat(/^[a-z][a-z0-9-]{0,63}$/.test(service) && typeof handler === 'function' && !this.#routes.has(service) && this.#routes.size < 64, 'INV-400-SCHEMA', 'Exact unique local service required'); this.#routes.set(service, handler);
  }
  reload(snapshot) { this.#control(); this.#installConfiguration(snapshot, true); this.maxEntries = Math.min(this.maxEntries, this.#config.cache_entries); this.#record({ type: 'CONFIGURATION_RELOADED', version: this.#config.version, time: this.clock() }); }
  importCapability(envelope) {
    this.#control();
    const cap = verifySigned(envelope, this.keys, 'capability'), now = this.clock();
    requireThat(cap.tenant_id === this.tenant && cap.gate_id === this.gate && cap.action === 'service.connect' && cap.destination === cap.resource && cap.runtime_policy.services.includes(cap.resource) && cap.expires_at > now && cap.policy_digest === this.policyDigest && cap.resource_state && Number.isSafeInteger(cap.resource_state.version) && /^[a-f0-9]{64}$/.test(cap.resource_state.digest), 'INV-403-SCOPE', 'Network capability scope denied', 403);
    for (const [id, c] of this.#capabilities) if (c.expires_at <= now) { this.#capabilities.delete(id); this.#capabilitySigners.delete(id); }
    this.#pruneUsage(now);
    requireThat(this.#capabilities.size < this.maxEntries || this.#capabilities.has(cap.capability_id), 'INV-429-CACHE', 'Network decision cache full; no critical entries evicted', 429);
    const present = this.#capabilities.get(cap.capability_id);
    requireThat(!present || digest(present) === digest(cap), 'INV-409-STATE', 'Capability identity cannot be rebound', 409);
    requireThat(!this.#revokedKeys.has(envelope.protected.key_id), 'INV-401-CAPABILITY', 'Capability signing key is revoked', 401);
    this.#capabilities.set(cap.capability_id, clone(cap)); this.#capabilitySigners.set(cap.capability_id, envelope.protected.key_id); return cap.capability_id;
  }
  #applyRevocation(envelope) {
    const revocation = verifySigned(envelope, this.revocationKeys, 'revocation');
    requireThat(revocation.tenant_id === this.tenant && ['capability', 'subject', 'key'].includes(revocation.kind) && typeof revocation.id === 'string' && Number.isSafeInteger(revocation.revoked_at) && revocation.revoked_at <= this.clock(), 'INV-403-SCOPE', 'Network revocation scope denied', 403);
    const propagation = this.clock() - revocation.revoked_at, revocationSlo = this.#config?.revocation_slo_ms ?? 0;
    if (propagation > revocationSlo) { this.withdraw(); requireThat(false, 'INV-503-GATE', 'Revocation propagation SLO exceeded', 503); }
    if (revocation.kind === 'capability') this.#ensureRevocationCapacity(this.#revoked, revocation.id);
    if (revocation.kind === 'subject') {
      this.#ensureRevocationCapacity(this.#revokedSubjects, revocation.id);
      for (const [device, health] of this.#health) if (this.configurationKeys[health.signer]?.subject_id === revocation.id) this.quarantine(device, 'HEALTH_ATTESTOR_REVOKED');
    }
    if (revocation.kind === 'key') {
      this.#ensureRevocationCapacity(this.#revokedKeys, revocation.id);
      if (this.#configSigners.has(revocation.id)) this.withdraw();
      for (const [device, health] of this.#health) if (health.signer === revocation.id) this.quarantine(device, 'HEALTH_ATTESTOR_REVOKED');
    }
    this.#record({ type: 'REVOKED', kind: revocation.kind, reference: revocation.id, time: this.clock(), propagation_ms: propagation });
  }
  revoke(envelope) { this.#control(); this.#applyRevocation(envelope); }
  syncRevocations(entries, acknowledge = () => {}) {
    this.#control(); requireThat(Array.isArray(entries) && entries.length <= this.maxEntries, 'INV-400-SCHEMA', 'Invalid revocation feed');
    for (const entry of entries) {
      if (!entry || !Number.isSafeInteger(entry.sequence) || entry.sequence !== this.#revocationCursor + 1 || !entry.envelope) { this.withdraw(); requireThat(false, 'INV-503-GATE', 'Revocation feed has a gap or replay', 503); }
      this.#applyRevocation(entry.envelope); this.#revocationCursor = entry.sequence; acknowledge(entry.sequence); this.#record({ type: 'REVOCATION_ACKNOWLEDGED', sequence: entry.sequence, time: this.clock() });
    }
    return this.#revocationCursor;
  }
  reportEndpointHealth(envelope) {
    this.#control(); const report = verifySigned(envelope, this.configurationKeys, 'endpoint-health'), now = this.clock();
    fields(report, ['tenant_id', 'gate_id', 'device_id', 'reported_at', 'expires_at', 'status', 'nonce']); identifier(report.device_id); identifier(report.nonce); integer(report.reported_at, 'health report time', 1); integer(report.expires_at, 'health expiry', report.reported_at + 1); oneOf(report.status, ['HEALTHY'], 'endpoint health status');
    const attestor = this.configurationKeys[envelope.protected.key_id];
    requireThat(this.#config.endpoint_attestors.includes(envelope.protected.key_id) && !this.#revokedKeys.has(envelope.protected.key_id) && !this.#revokedSubjects.has(attestor.subject_id) && report.tenant_id === this.tenant && report.gate_id === this.gate && report.reported_at <= now && now - report.reported_at <= this.#config.endpoint_health_slo_ms && report.expires_at > now && report.expires_at <= report.reported_at + this.#config.endpoint_health_slo_ms, 'INV-403-HEALTH', 'Endpoint health report is stale or out of scope', 403);
    if (!this.#health.has(report.device_id) && this.#health.size >= this.maxEntries) { this.withdraw(); requireThat(false, 'INV-503-GATE', 'Endpoint health capacity exhausted', 503); }
    this.#health.set(report.device_id, { expires_at: report.expires_at, signer: envelope.protected.key_id });
    const containment = this.#containment.get(report.device_id);
    if (containment) { this.#quarantined.delete(report.device_id); this.#containment.delete(report.device_id); this.#record({ type: 'CONTAINMENT_RECOVERED', device_id: report.device_id, time: now, containment_duration_ms: now - containment.started_at, affected_capabilities: containment.affected_capabilities }); }
    else this.#record({ type: 'HEALTH_ATTESTED', device_id: report.device_id, time: now, expires_at: report.expires_at });
  }
  endpointControlLost(device) { this.#control(); identifier(device, 'device'); this.quarantine(device, 'ENDPOINT_CONTROL_LOST'); }
  watchdog() {
    this.#control(); const now = this.clock(), contained = [];
    for (const [device, health] of this.#health) if (health.expires_at <= now && !this.#quarantined.has(device)) { this.quarantine(device, 'HEALTH_ATTESTATION_EXPIRED'); contained.push(device); }
    return contained;
  }
  quarantine(device, reason = 'HEALTH_LOST') {
    if (this.#quarantined.has(device)) return;
    if (this.#quarantined.size >= this.maxEntries || this.#containment.size >= this.maxEntries) { this.withdraw(); requireThat(false, 'INV-503-GATE', 'Containment capacity exhausted', 503); }
    this.#quarantined.add(device); const now = this.clock(), affected_capabilities = [...this.#capabilities.values()].filter(c => c.device_id === device && c.expires_at > now).map(c => c.capability_id); this.#containment.set(device, { started_at: now, affected_capabilities }); this.#record({ type: 'QUARANTINE', device_id: device, reason, time: now, affected_capabilities });
  }
  withdraw() { this.#config = null; }
  #infrastructureFailure(cap) {
    const mode = this.#config.failure_policies[cap.action];
    if (mode === 'cached-allow') return { decision: 'ALLOW', code: 'CACHED_ALLOW', simulation: true, upstream_delivery: 'UNAVAILABLE' };
    if (mode === 'constrained-open' && this.#config.remediation_services.includes(cap.destination)) return { decision: 'ALLOW', code: 'CONSTRAINED_REMEDIATION_ALLOW', simulation: true, upstream_delivery: 'UNAVAILABLE' };
    return this.#reject('INV-503-GATE');
  }
  decide(request) {
    const now = this.clock(), cap = request && this.#capabilities.get(request.capability_id);
    if (!this.#config || this.#config.expires_at <= now) return this.#reject('INV-503-CONFIG');
    if (!request || Object.getPrototypeOf(request) !== Object.prototype || Object.keys(request).sort().join() !== 'capability_id,destination,device_id,port,protocol,request_id,subject_id,tenant_id' || !cap || cap.tenant_id !== request.tenant_id || cap.subject_id !== request.subject_id || cap.device_id !== request.device_id || cap.destination !== request.destination || request.protocol !== 'https' || request.port !== 443 || !this.#routes.has(request.destination)) return this.#reject('INV-403-SCOPE');
    const remediation = this.#config.remediation_services.includes(request.destination), unhealthy = this.#healthRequired(request.device_id, now);
    if (this.#revokedSubjects.has(request.subject_id) || ((unhealthy || this.#quarantined.has(request.device_id)) && !remediation)) return this.#reject('INV-403-QUARANTINE');
    if (this.#revoked.has(cap.capability_id) || this.#revokedKeys.has(this.#capabilitySigners.get(cap.capability_id)) || cap.expires_at <= now || cap.issued_at > now || cap.policy_digest !== this.policyDigest) return this.#reject('INV-401-CAPABILITY');
    if (typeof request.request_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(request.request_id)) return this.#reject('INV-400-SCHEMA');
    if (now >= this.#nextUsagePrune) { this.#pruneUsage(now); this.#nextUsagePrune = now + 1000; }
    const id = `${request.subject_id}:${request.device_id}`;
    if (!this.#usage.has(id) && this.#usage.size >= this.maxEntries) return this.#reject('INV-429-CAPACITY');
    const usage = this.#usage.get(id) ?? { last: now, calls: [], windows: new Map(), seen: new Map(), capCosts: new Map() };
    if (now < usage.last) return this.#reject('INV-503-TIME');
    if (usage.seen.has(request.request_id)) return this.#reject('INV-409-REPLAY');
    const r = cap.runtime_policy;
    if (usage.calls.length >= 10000 || usage.seen.size >= 10000) return this.#reject('INV-429-CAPACITY');
    if ((usage.capCosts.get(cap.capability_id)?.cost ?? 0) >= cap.max_cost) return this.#reject('INV-429-BUDGET');
    const recent = this.#window(usage, 1000, now); if (recent.items.length - recent.head >= r.rate_per_second) return this.#reject('INV-429-RATE');
    if (!recent.destinations.has(cap.destination) && recent.destinations.size >= r.max_fanout) return this.#reject('INV-429-FANOUT');
    for (const w of r.windows) { const window = this.#window(usage, w.duration_ms, now); if (window.items.length - window.head >= w.limit) return this.#reject('INV-429-BUDGET'); }
    const call = { at: now, destination: cap.destination }; usage.last = now; usage.calls.push(call); for (const window of usage.windows.values()) { window.items.push(call); window.destinations.set(call.destination, (window.destinations.get(call.destination) ?? 0) + 1); } usage.seen.set(request.request_id, cap.expires_at); usage.capCosts.set(cap.capability_id, { cost: (usage.capCosts.get(cap.capability_id)?.cost ?? 0) + 1, expires_at: cap.expires_at }); this.#usage.set(id, usage);
    this.counters.ALLOW = (this.counters.ALLOW ?? 0) + 1; return { decision: 'ALLOW', code: 'ENVELOPE_SATISFIED', simulation: true };
  }
  send(request, payload) {
    requireThat(Buffer.byteLength(canonical(payload)) <= 16384, 'INV-413-BODY', 'Network simulator payload bound exceeded', 413);
    const decision = this.decide(request); if (decision.decision !== 'ALLOW') return decision;
    try { return { ...decision, response: this.#routes.get(request.destination)(clone(payload)) }; }
    catch { return this.#infrastructureFailure(this.#capabilities.get(request.capability_id)); }
  }
  infrastructureFailure(request) {
    const cap = request && this.#capabilities.get(request.capability_id);
    return cap ? this.#infrastructureFailure(cap) : this.#reject('INV-503-GATE');
  }
  report() { const now = this.clock(); return { format: 'IF-CONTAINMENT-1', tenant_id: this.tenant, counters: { ...this.counters }, events: clone(this.events), active_containment: [...this.#containment].map(([device_id, state]) => ({ device_id, started_at: state.started_at, containment_duration_ms: now - state.started_at, affected_capabilities: state.affected_capabilities })), cached_capabilities: this.#capabilities.size, configuration_digest: this.#configDigest ?? null, revocation_cursor: this.#revocationCursor, packet_enforcement: false }; }
}
