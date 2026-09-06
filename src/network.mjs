import { verifySigned } from './crypto.mjs';
import { digest, clone, canonical } from './canonical.mjs';
import { requireThat } from './errors.mjs';
import { verifyRuntimeConfiguration } from './runtime-config.mjs';

// A deterministic process-level network simulator, not a kernel packet filter.
// Only explicitly registered service handlers can receive a request. No sockets, DNS or arbitrary URLs.
export class LocalNetworkGate {
  #capabilities = new Map(); #capabilitySigners = new Map(); #routes = new Map(); #revoked = new Set(); #revokedSubjects = new Set(); #revokedKeys = new Set(); #configSigners = new Set(); #quarantined = new Set(); #usage = new Map(); #config; #configDigest; #configVersionFloor = 0; #controlCalls = [];
  constructor({ tenant, gate, publicKeys, configurationKeys, revocationKeys, clock = Date.now, maxEntries = 256, policyDigest, snapshot }) {
    requireThat(Number.isInteger(maxEntries) && maxEntries > 0 && maxEntries <= 4096, 'INV-400-SCHEMA', 'Invalid network cache bound');
    requireThat(configurationKeys && typeof configurationKeys === 'object' && !Array.isArray(configurationKeys) && revocationKeys && typeof revocationKeys === 'object' && !Array.isArray(revocationKeys) && typeof policyDigest === 'string' && /^[a-f0-9]{64}$/.test(policyDigest), 'INV-503-CONFIG', 'Signed network gate configuration and policy binding are required', 503);
    this.tenant = tenant; this.gate = gate; this.keys = publicKeys; this.configurationKeys = configurationKeys; this.revocationKeys = revocationKeys; this.clock = clock; this.maxEntries = maxEntries; this.policyDigest = policyDigest; this.counters = {}; this.events = [];
    this.#installConfiguration(snapshot, false);
    this.maxEntries = Math.min(this.maxEntries, this.#config.cache_entries);
  }
  #control() {
    const now = this.clock(), cutoff = now - 1000; this.#controlCalls = this.#controlCalls.filter(at => at > cutoff);
    requireThat(this.#controlCalls.length < (this.#config?.control_rate_per_second ?? 1), 'INV-429-RATE', 'Network gate control rate exceeded', 429);
    this.#controlCalls.push(now);
  }
  #installConfiguration(snapshot, requireAdvance) {
    const config = verifyRuntimeConfiguration(snapshot, this.configurationKeys, this.tenant, this.gate, this.clock()), fingerprint = digest(snapshot);
    requireThat(!requireAdvance || config.version > this.#configVersionFloor, 'INV-503-CONFIG', 'Network configuration rollback rejected', 503);
    requireThat(!requireAdvance || fingerprint !== this.#configDigest, 'INV-503-CONFIG', 'Network configuration must advance authority', 503);
    this.#config = clone(config); this.#configDigest = fingerprint; this.#configVersionFloor = config.version; this.#configSigners = new Set(snapshot.signatures.map(s => s.protected.key_id));
  }
  register(service, handler) { requireThat(/^[a-z][a-z0-9-]{0,63}$/.test(service) && typeof handler === 'function' && !this.#routes.has(service), 'INV-400-SCHEMA', 'Exact unique local service required'); this.#routes.set(service, handler); }
  reload(snapshot) { this.#control(); this.#installConfiguration(snapshot, true); this.maxEntries = Math.min(this.maxEntries, this.#config.cache_entries); this.events.push({ type: 'CONFIGURATION_RELOADED', version: this.#config.version, time: this.clock() }); }
  importCapability(envelope) {
    this.#control();
    const cap = verifySigned(envelope, this.keys, 'capability'), now = this.clock();
    requireThat(cap.tenant_id === this.tenant && cap.gate_id === this.gate && cap.action === 'service.connect' && cap.destination === cap.resource && cap.runtime_policy.services.includes(cap.resource) && cap.expires_at > now && cap.policy_digest === this.policyDigest, 'INV-403-SCOPE', 'Network capability scope denied', 403);
    for (const [id, c] of this.#capabilities) if (c.expires_at <= now) { this.#capabilities.delete(id); this.#capabilitySigners.delete(id); }
    requireThat(this.#capabilities.size < this.maxEntries || this.#capabilities.has(cap.capability_id), 'INV-429-CACHE', 'Network decision cache full; no critical entries evicted', 429);
    const present = this.#capabilities.get(cap.capability_id);
    requireThat(!present || digest(present) === digest(cap), 'INV-409-STATE', 'Capability identity cannot be rebound', 409);
    requireThat(!this.#revokedKeys.has(envelope.protected.key_id), 'INV-401-CAPABILITY', 'Capability signing key is revoked', 401);
    this.#capabilities.set(cap.capability_id, clone(cap)); this.#capabilitySigners.set(cap.capability_id, envelope.protected.key_id); return cap.capability_id;
  }
  revoke(envelope) {
    this.#control();
    const revocation = verifySigned(envelope, this.revocationKeys, 'revocation');
    requireThat(revocation.tenant_id === this.tenant && ['capability', 'subject', 'key'].includes(revocation.kind) && typeof revocation.id === 'string' && Number.isSafeInteger(revocation.revoked_at) && revocation.revoked_at <= this.clock(), 'INV-403-SCOPE', 'Network revocation scope denied', 403);
    const propagation = this.clock() - revocation.revoked_at, revocationSlo = this.#config?.revocation_slo_ms ?? 0;
    if (revocation.kind === 'capability') this.#revoked.add(revocation.id);
    if (revocation.kind === 'subject') this.#revokedSubjects.add(revocation.id);
    if (revocation.kind === 'key') { this.#revokedKeys.add(revocation.id); if (this.#configSigners.has(revocation.id)) this.withdraw(); }
    this.events.push({ type: 'REVOKED', kind: revocation.kind, reference: revocation.id, time: this.clock(), propagation_ms: propagation });
    requireThat(propagation <= revocationSlo, 'INV-503-GATE', 'Revocation propagation SLO exceeded', 503);
  }
  quarantine(device, reason = 'HEALTH_LOST') { this.#quarantined.add(device); this.events.push({ type: 'QUARANTINE', device_id: device, reason, time: this.clock() }); }
  withdraw() { this.#config = null; }
  decide(request) {
    const now = this.clock(), cap = request && this.#capabilities.get(request.capability_id);
    const reject = code => { this.counters[code] = (this.counters[code] ?? 0) + 1; return { decision: 'DENY', code, simulation: true }; };
    if (!this.#config || this.#config.expires_at <= now) return reject('INV-503-CONFIG');
    if (!request || Object.getPrototypeOf(request) !== Object.prototype || Object.keys(request).sort().join() !== 'capability_id,destination,device_id,port,protocol,request_id,subject_id,tenant_id' || !cap || cap.tenant_id !== request.tenant_id || cap.subject_id !== request.subject_id || cap.device_id !== request.device_id || cap.destination !== request.destination || request.protocol !== 'https' || request.port !== 443 || !this.#routes.has(request.destination)) return reject('INV-403-SCOPE');
    if (this.#quarantined.has(request.device_id) || this.#revokedSubjects.has(request.subject_id)) return reject('INV-403-QUARANTINE');
    if (this.#revoked.has(cap.capability_id) || this.#revokedKeys.has(this.#capabilitySigners.get(cap.capability_id)) || cap.expires_at <= now || cap.issued_at > now || cap.policy_digest !== this.policyDigest) return reject('INV-401-CAPABILITY');
    if (typeof request.request_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(request.request_id)) return reject('INV-400-SCHEMA');
    const id = `${request.subject_id}:${request.device_id}`;
    if (!this.#usage.has(id) && this.#usage.size >= this.maxEntries) return reject('INV-429-CAPACITY');
    const usage = this.#usage.get(id) ?? { last: now, calls: [], seen: new Set(), capCosts: new Map() };
    if (now < usage.last) return reject('INV-503-TIME');
    if (usage.seen.has(request.request_id)) return reject('INV-409-REPLAY');
    const r = cap.runtime_policy, cutoff = now - Math.max(...r.windows.map(w => w.duration_ms));
    usage.calls = usage.calls.filter(c => c.at > cutoff);
    if (usage.calls.length >= 10000 || usage.seen.size >= 10000) return reject('INV-429-CAPACITY');
    if ((usage.capCosts.get(cap.capability_id) ?? 0) >= cap.max_cost) return reject('INV-429-BUDGET');
    const recent = usage.calls.filter(c => c.at > now - 1000);
    if (recent.length >= r.rate_per_second) return reject('INV-429-RATE');
    const fanout = new Set(recent.map(c => c.destination));
    if (!fanout.has(cap.destination) && fanout.size >= r.max_fanout) return reject('INV-429-FANOUT');
    for (const w of r.windows) if (usage.calls.filter(c => c.at > now - w.duration_ms).length >= w.limit) return reject('INV-429-BUDGET');
    usage.last = now; usage.calls.push({ at: now, destination: cap.destination }); usage.seen.add(request.request_id); usage.capCosts.set(cap.capability_id, (usage.capCosts.get(cap.capability_id) ?? 0) + 1); this.#usage.set(id, usage);
    this.counters.ALLOW = (this.counters.ALLOW ?? 0) + 1; return { decision: 'ALLOW', code: 'ENVELOPE_SATISFIED', simulation: true };
  }
  send(request, payload) {
    requireThat(Buffer.byteLength(canonical(payload)) <= 16384, 'INV-413-BODY', 'Network simulator payload bound exceeded', 413);
    const decision = this.decide(request); if (decision.decision !== 'ALLOW') return decision;
    try { return { ...decision, response: this.#routes.get(request.destination)(clone(payload)) }; }
    catch { this.counters['INV-503-GATE'] = (this.counters['INV-503-GATE'] ?? 0) + 1; return { decision: 'DENY', code: 'INV-503-GATE', simulation: true }; }
  }
  report() { return { format: 'IF-CONTAINMENT-1', tenant_id: this.tenant, counters: { ...this.counters }, events: clone(this.events), cached_capabilities: this.#capabilities.size, configuration_digest: this.#configDigest ?? null, packet_enforcement: false }; }
}
