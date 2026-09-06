import { verifySigned } from './crypto.mjs';
import { digest, clone } from './canonical.mjs';
import { requireThat } from './errors.mjs';

// A deterministic process-level network simulator, not a kernel packet filter.
// Only explicitly registered service handlers can receive a request. No sockets, DNS or arbitrary URLs.
export class LocalNetworkGate {
  #capabilities = new Map(); #routes = new Map(); #revoked = new Set(); #quarantined = new Set(); #usage = new Map(); #config;
  constructor({ tenant, gate, publicKeys, clock = Date.now, maxEntries = 256, policyDigest, snapshot }) {
    requireThat(Number.isInteger(maxEntries) && maxEntries > 0 && maxEntries <= 4096, 'INV-400-SCHEMA', 'Invalid network cache bound');
    this.tenant = tenant; this.gate = gate; this.keys = publicKeys; this.clock = clock; this.maxEntries = maxEntries; this.policyDigest = policyDigest; this.#config = clone(snapshot); this.counters = {}; this.events = [];
  }
  register(service, handler) { requireThat(/^[a-z][a-z0-9-]{0,63}$/.test(service) && typeof handler === 'function' && !this.#routes.has(service), 'INV-400-SCHEMA', 'Exact unique local service required'); this.#routes.set(service, handler); }
  importCapability(envelope) {
    const cap = verifySigned(envelope, this.keys, 'capability'), now = this.clock();
    requireThat(cap.tenant_id === this.tenant && cap.gate_id === this.gate && cap.action === 'service.connect' && cap.destination === cap.resource && cap.runtime_policy.services.includes(cap.resource) && cap.expires_at > now && cap.policy_digest === this.policyDigest, 'INV-403-SCOPE', 'Network capability scope denied', 403);
    for (const [id, c] of this.#capabilities) if (c.expires_at <= now) this.#capabilities.delete(id);
    requireThat(this.#capabilities.size < this.maxEntries || this.#capabilities.has(cap.capability_id), 'INV-429-CACHE', 'Network decision cache full; no critical entries evicted', 429);
    const present = this.#capabilities.get(cap.capability_id);
    requireThat(!present || digest(present) === digest(cap), 'INV-409-STATE', 'Capability identity cannot be rebound', 409);
    this.#capabilities.set(cap.capability_id, clone(cap)); return cap.capability_id;
  }
  revoke(id) { this.#revoked.add(id); this.events.push({ type: 'REVOKED', capability_id: id, time: this.clock() }); }
  quarantine(device, reason = 'HEALTH_LOST') { this.#quarantined.add(device); this.events.push({ type: 'QUARANTINE', device_id: device, reason, time: this.clock() }); }
  withdraw() { this.#config = null; }
  decide(request) {
    const now = this.clock(), cap = this.#capabilities.get(request.capability_id);
    const reject = code => { this.counters[code] = (this.counters[code] ?? 0) + 1; return { decision: 'DENY', code, simulation: true }; };
    if (!this.#config || this.#config.expires_at <= now) return reject('INV-503-CONFIG');
    if (!cap || cap.tenant_id !== request.tenant_id || cap.subject_id !== request.subject_id || cap.device_id !== request.device_id || cap.destination !== request.destination || request.protocol !== 'https' || request.port !== 443 || !this.#routes.has(request.destination)) return reject('INV-403-SCOPE');
    if (this.#quarantined.has(request.device_id)) return reject('INV-403-QUARANTINE');
    if (this.#revoked.has(cap.capability_id) || cap.expires_at <= now || cap.issued_at > now || cap.policy_digest !== this.policyDigest) return reject('INV-401-CAPABILITY');
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
    requireThat(Buffer.byteLength(JSON.stringify(payload)) <= 16384, 'INV-413-BODY', 'Network simulator payload bound exceeded', 413);
    const decision = this.decide(request); if (decision.decision !== 'ALLOW') return decision;
    return { ...decision, response: this.#routes.get(request.destination)(clone(payload)) };
  }
  report() { return { format: 'IF-CONTAINMENT-1', tenant_id: this.tenant, counters: { ...this.counters }, events: clone(this.events), cached_capabilities: this.#capabilities.size, packet_enforcement: false }; }
}
