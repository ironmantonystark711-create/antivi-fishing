import { performance } from 'node:perf_hooks';
import { cpus, totalmem, platform, arch } from 'node:os';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fixture, runtimeInput, runtimeRequest } from '../tests/helpers.mjs';
import { evaluatePolicy } from '../src/policy.mjs';
import { LocalNetworkGate } from '../src/network.mjs';
const h = fixture(null, ['acme']);
const percentile = (values, q) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * q))];
function summary(values, elapsed, errors = 0) { return { samples: values.length, errors, p50_ms: percentile(values, .5), p95_ms: percentile(values, .95), p99_ms: percentile(values, .99), operations_per_second: values.length * 1000 / elapsed }; }
try {
  const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r);
  const stored = h.f.getCapsule(h.p(), r.capsule.capsule_id), graph = h.f.graph('acme', stored), policy = h.f.policy('acme'), identities = h.f.identities('acme');
  const input = { capsule: stored.capsule, policy, evidence: graph.items, approvals: stored.approvals.map(a => a.payload), identities, now: h.now() };
  const raw = [], integrated = [], auditedRuntime = [], cachedRuntime = []; let start = performance.now();
  for (let i = 0; i < 2000; i++) { const at = performance.now(); const out = evaluatePolicy(input); if (out.decision !== 'ALLOW') throw new Error('Policy unexpectedly denied'); raw.push(performance.now() - at); }
  const core = summary(raw, performance.now() - start); start = performance.now();
  for (let i = 0; i < 500; i++) { const at = performance.now(); const out = h.f.evaluate(h.p(), r.capsule.capsule_id); if (out.decision !== 'ALLOW') throw new Error('Integrated policy failed'); integrated.push(performance.now() - at); }
  const control = summary(integrated, performance.now() - start);
  let cap;
  start = performance.now();
  for (let i = 0; i < 500; i++) { if (i % 50 === 0) { h.advance(60001); cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [], max_cost: 10000 })); } h.advance(101); const at = performance.now(); h.f.runtime.consume(h.p(), runtimeRequest(cap)); auditedRuntime.push(performance.now() - at); }
  const audited = summary(auditedRuntime, performance.now() - start);
  const runtimePolicy = h.f.policy('acme'); runtimePolicy.runtime.rate_per_second = 10000; runtimePolicy.runtime.windows = [{ duration_ms: 2592000000, limit: 1000000 }]; h.f.store.put('acme', 'policy', 'active', runtimePolicy, h.now());
  const localCapability = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [], max_cost: 10000 }));
  const audit = h.f.keys('acme').audit;
  const gate = new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), configurationKeys: h.f.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, clock: h.now, maxEntries: 256, policyDigest: localCapability.payload.policy_digest, snapshot: h.setup.config.tenants.acme.runtime_snapshot });
  gate.register('erp-service', () => ({ accepted: true })); gate.importCapability(localCapability); start = performance.now();
  for (let i = 0; i < 5000; i++) { const at = performance.now(), result = gate.send({ capability_id: localCapability.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: `bench-${i}` }, { request: 'synthetic' }); if (result.decision !== 'ALLOW') throw new Error(`Cached runtime denied: ${result.code}`); cachedRuntime.push(performance.now() - at); }
  const local = summary(cachedRuntime, performance.now() - start);
  const connector = { status: process.env.IF_BENCHMARK_CONNECTOR_URL ? 'NOT_IMPLEMENTED' : 'NOT_CONFIGURED', samples: 0, reason: process.env.IF_BENCHMARK_CONNECTOR_URL ? 'External connector benchmark requires an explicit connector adapter; no arbitrary URL requests are performed.' : 'No external connector is configured; core and local-runtime latency are reported separately.' };
  const result = { reference_environment: { node: process.version, os: platform(), architecture: arch(), cpu: cpus()[0]?.model ?? 'unknown', logical_cpus: cpus().length, memory_bytes: totalmem(), isolated_environment: true }, benchmark_command: 'node scripts/benchmark.mjs', core_deterministic_evaluation: core, protected_action_evaluation_with_sqlite_audit: control, runtime_authorization_with_signed_audit: audited, cached_local_runtime_dataplane: local, external_connector_latency: connector, targets: { core_p95_at_most_250_ms: core.p95_ms <= 250, core_p99_at_most_750_ms: core.p99_ms <= 750, protected_action_100_evaluations_per_second: control.operations_per_second >= 100 && control.errors === 0, cached_runtime_p99_at_most_1_ms: local.p99_ms <= 1 && local.errors === 0 }, production_capacity_claim: false, caveat: 'Single-node warm-process benchmark using synthetic data and a virtual policy clock. It measures deterministic core, protected SQLite/audit, and cached local dataplane paths separately; it is not production load, soak, packet enforcement, multi-zone, or external connector evidence.' };
  mkdirSync('reports', { recursive: true }); writeFileSync('reports/benchmark.json', JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
} finally { h.close(); rmSync(h.directory, { recursive: true }); }
