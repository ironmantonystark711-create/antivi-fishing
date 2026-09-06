import { execFileSync } from 'node:child_process';
import { LocalNetworkGate } from '../src/network.mjs';
import { performance } from 'node:perf_hooks';
import { cpus, totalmem, platform, arch } from 'node:os';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fixture, runtimeInput, runtimeRequest } from '../tests/helpers.mjs';
import { evaluatePolicy } from '../src/policy.mjs';
const h = fixture(null, ['acme']);
const percentile = (values, q) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * q))];
function summary(values, elapsed) { return { samples: values.length, p50_ms: percentile(values, .5), p95_ms: percentile(values, .95), p99_ms: percentile(values, .99), operations_per_second: values.length * 1000 / elapsed }; }
try {
  const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r);
  const stored = h.f.getCapsule(h.p(), r.capsule.capsule_id), graph = h.f.graph('acme', stored), policy = h.f.policy('acme'), identities = h.f.identities('acme');
  const input = { capsule: stored.capsule, policy, evidence: graph.items, approvals: stored.approvals.map(a => a.payload), identities, now: h.now() };
  const raw = [], integrated = [], runtime = []; let start = performance.now();
  for (let i = 0; i < 2000; i++) { const at = performance.now(); const out = evaluatePolicy(input); if (out.decision !== 'ALLOW') throw new Error('Policy unexpectedly denied'); raw.push(performance.now() - at); }
  const core = summary(raw, performance.now() - start); start = performance.now();
  for (let i = 0; i < 500; i++) { const at = performance.now(); const out = h.f.evaluate(h.p(), r.capsule.capsule_id); if (out.decision !== 'ALLOW') throw new Error('Integrated policy failed'); integrated.push(performance.now() - at); }
  const control = summary(integrated, performance.now() - start);
  let cap;
  start = performance.now();
  for (let i = 0; i < 500; i++) { if (i % 50 === 0) { h.advance(60001); cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [], max_cost: 10000 })); } h.advance(101); const at = performance.now(); h.f.runtime.consume(h.p(), runtimeRequest(cap)); runtime.push(performance.now() - at); }
  const local = summary(runtime, performance.now() - start);
  const cacheSamples = []; let cache, capability;
  const cacheStart = performance.now();
  for (let i = 0; i < 2000; i++) {
    if (i > 0 && i % 1000 === 0) h.advance(3600001); // Honor the signed hourly budget without weakening it.
    if (i % 50 === 0) {
      h.advance(60001);
      capability = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [], max_cost: 10000 }));
      if (!cache) { cache = new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), clock: h.now, policyDigest: capability.payload.policy_digest, snapshot: h.setup.config.tenants.acme.runtime_snapshot, configurationIdentities: h.f.identities('acme') }); cache.register('erp-service', () => ({ received: true })); }
      cache.importCapability(capability);
    }
    h.advance(101);
    const request = { capability_id: capability.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: `perf-${i}` };
    const at = performance.now(); const decision = cache.decide(request); cacheSamples.push(performance.now() - at);
    if (decision.decision !== 'ALLOW') throw new Error('Cached runtime failed: ' + decision.code);
  }
  const cached = summary(cacheSamples, performance.now() - cacheStart);
  const result = { revision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), exact_command: 'node scripts/benchmark.mjs', reference_environment: { node: process.version, os: platform(), architecture: arch(), cpu: cpus()[0]?.model ?? 'unknown', logical_cpus: cpus().length, memory_bytes: totalmem(), isolated_environment: true }, core_deterministic_evaluation: core, integrated_evaluation_with_sqlite_audit: control, local_software_runtime_with_signed_audit: local, cached_local_runtime_decision: cached, target_network_latency: 'not measured: no external target connector', targets: { commit_evaluation_p95_at_most_250_ms: control.p95_ms <= 250, commit_evaluation_p99_at_most_750_ms: control.p99_ms <= 750, integrated_100_evaluations_per_second: control.operations_per_second >= 100, cached_runtime_p99_at_most_1_ms: cached.p99_ms <= 1 }, production_capacity_claim: false, caveat: 'Separate cached local decision, persistence/audit, and deterministic core paths; cached throughput includes capability renewal overhead. Single-node microbenchmark, warm process, synthetic data and virtual policy clock advanced to respect budget/rate limits; not a production load, soak, packet or multi-zone benchmark.' };
  mkdirSync('reports', { recursive: true }); writeFileSync('reports/benchmark.json', JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2)); if (Object.values(result.targets).some(pass => !pass)) process.exitCode = 1;
} finally { h.close(); rmSync(h.directory, { recursive: true }); }
