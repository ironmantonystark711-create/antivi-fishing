import { performance } from 'node:perf_hooks';
import { cpus, totalmem, platform, arch } from 'node:os';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fixture, runtimeInput } from '../tests/helpers.mjs';
import { LocalNetworkGate } from '../src/network.mjs';
import { signed } from '../src/crypto.mjs';

const durationTargetMs = Number.parseInt(process.env.IF_RUNTIME_STRESS_MS ?? '60000', 10);
if (!Number.isSafeInteger(durationTargetMs) || durationTargetMs < 1000 || durationTargetMs > 600000) throw new Error('IF_RUNTIME_STRESS_MS must be between 1000 and 600000');
const h = fixture(null, ['acme']);
function health(gate, nonce) {
  gate.reportEndpointHealth(signed({ tenant_id: 'acme', gate_id: h.f.config.gate_id, device_id: 'operator-device', reported_at: h.now(), expires_at: h.now() + 5000, status: 'HEALTHY', nonce }, h.setup.deviceKeys.acme, 'endpoint-health'));
}
try {
  const policy = h.f.policy('acme'); policy.runtime.rate_per_second = 1000000; policy.runtime.max_cost = 1000000000; policy.runtime.windows = [{ duration_ms: 2592000000, limit: 1000000000 }]; h.f.store.put('acme', 'policy', 'active', policy, h.now());
  const issue = () => h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [], max_cost: 10000, ttl_ms: 60000 }));
  const primary = issue(), audit = h.f.keys('acme').audit;
  const gate = new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), configurationKeys: h.f.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, clock: h.now, maxEntries: 64, policyDigest: primary.payload.policy_digest, snapshot: h.setup.config.tenants.acme.runtime_snapshot });
  health(gate, 'stress-health-0'); gate.register('erp-service', () => ({ accepted: true })); gate.importCapability(primary);
  const baselineHeap = process.memoryUsage().heapUsed; let peakHeap = baselineHeap, validAllows = 0, cacheCapacityRejects = 0, expectedDenials = 0, unexpected = 0;
  for (let i = 0; i < 10000; i++) {
    if (i && i % 4000 === 0) health(gate, `stress-health-${i}`);
    const outcome = gate.send({ capability_id: primary.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: `warm-${i}` }, {});
    if (outcome.decision === 'ALLOW') validAllows++; else unexpected++;
  }
  for (let i = 0; i < 96; i++) {
    if (i && i % 25 === 0) { h.advance(1001); health(gate, `stress-churn-health-${i}`); }
    try { gate.importCapability(issue()); } catch (error) { if (error.code === 'INV-429-CACHE') cacheCapacityRejects++; else unexpected++; }
  }
  const started = performance.now(); let attempted = 0;
  while (performance.now() - started < durationTargetMs) {
    for (let i = 0; i < 1000; i++) {
      const result = gate.send({ capability_id: primary.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'peer-workstation', protocol: 'https', port: 443, request_id: `adversarial-${attempted++}` }, {});
      if (result.code === 'INV-403-SCOPE') expectedDenials++; else unexpected++;
    }
    peakHeap = Math.max(peakHeap, process.memoryUsage().heapUsed);
  }
  const elapsedMs = performance.now() - started, report = gate.report();
  const result = { format: 'IF-RUNTIME-STRESS-1', reference_environment: { node: process.version, os: platform(), architecture: arch(), logical_cpus: cpus().length, memory_bytes: totalmem(), isolated_environment: true }, started_at_monotonic_ms: started, requested_duration_ms: durationTargetMs, measured_duration_ms: elapsedMs, valid_allows_before_churn: validAllows, cache_churn_attempts: 96, cache_capacity_rejections: cacheCapacityRejects, adversarial_scope_denials: expectedDenials, unexpected_outcomes: unexpected, heap_baseline_bytes: baselineHeap, heap_peak_bytes: peakHeap, heap_growth_bytes: peakHeap - baselineHeap, containment: report.active_containment, cached_capabilities: report.cached_capabilities, production_capacity_claim: false, caveat: 'Single-process synthetic stress test. It demonstrates bounded local-gate state and stable denial under adversarial requests; it is not a production soak, multi-node, packet-filter, or customer workload claim.' };
  mkdirSync('reports', { recursive: true }); writeFileSync('reports/runtime-stress.json', JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
  if (unexpected || validAllows !== 10000 || cacheCapacityRejects !== 33 || report.cached_capabilities !== 64) process.exitCode = 1;
} finally { h.close(); rmSync(h.directory, { recursive: true }); }
