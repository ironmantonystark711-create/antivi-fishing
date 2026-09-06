import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, hasCode, runtimeInput } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { LocalNetworkGate } from '../src/network.mjs';
import { clone, canonical } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { signRuntimeConfiguration } from '../src/runtime-config.mjs';

function serviceGate(h, maxEntries = 8, handler = payload => ({ payload })) {
  const capability = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  const audit = h.f.keys('acme').audit;
  const gate = new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), configurationKeys: h.f.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, clock: h.now, maxEntries, policyDigest: capability.payload.policy_digest, snapshot: h.setup.config.tenants.acme.runtime_snapshot });
  gate.reportEndpointHealth(signed({ tenant_id: 'acme', gate_id: h.f.config.gate_id, device_id: 'operator-device', reported_at: h.now(), expires_at: h.now() + 5000, status: 'HEALTHY', nonce: 'runtime-health-1' }, h.setup.deviceKeys.acme, 'endpoint-health'));
  gate.register('erp-service', handler); gate.importCapability(capability);
  const request = { capability_id: capability.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: 'runtime-hardening-1' };
  return { gate, capability, request };
}

test('RUN-005 RUN-010: local network gate requires a signed per-action configuration and rejects rollback', t => {
  const h = fixture(t), raw = h.setup.config.tenants.acme.runtime_snapshot.config;
  const audit = h.f.keys('acme').audit;
  assert.throws(() => new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), configurationKeys: h.f.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, policyDigest: 'x', snapshot: raw }), hasCode('INV-503-CONFIG'));
  const n = serviceGate(h), next = clone(h.setup.config.tenants.acme.runtime_snapshot); next.config.version++; next.config.issued_at = h.now(); next.config.expires_at += 1000;
  const signedNext = signRuntimeConfiguration(next.config, Object.values(h.setup.custodianKeys.acme).slice(0, 3));
  n.gate.reload(signedNext); assert.equal(n.gate.report().events.at(-1).type, 'CONFIGURATION_RELOADED');
  assert.throws(() => n.gate.reload(h.setup.config.tenants.acme.runtime_snapshot), hasCode('INV-503-CONFIG'));
});

test('RUN-004 RUN-006 RUN-009: signed capability revocation is immediate, scoped and does not expose payloads', t => {
  const h = fixture(t), n = serviceGate(h);
  const malformed = signed({ tenant_id: 'acme', kind: 'capability', id: n.capability.payload.capability_id, revoked_at: h.now() }, h.setup.issuerKeys.acme.bank, 'revocation');
  assert.throws(() => n.gate.revoke(malformed), hasCode('INV-401-SIGNATURE'));
  n.gate.revoke(h.f.revoke(h.p('security'), { kind: 'capability', id: n.capability.payload.capability_id, reason: 'Synthetic compromise' }));
  assert.equal(n.gate.send(n.request, { secret: 'do-not-log' }).code, 'INV-401-CAPABILITY');
  assert.doesNotMatch(JSON.stringify(n.gate.report()), /do-not-log|Synthetic compromise/);
  assert.equal(n.gate.report().events.at(-1).propagation_ms, 0);
  const m = serviceGate(h);
  m.gate.revoke(h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'Synthetic identity compromise' }));
  assert.equal(m.gate.send(m.request, {}).code, 'INV-403-QUARANTINE');
});

test('RUN-008 RUN-009: malformed requests and failed local services fail closed without duplicate delivery', t => {
  const h = fixture(t); let calls = 0;
  const n = serviceGate(h, 8, () => { calls++; throw new Error('connector failure'); });
  assert.equal(n.gate.send({ ...n.request, unexpected: true }, {}).code, 'INV-403-SCOPE');
  assert.equal(n.gate.send(n.request, {}).code, 'INV-503-GATE'); assert.equal(calls, 1);
  assert.equal(n.gate.send(n.request, {}).code, 'INV-409-REPLAY'); assert.equal(calls, 1);
  assert.equal(n.gate.report().counters['INV-403-SCOPE'], 1);
});

test('RUN-004 RUN-008: signer revocation withdraws a local gate and cache saturation preserves existing authority', t => {
  const h = fixture(t), n = serviceGate(h, 1);
  for (let i = 0; i < 20; i++) {
    const challenger = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
    assert.throws(() => n.gate.importCapability(challenger), hasCode('INV-429-CACHE'));
  }
  assert.equal(n.gate.send(n.request, {}).decision, 'ALLOW');
  const signer = h.setup.config.tenants.acme.runtime_snapshot.signatures[0].protected.key_id;
  n.gate.revoke(h.f.revoke(h.p('security'), { kind: 'key', id: signer, reason: 'Synthetic custodian compromise' }));
  assert.equal(n.gate.send({ ...n.request, request_id: 'after-signer-revocation' }, {}).code, 'INV-503-CONFIG');
});

test('RUN-010: runtime configuration rejection persists a version floor across a process restart', t => {
  const h = fixture(t), old = clone(h.setup.config), upgraded = clone(h.setup.config.tenants.acme.runtime_snapshot.config);
  upgraded.version++; upgraded.issued_at = h.now(); upgraded.expires_at += 1000;
  const next = signRuntimeConfiguration(upgraded, Object.values(h.setup.custodianKeys.acme).slice(0, 3));
  h.f.runtimeIntegrity.reload(h.p('security'), next);
  h.close();
  assert.throws(() => new Fabric(old, h.directory, h.now), hasCode('INV-503-CONFIG'));
});

test('RUN-010: duplicate-key on-disk runtime configuration withdraws the gate', t => {
  const h = fixture(t), configPath = join(h.directory, 'config.json');
  writeFileSync(configPath, canonical(h.setup.config));
  const f = new Fabric(h.setup.config, h.directory, h.now);
  f.runtime.issue(h.p(), runtimeInput());
  writeFileSync(configPath, '{"tenants":{},"tenants":{}}'); h.advance(1000);
  assert.throws(() => f.runtime.issue(h.p(), runtimeInput()), hasCode('INV-503-CONFIG'));
  assert.equal(f.store.list('acme', 'runtime-config-state')[0].status, 'WITHDRAWN');
  f.close();
});
