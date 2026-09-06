import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { LocalNetworkGate } from '../src/network.mjs';
import { LocalNetworkProxy } from '../src/network-proxy.mjs';
import { clone } from '../src/canonical.mjs';
import { signRuntimeConfiguration } from '../src/runtime-config.mjs';
import { signed } from '../src/crypto.mjs';
import { Fabric } from '../src/fabric.mjs';

function gateWithService(h, maxEntries = 16) {
  const capability = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  const audit = h.f.keys('acme').audit;
  const gate = new LocalNetworkGate({ tenant: 'acme', gate: h.f.config.gate_id, publicKeys: h.f.executionPublic('acme'), configurationKeys: h.f.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, clock: h.now, maxEntries, policyDigest: capability.payload.policy_digest, snapshot: h.setup.config.tenants.acme.runtime_snapshot });
  gate.reportEndpointHealth(signed({ tenant_id: 'acme', gate_id: h.f.config.gate_id, device_id: 'operator-device', reported_at: h.now(), expires_at: h.now() + 5000, status: 'HEALTHY', nonce: 'proxy-health-1' }, h.setup.deviceKeys.acme, 'endpoint-health'));
  gate.importCapability(capability); return { gate, capability };
}
function request(port, path, headers, body = '') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'POST', headers: { ...headers, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, res => { const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) })); });
    req.on('error', reject); req.end(body);
  });
}

test('NET-001 NET-003: loopback proxy mediates an actual HTTP request and blocks non-enrolled paths', async t => {
  const h = fixture(t); let received = 0;
  const target = http.createServer((req, res) => { received++; assert.equal(req.url, '/v1/orders'); res.end(JSON.stringify({ accepted: true })); });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve)); t.after(() => target.close());
  const { gate, capability } = gateWithService(h), targetPort = target.address().port;
  const proxy = new LocalNetworkProxy({ gate, routes: [{ service: 'erp-service', origin: `http://127.0.0.1:${targetPort}`, paths: ['/v1/orders'] }] });
  const listener = await proxy.listen(); t.after(() => proxy.close());
  const headers = { 'x-if-capability-id': capability.payload.capability_id, 'x-if-subject-id': 'operator', 'x-if-device-id': 'operator-device', 'x-if-request-id': 'proxy-1' };
  const allowed = await request(listener.port, '/v1/proxy/erp-service/v1/orders', headers, '{"order":"synthetic"}');
  assert.equal(allowed.status, 200); assert.equal(allowed.body.decision, 'ALLOW'); assert.equal(received, 1);
  const denied = await request(listener.port, '/v1/proxy/erp-service/admin', { ...headers, 'x-if-request-id': 'proxy-2' });
  assert.equal(denied.status, 403); assert.equal(denied.body.error.code, 'INV-403-SCOPE'); assert.equal(received, 1);
  const queried = await request(listener.port, '/v1/proxy/erp-service/v1/orders?target=http://127.0.0.1', { ...headers, 'x-if-request-id': 'proxy-3' });
  assert.equal(queried.status, 403); assert.equal(received, 1);
  const oversized = await request(listener.port, '/v1/proxy/erp-service/v1/orders', { ...headers, 'x-if-request-id': 'proxy-4' }, 'x'.repeat(16385));
  assert.equal(oversized.status, 413); assert.equal(received, 1);
  assert.throws(() => new LocalNetworkProxy({ gate, routes: [{ service: 'bad-route', origin: 'http://localhost:1', paths: ['/x'] }] }), hasCode('INV-403-SCOPE'));
});

test('RUN-004: Fabric revocation is durably fed and acknowledged by a local gate', t => {
  const h = fixture(t), { gate, capability } = gateWithService(h), revocation = h.f.revoke(h.p('security'), { kind: 'capability', id: capability.payload.capability_id, reason: 'compromise drill' });
  assert.equal(h.f.revocationOutbox.read('acme').length, 1);
  assert.equal(gate.syncRevocations(h.f.revocationOutbox.read('acme'), sequence => h.f.revocationOutbox.acknowledge('acme', gate.gate, sequence, h.now())), 1);
  const request = { capability_id: capability.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: 'revoked-through-feed' };
  gate.register('erp-service', () => ({ accepted: true })); assert.equal(gate.send(request, {}).code, 'INV-401-CAPABILITY');
  assert.equal(h.f.store.list('acme', 'runtime-revocation-ack').length, 1); assert.equal(revocation.payload.remote_propagation, 'durable-gate-outbox');
});

test('RUN-004: a restarted gate recovers the durable feed, rejects invalid envelopes, and fails closed for stale entries', t => {
  const h = fixture(t), config = clone(h.setup.config), { capability } = gateWithService(h), revocation = h.f.revoke(h.p('security'), { kind: 'capability', id: capability.payload.capability_id, reason: 'restart drill' });
  h.close(); const restarted = new Fabric(config, h.directory, h.now); t.after(() => restarted.close());
  const audit = restarted.keys('acme').audit, gate = new LocalNetworkGate({ tenant: 'acme', gate: restarted.config.gate_id, publicKeys: restarted.executionPublic('acme'), configurationKeys: restarted.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, clock: h.now, maxEntries: 8, policyDigest: capability.payload.policy_digest, snapshot: config.tenants.acme.runtime_snapshot });
  gate.importCapability(capability); gate.register('erp-service', () => ({ accepted: true }));
  const entry = restarted.revocationOutbox.read('acme')[0], invalid = signed(entry.envelope.payload, h.setup.issuerKeys.acme.bank, 'revocation');
  assert.throws(() => gate.syncRevocations([{ sequence: entry.sequence, envelope: invalid }]), hasCode('INV-401-SIGNATURE'));
  assert.equal(gate.report().revocation_cursor, 0);
  gate.syncRevocations([entry]); assert.equal(gate.report().revocation_cursor, entry.sequence);
  const stale = restarted.revocationOutbox.read('acme')[0]; h.advance(1001);
  const freshGate = new LocalNetworkGate({ tenant: 'acme', gate: restarted.config.gate_id, publicKeys: restarted.executionPublic('acme'), configurationKeys: restarted.identities('acme'), revocationKeys: { [audit.key_id]: { public_key: audit.public_key } }, clock: h.now, maxEntries: 8, policyDigest: capability.payload.policy_digest, snapshot: config.tenants.acme.runtime_snapshot });
  assert.throws(() => freshGate.syncRevocations([stale]), hasCode('INV-503-GATE'));
  assert.equal(freshGate.report().configuration_digest !== null, true);
});

test('RUN-002: service capability consumption rejects a changed resource state', t => {
  const h = fixture(t), capability = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [] }));
  h.f.target.seed('acme', 'erp-service', { revision: 'changed' });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(capability)), hasCode('INV-409-STATE'));
});

test('RUN-005 NET-005 NET-006: configured constrained remediation is the only non-fail-closed infrastructure behavior', t => {
  const h = fixture(t), { gate, capability } = gateWithService(h);
  gate.register('erp-service', () => { throw new Error('synthetic upstream outage'); });
  const request = { capability_id: capability.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: 'fail-closed' };
  assert.equal(gate.send(request, {}).code, 'INV-503-GATE');
  const next = clone(h.setup.config.tenants.acme.runtime_snapshot.config); next.version++; next.issued_at = h.now(); next.expires_at += 1000; next.failure_policies['service.connect'] = 'constrained-open'; next.remediation_services = ['erp-service'];
  gate.reload(signRuntimeConfiguration(next, Object.values(h.setup.custodianKeys.acme).slice(0, 3)));
  assert.equal(gate.send({ ...request, request_id: 'constrained-remediation' }, {}).code, 'CONSTRAINED_REMEDIATION_ALLOW');
  gate.quarantine('operator-device'); assert.equal(gate.send({ ...request, request_id: 'quarantined-remediation' }, {}).code, 'CONSTRAINED_REMEDIATION_ALLOW');
  assert.deepEqual(gate.report().events.at(-1).affected_capabilities, [capability.payload.capability_id]);
});

test('RUN-008: bounded revocation state withdraws the gate rather than evicting security state', t => {
  const h = fixture(t), { gate } = gateWithService(h, 1), first = h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'first' }), second = h.f.revoke(h.p('security'), { kind: 'subject', id: 'another-subject', reason: 'second' });
  gate.revoke(first); assert.throws(() => gate.revoke(second), hasCode('INV-503-GATE'));
  assert.equal(gate.report().configuration_digest !== null, true);
});

test('RUN-006: primary runtime enforcement exposes bounded reason-coded counters without payloads', t => {
  const h = fixture(t), capability = h.f.runtime.issue(h.p(), runtimeInput());
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(capability, { destination: 'different-destination' })), hasCode('INV-403-SCOPE'));
  const metrics = h.f.runtime.metrics('acme');
  assert.equal(metrics.counters['issue.ALLOW'], 1); assert.equal(metrics.counters['consume.INV-403-SCOPE'], 1);
  assert.doesNotMatch(JSON.stringify(metrics), /payload-must-not-appear|different-destination/);
});

test('NET-005 NET-006 NET-010: signed endpoint-health expiry and agent-loss hooks quarantine, report duration, and recover only on fresh proof', t => {
  const h = fixture(t), { gate, capability } = gateWithService(h); gate.register('erp-service', () => ({ accepted: true }));
  h.advance(5001); assert.deepEqual(gate.watchdog(), ['operator-device']);
  const request = { capability_id: capability.payload.capability_id, tenant_id: 'acme', subject_id: 'operator', device_id: 'operator-device', destination: 'erp-service', protocol: 'https', port: 443, request_id: 'expired-health' };
  assert.equal(gate.send(request, {}).code, 'INV-403-QUARANTINE'); h.advance(10);
  const fresh = { tenant_id: 'acme', gate_id: h.f.config.gate_id, device_id: 'operator-device', reported_at: h.now(), expires_at: h.now() + 5000, status: 'HEALTHY', nonce: 'fresh-health-2' };
  assert.throws(() => gate.reportEndpointHealth(signed(fresh, h.setup.issuerKeys.acme.bank, 'endpoint-health')), hasCode('INV-401-SIGNATURE'));
  gate.reportEndpointHealth(signed(fresh, h.setup.deviceKeys.acme, 'endpoint-health'));
  assert.equal(gate.send({ ...request, request_id: 'recovered-health' }, {}).decision, 'ALLOW');
  const recovered = gate.report().events.at(-1); assert.equal(recovered.type, 'CONTAINMENT_RECOVERED'); assert.equal(recovered.containment_duration_ms, 10);
  gate.endpointControlLost('operator-device'); assert.equal(gate.send({ ...request, request_id: 'agent-lost' }, {}).code, 'INV-403-QUARANTINE');
  gate.reportEndpointHealth(signed({ ...fresh, nonce: 'fresh-health-3' }, h.setup.deviceKeys.acme, 'endpoint-health'));
  gate.revoke(h.f.revoke(h.p('security'), { kind: 'key', id: h.setup.deviceKeys.acme.key_id, reason: 'attestor compromise' }));
  assert.equal(gate.send({ ...request, request_id: 'attestor-revoked' }, {}).code, 'INV-403-QUARANTINE');
});
