import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, runtimeInput, runtimeRequest, hasCode } from './helpers.mjs';
import { clone } from '../src/canonical.mjs';
import { signRuntimeConfiguration } from '../src/runtime-config.mjs';
import { loadConfiguration } from '../src/bootstrap.mjs';
test('RUN-010: restart cannot roll back signed configuration or rebind an accepted version', t => {
  const h = fixture(t), original = clone(h.setup.config), old = original.tenants.acme.runtime_snapshot;
  const keys = Object.values(h.setup.custodianKeys.acme).slice(0, 3);
  h.f.runtimeIntegrity.reload(h.p('security'), signRuntimeConfiguration({ ...old.config, version: 2 }, keys)); h.close();
  assert.throws(() => new h.f.constructor(original, h.directory, h.now), hasCode('INV-503-CONFIG'));
  const rebound = clone(h.setup.config); rebound.tenants.acme.runtime_snapshot = signRuntimeConfiguration({ ...old.config, version: 2, cache_entries: 100 }, keys);
  assert.throws(() => new h.f.constructor(rebound, h.directory, h.now), hasCode('INV-503-CONFIG'));
  const next = new h.f.constructor(h.setup.config, h.directory, h.now); t.after(() => next.close());
  assert.equal(next.runtimeIntegrity.check('acme').version, 2);
});
test('RUN-010 RUN-003: expiry, revoked custodian, duplicate signer and stale process withdraw local authority', t => {
  const h = fixture(t), snapshot = clone(h.setup.config.tenants.acme.runtime_snapshot), keys = Object.values(h.setup.custodianKeys.acme);
  assert.throws(() => h.f.runtimeIntegrity.reload(h.p('security'), signRuntimeConfiguration({ ...snapshot.config, version: 2 }, [keys[0], keys[0], keys[1]])), hasCode('INV-503-CONFIG'));
  const peer = new h.f.constructor(clone(h.setup.config), h.directory, h.now); t.after(() => peer.close());
  h.f.runtimeIntegrity.reload(h.p('security'), signRuntimeConfiguration({ ...snapshot.config, version: 2, expires_at: h.now() + 1000 }, keys.slice(0, 3)));
  assert.throws(() => peer.runtimeIntegrity.check('acme'), hasCode('INV-503-CONFIG'));
  const cap = h.f.runtime.issue(h.p(), runtimeInput()); h.advance(1000);
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-503-CONFIG'));
  h.f.revoke(h.p('security'), { kind: 'key', id: keys[0].key_id, reason: 'custodian compromised' });
  assert.throws(() => h.f.runtimeIntegrity.reload(h.p('security'), signRuntimeConfiguration({ ...snapshot.config, version: 3 }, keys.slice(0, 3))));
  assert.equal(h.f.runtimeIntegrity.reload(h.p('security'), signRuntimeConfiguration({ ...snapshot.config, version: 3 }, keys.slice(1, 4))).version, 3);
});
test('RUN-010 NFR-SEC-006: duplicate JSON configuration keys are rejected at startup', t => {
  const h = fixture(t); writeFileSync(join(h.directory, 'config.json'), '{"profile":"production","profile":"engineering"}');
  assert.throws(() => loadConfiguration(h.directory), hasCode('INV-400-SCHEMA'));
});
