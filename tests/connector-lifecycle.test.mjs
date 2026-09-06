import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { verifySigned } from '../src/crypto.mjs';
function deprecated(h, kind, id, version) { return { kind, id, version, status: 'DEPRECATED', end_of_support: h.now() + 1000, replacement: 'customer-approved-next-version', migration: 'Revalidate, deploy supported adapter, and re-propose exact action.', compatibility_digest: digest('test compatibility') }; }
test('CON-001 CON-002 CON-010: tenant-signed connector manifest enumerates actions, least privilege and limitations', t => {
 const h = fixture(t), e = h.f.connectorManifest(h.p()), key = h.f.keys('acme').audit;
 const m = verifySigned(e, { [key.key_id]: key }, 'connector-manifest').manifest;
 assert.ok(m.supported_actions.includes('finance.bank.change')); assert.deepEqual(m.admin_permissions, []); assert.equal(m.atomic_batch, true); assert.equal(m.production_supported, false); assert.ok(m.limitations.length);
 assert.throws(() => verifySigned(e, { [h.f.keys('globex').audit.key_id]: h.f.keys('globex').audit }, 'connector-manifest'));
});
for (const kind of ['schema', 'connector']) test(`CON-006 NFR-MNT-005: ${kind} expiry invalidates already-issued certificates and cannot be delayed to revive authority`, t => {
 const h = fixture(t), { record, certificate } = h.ready(), m = h.f.target.manifest();
 const x = deprecated(h, kind, kind === 'schema' ? record.capsule.schema_id : m.connector_id, kind === 'schema' ? '1' : m.version);
 h.f.versions.publish(h.p('security'), x); h.advance(1000);
 assert.throws(() => h.f.execute(h.p(), certificate), hasCode('INV-410-VERSION'));
 assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 0);
 assert.throws(() => h.f.versions.publish(h.p('security'), { ...x, end_of_support: h.now() + 10000 }), hasCode('INV-409-LIFECYCLE'));
 assert.throws(() => h.proposed(), hasCode('INV-410-VERSION'));
});
