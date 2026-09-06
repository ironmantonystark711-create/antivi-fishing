import test from 'node:test';
import assert from 'node:assert/strict';
import { SCHEMAS, proposal, validateProposal } from '../src/schema.mjs';
import { clone, digest } from '../src/canonical.mjs';
import { fixture, hasCode } from './helpers.mjs';

function example(type) {
  const values = { text: 'synthetic', id: 'resource-1', positive: 1, strings: ['id'], currency: 'EUR', account: 'TESTBANK000001', hash: 'a'.repeat(64), object: {} };
  const requested = Object.fromEntries(Object.entries(SCHEMAS[type].requested).map(([name, rule]) => [name, clone(values[rule])]));
  if (type === 'cloud.firewall.change') requested.protocol = 'tcp';
  return proposal(type, { subject_id: 'operator', identity_class: 'workforce', device_id: 'operator-device' }, { version: 0, digest: digest({}), material_fields: {} }, requested, 1788648000000);
}

test('ACT-002: every action schema rejects all missing capsule, actor, action, state and requested fields', () => {
  for (const type of Object.keys(SCHEMAS)) {
    const valid = example(type); assert.deepEqual(validateProposal(valid), valid);
    for (const section of [null, 'actor', 'action', 'current_state', 'requested_state']) {
      for (const field of Object.keys(section ? valid[section] : valid)) {
        const changed = clone(valid); delete (section ? changed[section] : changed)[field];
        assert.throws(() => validateProposal(changed), hasCode('INV-400-SCHEMA'), `${type}/${section ?? 'capsule'}/${field}`);
      }
    }
  }
});

test('ACT-008: all schemas reject missing, unknown or substituted identifiers and digests', () => {
  for (const type of Object.keys(SCHEMAS)) {
    for (const change of [{ schema_id: 'if:unknown:99' }, { schema_digest: 'f'.repeat(64) }, { schema_id: `if:${type}:2` }]) assert.throws(() => validateProposal({ ...example(type), ...change }), hasCode('INV-400-SCHEMA'));
  }
});

test('ACT-002 ACT-011: the gate supplies tenant and collision-resistant capsule identity, never caller overrides', t => {
  const h = fixture(t), input = example('finance.vendor.create');
  for (const change of [{ tenant_id: 'globex' }, { capsule_id: 'caller-selected' }]) assert.throws(() => h.f.propose(h.p(), { ...input, ...change }, crypto.randomUUID()), hasCode('INV-400-SCHEMA'));
  const record = h.f.propose(h.p(), input, 'unique-proposal');
  assert.equal(record.capsule.tenant_id, 'acme');
  assert.match(record.capsule.capsule_id, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.throws(() => h.f.propose(h.p(), input, 'duplicate-proposal'), hasCode('INV-409-REPLAY'));
});
