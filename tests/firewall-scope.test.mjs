import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode } from './helpers.mjs';
import { validateNetworkRange } from '../src/schema.mjs';
for (const source_cidr of ['0.0.0.0/0', '::/0', '0:0:0:0:0:0:0:0/0']) test(`POL-003 UC-08: all-address ${source_cidr} never becomes executable`, t => {
 const h = fixture(t), r = h.proposed('cloud.firewall.change', { protocol: 'tcp', port: 5432, source_cidr, service_id: 'database' });
 assert.equal(h.f.evaluate(h.p(), r.capsule.capsule_id).decision, 'DENY'); assert.throws(() => h.f.certificate(h.p(), r.capsule.capsule_id));
});
test('ACT-007 UC-08: ambiguous masks, mapped address families and masked host bits fail before authorization', () => {
 for (const value of ['0.0.0.0/00', '0.0.0.0/0 ', '0.0.0.0/+0', '128.0.0.0/0', '1.2.3.4/24', '1.2.3.4/33', '::ffff:0.0.0.0/96', 'fe80::%eth0/64', '::/129', '2001:DB8::/32', 'not-a-cidr']) assert.throws(() => validateNetworkRange(value), hasCode('INV-400-SCHEMA'));
 for (const value of ['10.0.0.0/24', '1.2.3.4/32', '2001:db8::/32', '::1/128']) assert.ok(validateNetworkRange(value).prefix > 0);
});
