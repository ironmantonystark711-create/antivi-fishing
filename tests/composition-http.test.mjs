import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
import { createServer } from '../src/server.mjs';

test('COM-012: HTTP aggregate reconciliation verifies the journal without repeating target mutations', async t => {
  const h = fixture(t), app = createServer(h.f, { port: 0 });
  await app.listen(); t.after(() => app.close());
  const records = [h.proposed(), h.proposed()];
  for (const record of records) { h.evidence(record); h.evidence(record, { issuer: 'registry' }); }
  const composition = h.f.compositions.create(h.p(), { tree: { root: 'root', nodes: { root: { kind: 'all', children: ['one', 'two'] }, one: { kind: 'action', capsule_id: records[0].capsule.capsule_id }, two: { kind: 'action', capsule_id: records[1].capsule.capsule_id } } }, expires_at: h.now() + 60000 }, crypto.randomUUID());
  for (const subject of ['custodian-1', 'custodian-2']) h.f.compositions.approve(h.p(subject), signed(h.f.compositions.challenge(h.p(subject), composition.payload.composition_id), h.setup.custodianKeys.acme[subject], 'batch-approval'));
  const certificates = records.map(record => h.f.certificate(h.p(), record.capsule.capsule_id));
  const executed = h.f.compositions.execute(h.p(), { composition_id: composition.payload.composition_id, certificates });
  assert.equal(executed.status, 'VERIFIED');
  const request = (token, body = {}) => new Promise((resolve, reject) => {
    const payload = JSON.stringify(body), req = http.request({ host: '127.0.0.1', port: app.server.address().port, path: `/gate/v1/compositions/${composition.payload.composition_id}/reconcile`, method: 'POST', headers: { Host: '127.0.0.1:0', Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      const chunks = []; res.on('error', reject); res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString()) }));
    }); req.on('error', reject); req.end(payload);
  });
  assert.equal((await request(h.setup.credentials.globex.operator)).status, 404);
  assert.equal((await request(h.setup.credentials.acme.auditor)).status, 403);
  assert.equal((await request(h.setup.credentials.acme.operator, { retry: true })).status, 400);
  const response = await request(h.setup.credentials.acme.operator);
  assert.equal(response.status, 200);
  assert.equal(response.data.status, 'VERIFIED');
  for (const record of records) assert.equal(h.f.target.state('acme', record.capsule.action.target_resource).version, 1);
});
