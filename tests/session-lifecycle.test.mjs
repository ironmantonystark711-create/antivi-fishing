import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer } from '../src/server.mjs';
import { fixture } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';

async function httpFixture(t) {
  const h = fixture(t), origin = 'http://127.0.0.1:17778', app = createServer(h.f, { port: 0, origin }); await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  async function request(path, { method = 'GET', token, body, headers = {} } = {}) {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => { const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17778', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }), ...headers } }, response => { const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, data: JSON.parse(Buffer.concat(chunks).toString('utf8')) })); }); req.on('error', reject); req.end(payload); });
  }
  return { ...h, origin, request };
}

function resetIdentity(h) {
  const request = h.f.identityLifecycle.request(h.p('security'), { operation: 'MFA_RESET', subject_id: 'operator', new_authenticator: null, proofing_level: 2, recovery_domains: ['identity-proofing', 'customer-contact'], out_of_band_receipt_digest: 'a'.repeat(64), reason: 'lost authenticator' });
  for (let n = 1; n <= 2; n++) { const p = h.p(`custodian-${n}`), challenge = h.f.identityLifecycle.challenge(p, request.request_id); h.f.identityLifecycle.approve(p, signed(challenge, h.setup.custodianKeys.acme[`custodian-${n}`], 'identity-lifecycle-approval')); }
  h.f.identityLifecycle.complete(h.p('security'), request.request_id);
}

test('IDN-005 IDN-008 IDN-009: reset invalidates bearer and cookie credentials; independent custodians reissue one short-lived credential', async t => {
  const h = await httpFixture(t), old = h.setup.credentials.acme.operator;
  assert.equal((await h.request('/session/credential-reissue/challenge', { method: 'POST', body: { tenant_id: 'acme', subject_id: 'operator' }, headers: { Origin: h.origin } })).status, 409);
  const login = await h.request('/session', { method: 'POST', body: { token: old }, headers: { Origin: h.origin } }); assert.equal(login.status, 200);
  const cookie = login.headers['set-cookie'][0].split(';')[0]; resetIdentity(h);
  assert.equal((await h.request('/v1/me', { token: old })).status, 401);
  assert.equal((await h.request('/v1/me', { headers: { Cookie: cookie } })).status, 401);
  const challenge = await h.request('/session/credential-reissue/challenge', { method: 'POST', body: { tenant_id: 'acme', subject_id: 'operator' }, headers: { Origin: h.origin } }); assert.equal(challenge.status, 201);
  const approvals = [1, 2, 3].map(n => signed({ ...challenge.data, signer_id: Object.entries(h.f.identities('acme')).find(([, identity]) => identity.subject_id === `custodian-${n}`)[0] }, h.setup.custodianKeys.acme[`custodian-${n}`], 'credential-reissue'));
  assert.equal((await h.request('/session/credential-reissue', { method: 'POST', body: { tenant_id: 'acme', credential_reissue_id: challenge.data.credential_reissue_id, approvals: approvals.slice(0, 2) }, headers: { Origin: h.origin } })).status, 412);
  const reissued = await h.request('/session/credential-reissue', { method: 'POST', body: { tenant_id: 'acme', credential_reissue_id: challenge.data.credential_reissue_id, approvals }, headers: { Origin: h.origin } });
  assert.equal(reissued.status, 201); assert.match(reissued.data.token, /^[A-Za-z0-9_-]{43}$/); assert.equal((await h.request('/v1/me', { token: reissued.data.token })).status, 200);
  assert.equal((await h.request('/session/credential-reissue', { method: 'POST', body: { tenant_id: 'acme', credential_reissue_id: challenge.data.credential_reissue_id, approvals }, headers: { Origin: h.origin } })).status, 409);
  assert.doesNotMatch(JSON.stringify(h.f.store.auditExport('acme', h.now())), new RegExp(reissued.data.token));
});

test('IDN-001 IDN-007 IDN-008: credential reissue rejects an unattested custodian device', async t => {
  const h = await httpFixture(t); resetIdentity(h);
  const challenge = await h.request('/session/credential-reissue/challenge', { method: 'POST', body: { tenant_id: 'acme', subject_id: 'operator' }, headers: { Origin: h.origin } }); assert.equal(challenge.status, 201);
  const approvals = [1, 2, 3].map(n => signed({ ...challenge.data, signer_id: Object.entries(h.f.identities('acme')).find(([, identity]) => identity.subject_id === `custodian-${n}`)[0] }, h.setup.custodianKeys.acme[`custodian-${n}`], 'credential-reissue'));
  h.f.revoke(h.p('security'), { kind: 'device', id: 'custodian-3-device', reason: 'device attestation withdrawn' });
  assert.equal((await h.request('/session/credential-reissue', { method: 'POST', body: { tenant_id: 'acme', credential_reissue_id: challenge.data.credential_reissue_id, approvals }, headers: { Origin: h.origin } })).status, 403);
});
