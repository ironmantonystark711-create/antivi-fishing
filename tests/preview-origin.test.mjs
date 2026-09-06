import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture } from './helpers.mjs';
import { createServer } from '../src/server.mjs';

test('NFR-SEC-005 UX-010: preview permits only configured hosts and origin-bound secure sessions', async t => {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777', previewHostSuffixes: ['.preview.usehoplite.com'] });
  await app.listen(); t.after(() => app.close());
  const host = 'synthetic.preview.usehoplite.com', origin = `https://${host}`;
  function request(path, headers, body) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? null : JSON.stringify(body);
      const req = http.request({ host: '127.0.0.1', port: app.server.address().port, path, method: data === null ? 'GET' : 'POST', headers: { host, ...headers, ...(data === null ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) }) } }, res => {
        let value = ''; res.on('data', chunk => { value += chunk; }); res.on('end', () => resolve({ status: res.statusCode, cookie: res.headers['set-cookie']?.[0], data: JSON.parse(value) }));
      }); req.on('error', reject); req.end(data);
    });
  }
  for (const invalid of ['evil.test', 'preview.usehoplite.com.evil.test', 'notpreview.usehoplite.com', 'synthetic.preview.usehoplite.com:443']) assert.equal((await request('/healthz', { host: invalid })).status, 400);
  assert.equal((await request('/healthz', {})).status, 200);
  assert.equal((await request('/session', { origin: 'http://' + host }, { token: h.setup.credentials.acme.operator })).status, 403);
  const login = await request('/session', { origin }, { token: h.setup.credentials.acme.operator });
  assert.equal(login.status, 200); assert.match(login.cookie, /; Secure/);
  const cookie = login.cookie.split(';')[0];
  assert.equal((await request('/v1/me', { cookie })).status, 200);
  assert.equal((await request('/v1/me', { cookie, host: 'another.preview.usehoplite.com' })).status, 401);
  assert.equal((await request('/session/logout', { cookie, origin }, {})).status, 403);
  assert.equal((await request('/session/logout', { cookie, origin, 'x-csrf-token': login.data.csrf_token }, {})).status, 200);
  assert.equal((await request('/v1/me', { cookie })).status, 401);
});
