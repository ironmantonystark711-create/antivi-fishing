import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { fixture } from './helpers.mjs';
import { createServer } from '../src/server.mjs';

function oversizedAbort(port, i) {
  return new Promise(resolve => {
    const socket = net.connect(port, '127.0.0.1'); socket.on('error', () => {}); socket.on('close', resolve);
    socket.on('connect', () => { socket.write('POST /v1/certificates HTTP/1.1\r\nHost: 127.0.0.1:17777\r\nContent-Type: application/json\r\nContent-Length: 2000000\r\n\r\n' + 'x'.repeat(32768)); if (i % 2) socket.destroy(); else socket.end(); }); socket.resume();
  });
}

test('NFR-SEC-001 NFR-PERF-005: aborted and oversized clients cannot crash the HTTP gate', async t => {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' });
  await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  await Promise.all(Array.from({ length: 50 }, (_, i) => oversizedAbort(port, i)));
  const status = await new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/healthz', headers: { host: '127.0.0.1:17777' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); req.on('error', reject);
  });
  assert.equal(status, 200);
});

test('NFR-SEC-001: repeated oversized aborts drain streams without an asynchronous transport failure after request completion', async t => {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' });
  await app.listen(); t.after(() => app.close()); const port = app.server.address().port;
  for (let wave = 0; wave < 6; wave++) await Promise.all(Array.from({ length: 50 }, (_, i) => oversizedAbort(port, wave * 50 + i)));
  const status = await new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/healthz', headers: { host: '127.0.0.1:17777' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); req.on('error', reject);
  });
  assert.equal(status, 200);
});
