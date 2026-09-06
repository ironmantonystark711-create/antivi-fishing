import http from 'node:http';
import { URL } from 'node:url';
import { requireThat } from './errors.mjs';

function routeMap(routes) {
  requireThat(Array.isArray(routes) && routes.length > 0 && routes.length <= 64, 'INV-400-SCHEMA', 'A bounded explicit route map is required');
  const mapped = new Map();
  for (const route of routes) {
    requireThat(route && /^[a-z][a-z0-9-]{0,63}$/.test(route.service) && typeof route.origin === 'string' && Array.isArray(route.paths) && route.paths.length > 0 && route.paths.length <= 64 && !mapped.has(route.service), 'INV-400-SCHEMA', 'Invalid explicit proxy route');
    const origin = new URL(route.origin);
    requireThat(origin.protocol === 'http:' && ['127.0.0.1', '::1'].includes(origin.hostname) && !origin.username && !origin.password && !origin.search && !origin.hash && (origin.pathname === '/' || origin.pathname === ''), 'INV-403-SCOPE', 'Proxy targets must be exact loopback HTTP origins');
    requireThat(route.paths.every(path => typeof path === 'string' && /^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,255}$/.test(path) && !path.includes('//') && !path.split('/').includes('..')), 'INV-400-SCHEMA', 'Invalid proxy route path');
    mapped.set(route.service, { origin, paths: new Set(route.paths) });
  }
  return mapped;
}

export class LocalNetworkProxy {
  constructor({ gate, routes, port = 0, host = '127.0.0.1' }) {
    requireThat(gate && ['127.0.0.1', '::1'].includes(host), 'INV-503-GATE', 'Loopback network gate required', 503);
    this.gate = gate; this.routes = routeMap(routes); this.host = host; this.port = port;
    for (const service of this.routes.keys()) gate.register(service, () => null);
    this.agent = new http.Agent({ keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 5000 });
    this.server = http.createServer({ maxHeaderSize: 8192 }, (req, res) => this.#handle(req, res));
    this.server.requestTimeout = 5000; this.server.headersTimeout = 5000; this.server.keepAliveTimeout = 1000;
  }
  listen() { return new Promise(resolve => this.server.listen(this.port, this.host, () => resolve(this.server.address()))); }
  close() { return new Promise((resolve, reject) => this.server.close(error => { this.agent.destroy(); error ? reject(error) : resolve(); })); }
  syncRevocations(outbox) {
    const entries = outbox.read(this.gate.tenant, this.gate.report().revocation_cursor, this.gate.maxEntries);
    return this.gate.syncRevocations(entries, sequence => outbox.acknowledge(this.gate.tenant, this.gate.gate, sequence, this.gate.clock()));
  }
  async #body(req) {
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; requireThat(size <= 16384, 'INV-413-BODY', 'Proxy request body too large', 413); chunks.push(chunk); }
    return Buffer.concat(chunks);
  }
  #send(res, status, body) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(body)); }
  async #handle(req, res) {
    try {
      requireThat(['GET', 'POST'].includes(req.method), 'INV-405-METHOD', 'Method not allowed', 405);
      const url = new URL(req.url, 'http://proxy.invalid'), match = /^\/v1\/proxy\/([a-z][a-z0-9-]{0,63})(\/.*)$/.exec(url.pathname), route = match && this.routes.get(match[1]);
      requireThat(route && !url.search && route.paths.has(match[2]), 'INV-403-SCOPE', 'Proxy destination or path denied', 403);
      const request = { capability_id: req.headers['x-if-capability-id'], tenant_id: this.gate.tenant, subject_id: req.headers['x-if-subject-id'], device_id: req.headers['x-if-device-id'], destination: match[1], protocol: 'https', port: 443, request_id: req.headers['x-if-request-id'] };
      const decision = this.gate.decide(request); if (decision.decision !== 'ALLOW') return this.#send(res, 403, { error: { code: decision.code } });
      const body = await this.#body(req), upstream = http.request({ agent: this.agent, hostname: route.origin.hostname, port: Number(route.origin.port || 80), method: req.method, path: match[2], headers: { 'content-type': req.headers['content-type'] ?? 'application/octet-stream', 'content-length': body.length, host: route.origin.host } }, response => {
        let size = 0; const chunks = [];
        response.on('data', chunk => { size += chunk.length; if (size <= 16384) chunks.push(chunk); else response.destroy(); });
        response.on('end', () => this.#send(res, response.statusCode ?? 502, { decision: 'ALLOW', upstream_status: response.statusCode ?? 502, body: Buffer.concat(chunks).toString('base64url') }));
        response.on('error', () => this.#send(res, 502, { error: { code: this.gate.infrastructureFailure(request).code } }));
      });
      upstream.on('error', () => this.#send(res, 502, { error: { code: this.gate.infrastructureFailure(request).code } }));
      upstream.end(body);
    } catch (error) { this.#send(res, error.status ?? 500, { error: { code: error.code ?? 'INV-500-INTERNAL' } }); }
  }
}
