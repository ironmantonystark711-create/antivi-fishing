import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { parseStrict, canonical, hashBytes, digest } from './canonical.mjs';
import { fields, text, identifier, integer } from './schema.mjs';
import { SCHEMAS } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { verifySigned } from './crypto.mjs';

export function createServer(fabric, { port = 8080, host = '127.0.0.1', origin = `http://127.0.0.1:${port}`, previewHostSuffixes = [] } = {}) {
  requireThat(['127.0.0.1', '::1'].includes(host), 'INV-503-RELEASE', 'Engineering HTTP service must bind to loopback', 503);
  requireThat(previewHostSuffixes.every(s => /^\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(s)), 'INV-503-CONFIG', 'Invalid preview host suffix', 503);
  function requestOrigin(req) {
    if (req.headers.host === new URL(origin).host) return origin;
    const name = req.headers.host ?? '';
    requireThat(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(name) && previewHostSuffixes.some(s => name.endsWith(s)), 'INV-400-HOST', 'Unrecognised host', 400);
    return `https://${name}`;
  }
  const web = fileURLToPath(new URL('../web/', import.meta.url));
  const sessions = new Map(), rate = new Map();
  const metrics = { requests: 0, errors: 0, unauthorised: 0 };
  function rateLimit(key, max, window = 60000) {
    const now = Date.now();
    if (rate.size > 10000) for (const [k, v] of rate) if (v.reset <= now) rate.delete(k);
    let entry = rate.get(key); if (!entry || entry.reset <= now) { entry = { count: 0, reset: now + window }; rate.set(key, entry); }
    requireThat(++entry.count <= max, 'INV-429-RATE', 'Request rate limit reached', 429);
  }
  function authenticateToken(token) {
    requireThat(typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token), 'INV-401-AUTH', 'Authentication required', 401);
    const hash = hashBytes(token);
    for (const [tenant, t] of Object.entries(fabric.config.tenants)) {
      const entry = t.auth[hash] ?? fabric.store.get(tenant, 'http-credential', hash);
      if (entry && entry.expires_at > fabric.clock() && fabric.identityLifecycle.sessionValid(tenant, entry.subject_id, entry.auth_epoch ?? 0)) {
        const principal = { tenant_id: tenant, subject_id: entry.subject_id };
        fabric.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload', 'audit_finance', 'audit_privacy', 'audit_technical', 'audit_security']);
        return { principal, expires: entry.expires_at };
      }
    }
    throw new InvariantError('INV-401-AUTH', 'Authentication required', 401);
  }
  function auth(req) {
    const authorization = req.headers.authorization;
    if (authorization) { requireThat(/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization), 'INV-401-AUTH', 'Authentication required', 401); return authenticateToken(authorization.slice(7)).principal; }
    const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1], session = sid ? sessions.get(hashBytes(sid)) : null;
    requireThat(session && session.expires > Date.now() && fabric.identityLifecycle.sessionValid(session.principal.tenant_id, session.principal.subject_id, session.auth_epoch), 'INV-401-AUTH', 'Authentication required', 401);
    requireThat(session.origin === requestOrigin(req), 'INV-401-AUTH', 'Authentication required', 401);
    if (req.method !== 'GET') requireThat(req.headers['x-csrf-token'] === session.csrf && req.headers.origin === requestOrigin(req), 'INV-403-CSRF', 'Request origin or CSRF token rejected', 403);
    fabric.authorize(session.principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload', 'audit_finance', 'audit_privacy', 'audit_technical', 'audit_security']); return session.principal;
  }
  function credentialReissueChallenge(input) {
    fields(input, ['tenant_id', 'subject_id']); identifier(input.tenant_id, 'tenant'); identifier(input.subject_id, 'subject');
    const identity = fabric.identityLifecycle.effective(input.tenant_id, input.subject_id), epoch = fabric.identityLifecycle.sessionEpoch(input.tenant_id, input.subject_id);
    requireThat(identity.session_invalidated_at && epoch > 0, 'INV-409-STATE', 'Credential reissue requires completed reset or recovery', 409);
    return fabric.store.tx(() => {
      const now = fabric.clock(); fabric.store.clock(now);
      const challenge = { credential_reissue_id: randomUUID(), tenant_id: input.tenant_id, subject_id: input.subject_id, session_epoch: epoch, issued_at: now, expires_at: now + 300000 };
      fabric.store.insert(input.tenant_id, 'credential-reissue', challenge.credential_reissue_id, { ...challenge, status: 'PENDING' }, now);
      fabric.store.audit(input.tenant_id, 'CREDENTIAL_REISSUE_REQUESTED', input.subject_id, challenge.credential_reissue_id, { session_epoch: epoch }, now);
      return challenge;
    });
  }
  function reissueCredential(input) {
    fields(input, ['tenant_id', 'credential_reissue_id', 'approvals']); identifier(input.tenant_id, 'tenant'); identifier(input.credential_reissue_id, 'credential reissue'); requireThat(Array.isArray(input.approvals), 'INV-400-SCHEMA', 'Credential reissue approvals must be an array');
    return fabric.store.tx(() => {
      const now = fabric.clock(); fabric.store.clock(now); const request = fabric.store.must(input.tenant_id, 'credential-reissue', input.credential_reissue_id);
      requireThat(request.status === 'PENDING' && request.expires_at > now && request.session_epoch === fabric.identityLifecycle.sessionEpoch(input.tenant_id, request.subject_id), 'INV-409-STATE', 'Credential reissue request is unavailable', 409);
      const signers = new Set(), domains = new Set(), threshold = fabric.tenant(input.tenant_id).key_governance.root_threshold;
      for (const envelope of input.approvals) {
        const approval = verifySigned(envelope, fabric.identities(input.tenant_id), 'credential-reissue'), identity = fabric.identities(input.tenant_id)[approval.signer_id];
        fields(approval, ['credential_reissue_id', 'tenant_id', 'subject_id', 'session_epoch', 'issued_at', 'expires_at', 'signer_id']);
        requireThat(approval.credential_reissue_id === request.credential_reissue_id && approval.tenant_id === input.tenant_id && approval.subject_id === request.subject_id && approval.session_epoch === request.session_epoch && approval.issued_at === request.issued_at && approval.expires_at === request.expires_at && identity?.roles.includes('custodian') && fabric.tenant(input.tenant_id).key_governance.root_custodians.includes(identity.subject_id) && !signers.has(approval.signer_id) && !domains.has(identity.failure_domain), 'INV-403-SCOPE', 'Credential reissue approval scope mismatch', 403);
        fabric.assertHealthy(input.tenant_id, identity.subject_id, identity.device_id, now);
        signers.add(approval.signer_id); domains.add(identity.failure_domain);
      }
      requireThat(signers.size >= threshold && domains.size >= threshold, 'INV-412-EVIDENCE', 'Independent customer threshold is required for credential reissue', 412);
      const token = randomBytes(32).toString('base64url'), expiresAt = now + 900000;
      fabric.store.insert(input.tenant_id, 'http-credential', hashBytes(token), { subject_id: request.subject_id, auth_epoch: request.session_epoch, issued_at: now, expires_at: expiresAt }, now);
      fabric.store.put(input.tenant_id, 'credential-reissue', request.credential_reissue_id, { ...request, status: 'COMPLETED', completed_at: now, approval_count: signers.size }, now);
      fabric.store.audit(input.tenant_id, 'CREDENTIAL_REISSUED', request.subject_id, request.credential_reissue_id, { session_epoch: request.session_epoch, approval_count: signers.size, expires_at: expiresAt }, now);
      return { token, expires_in: 900, session_epoch: request.session_epoch };
    });
  }
  function body(req) {
    requireThat(req.headers['content-type']?.split(';')[0] === 'application/json', 'INV-415-CONTENT', 'Use application/json', 415);
    requireThat(!req.headers['content-encoding'], 'INV-415-CONTENT', 'Compressed request bodies are not accepted', 415);
    return new Promise((resolve, reject) => {
      let size = 0, settled = false, oversized = Number(req.headers['content-length'] ?? 0) > 1048576; const chunks = [];
      const finish = () => {
        if (settled) return; settled = true;
        if (oversized) return reject(new InvariantError('INV-413-BODY', 'Request body too large', 413));
        try { resolve(parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); } catch (e) { reject(e instanceof InvariantError ? e : new InvariantError('INV-400-SCHEMA', 'Invalid UTF-8 or JSON')); }
      };
      req.on('data', chunk => {
        if (settled) return;
        size += chunk.length;
        if (size > 1048576) { oversized = true; chunks.length = 0; return; }
        if (oversized) return;
        chunks.push(chunk);
      });
      req.once('end', finish);
      req.once('error', error => { if (!settled) { settled = true; reject(error); } });
    });
  }
  const server = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    metrics.requests++; const requestId = randomBytes(12).toString('hex');
    const abort = () => { metrics.errors++; if (!res.destroyed && !res.writableEnded) res.destroy(); };
    req.once('aborted', abort); req.once('error', abort);
    // ServerResponse already owns the failed socket; destroying it again can race its error path.
    res.once('error', () => { metrics.errors++; });
    res.setHeader('X-Request-Id', requestId); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, data, type = 'application/json; charset=utf-8') => { if (res.destroyed || res.writableEnded) return; res.writeHead(status, { 'Content-Type': type }); res.end(type.startsWith('application/json') ? canonical(data) : data); };
    try {
      requireThat(['GET', 'POST'].includes(req.method), 'INV-405-METHOD', 'Method not allowed', 405);
      const effectiveOrigin = requestOrigin(req);
      requireThat(!req.headers.origin || req.headers.origin === effectiveOrigin, 'INV-403-ORIGIN', 'Cross-origin requests are not allowed', 403);
      const url = new URL(req.url, origin), path = url.pathname;
      rateLimit(`ip:${req.socket.remoteAddress}`, 600);
      if (path === '/healthz' && req.method === 'GET') return send(200, { status: 'ok', profile: 'engineering', production_ready: false });
      if (path === '/readyz' && req.method === 'GET') { fabric.store.db.prepare('SELECT 1').get(); return send(200, { status: 'ready', profile: 'engineering', real_targets: false }); }
      const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/workspace': ['workspace.html', 'text/html; charset=utf-8'], '/mark.svg': ['mark.svg', 'image/svg+xml'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
      if (req.method === 'GET' && assets[path]) { const [file, type] = assets[path]; return send(200, readFileSync(join(web, file)), type); }
      if (path === '/session' && req.method === 'POST') {
        rateLimit(`login:${req.socket.remoteAddress}`, 20);
        requireThat(req.headers.origin === effectiveOrigin, 'INV-403-ORIGIN', 'Session creation requires same origin', 403);
        const input = await body(req); fields(input, ['token']); const result = authenticateToken(input.token);
        for (const [key, session] of sessions) if (session.expires <= Date.now()) sessions.delete(key);
        requireThat(sessions.size < 1000, 'INV-503-CAPACITY', 'Session capacity reached', 503);
        const sid = randomBytes(32).toString('base64url'), csrf = randomBytes(32).toString('base64url');
        sessions.set(hashBytes(sid), { principal: result.principal, auth_epoch: fabric.identityLifecycle.sessionEpoch(result.principal.tenant_id, result.principal.subject_id), origin: effectiveOrigin, csrf, expires: Math.min(Date.now() + 900000, result.expires) });
        res.setHeader('Set-Cookie', `if_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900${effectiveOrigin.startsWith('https:') ? '; Secure' : ''}`);
        return send(200, { ...result.principal, csrf_token: csrf, expires_in: 900 });
      }
      if (path === '/session/credential-reissue/challenge' && req.method === 'POST') { requireThat(req.headers.origin === effectiveOrigin, 'INV-403-ORIGIN', 'Credential reissue requires same origin', 403); rateLimit(`credential-reissue:${req.socket.remoteAddress}`, 10); return send(201, credentialReissueChallenge(await body(req))); }
      if (path === '/session/credential-reissue' && req.method === 'POST') { requireThat(req.headers.origin === effectiveOrigin, 'INV-403-ORIGIN', 'Credential reissue requires same origin', 403); rateLimit(`credential-reissue:${req.socket.remoteAddress}`, 10); return send(201, reissueCredential(await body(req))); }
      const p = auth(req); rateLimit(`subject:${p.tenant_id}:${p.subject_id}`, 300);
      if (path === '/session/logout' && req.method === 'POST') {
        const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1]; if (sid) sessions.delete(hashBytes(sid));
        res.setHeader('Set-Cookie', 'if_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return send(200, { logged_out: true });
      }
      if (path === '/v1/me' && req.method === 'GET') return send(200, { ...p, roles: fabric.identity(p).roles, device_id: fabric.identity(p).device_id, profile: 'engineering', secure_perception: false });
      if (path === '/v1/schemas' && req.method === 'GET') return send(200, Object.values(SCHEMAS).map(s => ({ ...s, digest: digest(s) })));
      if (path === '/v1/policy' && req.method === 'GET') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'policy_admin', 'security']); return send(200, fabric.policy(p.tenant_id)); }
      if (path === '/v1/action-capsules' && req.method === 'GET') {
        fabric.authorize(p, ['operator', 'approver', 'custodian', 'security', 'policy_admin']);
        const limit = integer(Number(url.searchParams.get('limit') ?? 50), 'limit', 1, 100), offset = integer(Number(url.searchParams.get('offset') ?? 0), 'offset', 0, 1000000);
        return send(200, { items: fabric.store.list(p.tenant_id, 'capsule', limit, offset), limit, offset });
      }
      if (path === '/v1/action-capsules' && req.method === 'POST') return send(201, fabric.propose(p, await body(req), req.headers['idempotency-key']));
      let m;
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)$/.exec(path)) && req.method === 'GET') return send(200, fabric.getCapsule(p, m[1]));
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)\/approval-challenge$/.exec(path)) && req.method === 'GET') return send(200, fabric.approvalChallenge(p, m[1]));
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)\/shield$/.exec(path)) && req.method === 'POST') { fields(await body(req), []); return send(201, fabric.createShieldedProposal(p, m[1])); }
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)\/(evidence|evaluate|cancel)$/.exec(path)) && req.method === 'POST') {
        const input = await body(req); if (m[2] === 'evidence') return send(201, fabric.attachEvidence(p, m[1], input)); fields(input, []);
        return send(200, m[2] === 'evaluate' ? fabric.evaluate(p, m[1]) : fabric.cancel(p, m[1]));
      }
      if (path === '/v1/approvals' && req.method === 'POST') return send(201, fabric.approve(p, await body(req)));
      if (path === '/v1/compositions' && req.method === 'POST') return send(201, fabric.compositions.create(p, await body(req), req.headers['idempotency-key']));
      if (path === '/v1/compositions' && req.method === 'GET') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'policy_admin', 'security']); return send(200, fabric.store.list(p.tenant_id, 'composition', 100).map(r => r.envelope)); }
      if ((m = /^\/v1\/compositions\/([A-Za-z0-9-]+)\/challenge$/.exec(path)) && req.method === 'GET') return send(200, fabric.compositions.challenge(p, m[1]));
      if (path === '/v1/batch-approvals' && req.method === 'POST') return send(201, fabric.compositions.approve(p, await body(req)));
      if (path === '/gate/v1/compositions/execute' && req.method === 'POST') return send(200, fabric.compositions.execute(p, await body(req)));
      if ((m = /^\/gate\/v1\/compositions\/([A-Za-z0-9-]+)\/reconcile$/.exec(path)) && req.method === 'POST') { fields(await body(req), []); return send(200, fabric.reconcileComposition(p, m[1])); }
      if (path === '/v1/emergencies/simulate' && req.method === 'POST') return send(200, fabric.emergencies.simulate(p, await body(req)));
      if (path === '/v1/emergencies/activate' && req.method === 'POST') return send(201, fabric.emergencies.activate(p, await body(req)));
      if (path === '/v1/emergencies/expire' && req.method === 'POST') { fields(await body(req), []); return send(200, fabric.emergencies.sweep(p)); }
      if (path === '/v1/runtime/configuration' && req.method === 'POST') return send(200, fabric.runtimeIntegrity.reload(p, await body(req)));
      if (path === '/v1/coverage/drift' && req.method === 'POST') return send(200, fabric.coverageLifecycle.drift(p, await body(req)));
      if (path === '/v1/coverage/revalidate' && req.method === 'POST') return send(200, fabric.coverageLifecycle.revalidate(p, await body(req)));
      if (path === '/v1/versions' && req.method === 'POST') return send(201, fabric.versions.publish(p, await body(req)));
      if (path === '/v1/versions' && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin', 'security']); return send(200, fabric.store.list(p.tenant_id, 'version-lifecycle')); }
      if (path === '/v1/advisory/capabilities' && req.method === 'POST') return send(201, fabric.advisory.issue(p, await body(req)));
      if (path === '/v1/advisory/extract' && req.method === 'POST') return send(200, fabric.advisory.extract(p, await body(req)));
      if (path === '/v1/advisory/regressions' && req.method === 'POST') return send(201, fabric.runAdvisoryRegression(p, await body(req)));
      if (path === '/v1/advisory/promotions' && req.method === 'POST') return send(201, fabric.promoteAdvisory(p, await body(req)));
      if (path === '/v1/audit-views' && req.method === 'POST') { const input = await body(req); fields(input, ['role', 'purpose']); return send(200, fabric.auditView(p, input.role, input.purpose)); }
      if (path === '/v1/notifications' && req.method === 'GET') { fabric.authorize(p, ['security', 'policy_admin']); return send(200, fabric.store.list(p.tenant_id, 'notification')); }
      if (path === '/v1/alerts' && req.method === 'POST') return send(201, fabric.operations.alert(p, await body(req)));
      if ((m = /^\/v1\/alerts\/([A-Za-z0-9_.:-]+)\/acknowledge$/.exec(path)) && req.method === 'POST') { fields(await body(req), []); return send(200, fabric.operations.acknowledge(p, m[1])); }
      if (path === '/v1/alerts/sweep' && req.method === 'POST') { fields(await body(req), []); return send(200, fabric.operations.sweepAlerts(p)); }
      if (path === '/v1/incidents' && req.method === 'POST') return send(201, fabric.operations.incident(p, await body(req)));
      if (path === '/v1/incidents/transitions' && req.method === 'POST') return send(200, fabric.operations.transitionIncident(p, await body(req)));
      if (path === '/v1/deployments/stage' && req.method === 'POST') return send(201, fabric.operations.stageDeployment(p, await body(req)));
      if (path === '/v1/deployments/rollback' && req.method === 'POST') return send(200, fabric.operations.rollbackDeployment(p, await body(req)));
      if (path === '/v1/certificates' && req.method === 'POST') { const input = await body(req); fields(input, ['capsule_id']); identifier(input.capsule_id); return send(201, fabric.certificate(p, input.capsule_id)); }
      if ((m = /^\/v1\/certificates\/([A-Za-z0-9-]+)$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin', 'security']); return send(200, fabric.store.must(p.tenant_id, 'certificate', m[1]).envelope); }
      if (path === '/gate/v1/execute' && req.method === 'POST') { const input = await body(req); fields(input, ['certificate', 'dry_run']); requireThat(typeof input.dry_run === 'boolean', 'INV-400-SCHEMA', 'dry_run must be boolean'); return send(200, fabric.execute(p, input.certificate, { dryRun: input.dry_run })); }
      if ((m = /^\/gate\/v1\/outcomes\/([A-Za-z0-9-]+)$/.exec(path)) && req.method === 'GET') return send(200, fabric.reconcile(p, m[1]));
      if ((m = /^\/v1\/resources\/([A-Za-z0-9_.:-]+)$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin']); const state = fabric.target.state(p.tenant_id, m[1]); if (Array.isArray(state.material_fields.rows)) throw new InvariantError('INV-403-SCOPE', 'Use a data capability for dataset access', 403); return send(200, state); }
      if (path === '/v1/capabilities' && req.method === 'POST') { fabric.authorize(p, ['operator', 'workload']); return send(201, fabric.runtime.issue(p, await body(req))); }
      if (path === '/gate/v1/runtime' && req.method === 'POST') return send(200, fabric.runtime.consume(p, await body(req)));
      if (path === '/v1/revocations' && req.method === 'POST') return send(201, fabric.revoke(p, await body(req)));
      if (path === '/v1/coverage' && req.method === 'GET') return send(200, fabric.coverage(p));
      if (path === '/v1/coverage' && req.method === 'POST') return send(201, fabric.declareCoverage(p, await body(req)));
      if (path === '/v1/connectors' && req.method === 'GET') return send(200, fabric.target.manifest());
      if (path === '/v1/policies/simulate' && req.method === 'POST') return send(200, fabric.simulate(p, await body(req)));
      if (path === '/v1/policies/promotion-challenge' && req.method === 'POST') return send(200, fabric.policyPromotionChallenge(p, await body(req)));
      if (path === '/v1/policies/promotions' && req.method === 'POST') return send(201, fabric.promotePolicy(p, await body(req)));
      if (path === '/v1/audit-exports' && req.method === 'POST') { const input = await body(req); fields(input, ['purpose']); return send(200, fabric.exportAudit(p, input.purpose)); }
      if (path === '/v1/retention/hold' && req.method === 'POST') return send(200, fabric.retention(p, await body(req)));
      if (path === '/v1/retention/sweep' && req.method === 'POST') { fields(await body(req), []); return send(200, fabric.retentionSweep(p)); }
      if (path === '/v1/metrics' && req.method === 'GET') { fabric.authorize(p, ['security']); return send(200, { ...metrics, scope: 'process', analytics_enabled: false }); }
      if (path.startsWith('/v1/secure-perception')) throw new InvariantError('INV-501-HARDWARE', 'Secure Perception is unavailable; no plaintext release or secure-mode claim is permitted', 501);
      throw new InvariantError('INV-404-NOT-FOUND', 'Resource not found', 404);
    } catch (e) {
      metrics.errors++; if (e.status === 401) metrics.unauthorised++;
      const known = e instanceof InvariantError;
      if (!res.headersSent) send(known ? e.status : 500, { error: { code: known ? e.code : 'INV-500-INTERNAL', message: known ? e.message : 'Internal failure; contact the operator with the request id', request_id: requestId } });
      else if (!res.writableEnded) res.destroy();
      // Never log request bodies, tokens, target fields, or raw exception text.
      if (!known) process.stderr.write(JSON.stringify({ level: 'error', request_id: requestId, code: 'INV-500-INTERNAL' }) + '\n');
    }
  });
  // Response writes surface EPIPE on the underlying socket, not necessarily ServerResponse.
  server.on('connection', socket => socket.on('error', () => { metrics.errors++; }));
  server.on('clientError', (_error, socket) => { metrics.errors++; socket.destroy(); });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100;
  return { server, sessions, metrics, listen: () => new Promise(resolve => server.listen(port, host, resolve)), close: () => new Promise((resolve, reject) => { server.closeAllConnections(); server.close(e => e ? reject(e) : resolve()); }) };
}
