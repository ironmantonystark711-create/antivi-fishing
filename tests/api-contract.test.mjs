import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SUITES } from '../src/suites.mjs';
import { generateKey, signed } from '../src/crypto.mjs';
const api = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
test('NFR-MNT-001: every implemented literal control/gate endpoint has a versioned API operation', () => {
 const source = readFileSync('src/server.mjs', 'utf8');
 for (const match of source.matchAll(/path === '(\/(?:v1|gate\/v1)\/[^']+)' && req.method === '(GET|POST)'/g)) assert.ok(api.paths[match[1]]?.[match[2].toLowerCase()], `${match[2]} ${match[1]} must be documented`);
 for (const path of ['/v1/coverage/{id}/history', '/gate/v1/compositions/{id}/outcome', '/v1/notifications/{id}/acknowledge', '/v1/incidents/{id}']) assert.ok(api.paths[path]);
 assert.deepEqual(api.components.schemas.ExecuteRequest.required, ['certificate','dry_run']);
});
test('KEY-005 NFR-MNT-001: advertised envelope variants accept actual signatures with exact suite-specific lengths', () => {
 const variants = api.components.schemas.Envelope.oneOf;
 assert.deepEqual(variants.map(v => v.properties.protected.properties.suite.const).sort(), Object.keys(SUITES).sort());
 for (const id of Object.keys(SUITES)) {
   const key = generateKey(id), envelope = signed({ value: 1 }, key, 'contract-test'), v = variants.find(v => v.properties.protected.properties.suite.const === id);
   const pattern = new RegExp(v.properties.signature.pattern); assert.ok(pattern.test(envelope.signature)); assert.equal(pattern.test(envelope.signature.slice(1)), false); assert.equal(pattern.test(envelope.signature + '='), false);
 }
});
