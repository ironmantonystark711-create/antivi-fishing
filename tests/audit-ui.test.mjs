import test from 'node:test';
import assert from 'node:assert/strict';
import { auditOptions } from '../web/app.js';

test('AUD-010 UX-010: UI audit choices never widen role-specific server permissions', () => {
  assert.deepEqual(auditOptions(['operator']), []);
  assert.deepEqual(auditOptions(['workload']), []);
  for (const scope of ['finance', 'security', 'privacy', 'technical']) assert.deepEqual(auditOptions([`audit_${scope}`]).map(o => o.value), [scope]);
  assert.deepEqual(auditOptions(['security']).map(o => o.value), ['full']);
  assert.deepEqual(auditOptions(['auditor']).map(o => o.value), ['full']);
  assert.deepEqual(auditOptions(['audit_finance', 'audit_privacy']).map(o => o.value), ['finance', 'privacy']);
});
