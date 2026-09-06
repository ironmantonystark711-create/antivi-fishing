import test from 'node:test';
import assert from 'node:assert/strict';
import { auditOptions, workspaceAccess } from '../web/app.js';

test('AUD-010 UX-010: UI audit choices never widen role-specific server permissions', () => {
  assert.deepEqual(auditOptions(['operator']), []);
  assert.deepEqual(auditOptions(['workload']), []);
  for (const scope of ['finance', 'security', 'privacy', 'technical']) assert.deepEqual(auditOptions([`audit_${scope}`]).map(o => o.value), [scope]);
  assert.deepEqual(auditOptions(['security']).map(o => o.value), ['full']);
  assert.deepEqual(auditOptions(['auditor']).map(o => o.value), ['full']);
  assert.deepEqual(auditOptions(['audit_finance', 'audit_privacy']).map(o => o.value), ['finance', 'privacy']);
});

test('AUD-010 UX-010: role-scoped reviewers cannot navigate to unauthorized coverage or action data', () => {
  for (const scope of ['finance', 'security', 'privacy', 'technical']) {
    assert.deepEqual(workspaceAccess([`audit_${scope}`]), { batches: false, actions: false, propose: false, coverage: false, policy: false, runtime: false, audit: true });
  }
  assert.equal(workspaceAccess(['operator']).coverage, true);
  assert.equal(workspaceAccess(['auditor']).coverage, true);
});
