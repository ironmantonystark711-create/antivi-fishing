import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { enumerateRequirements, parseTap, assessRequirement, sha256 } from '../scripts/completion.mjs';

test('NFR-TST-001 TRACE-001: ledger enumerates the SRS, not historical completion arrays', () => {
  const rows = enumerateRequirements(readFileSync(new URL('../spec/Invariant_Fabric_SRS_and_System_Architecture.md', import.meta.url), 'utf8'));
  assert.equal(rows.filter(r => r.numbered).length, 211);
  assert.equal(rows.filter(r => r.id.startsWith('FAIL-')).length, 10);
  for (const [prefix, count] of [['TB-', 7], ['UC-', 12], ['OBJ-', 7], ['IFC-', 12], ['ERR-', 9], ['VFY-', 6], ['REL-', 6], ['DSN-', 7]]) assert.equal(rows.filter(r => r.id.startsWith(prefix)).length, count, prefix);
  assert.ok(rows.some(r => r.id === 'TRACE-001'));
  assert.ok(rows.every(r => r.requirement && r.acceptance && r.line > 0));
  assert.throws(() => enumerateRequirements('| ACT-001 | One | Two |\n| ACT-001 | Duplicate | Three |'));
});

test('NFR-TST-001: missing, stale, failed and merely ID-named evidence never closes a requirement', () => {
  const requirement = { id: 'ACT-001', requirement: 'Exact action', acceptance: 'Prove exact binding' };
  const execution = { source_fingerprint: 'source', exit_code: 0, failed: 0, skipped: 0, cancelled: 0, todo: 0, tests: [{ name: 'exact-action-tampering', passed: true }] };
  const review = { requirement_digest: sha256('Exact action\nProve exact binding'), source_fingerprint: 'source', status: 'VERIFIED', software_complete: true, acceptance_complete: true, implementation: ['src/canonical.mjs'], tests: ['exact-action-tampering'], rationale: 'Reviewed fields and adversarial mutation coverage', owner: 'Security maintainer', release_baseline: 'R0' };
  assert.equal(assessRequirement(requirement, null, execution, 'source').status, 'PARTIAL');
  assert.equal(assessRequirement(requirement, review, execution, 'source').status, 'VERIFIED');
  for (const invalid of [{ ...review, tests: ['ACT-001'] }, { ...review, implementation: [] }, { ...review, requirement_digest: 'old' }, { ...review, source_fingerprint: 'old' }, { ...review, acceptance_complete: false }]) assert.equal(assessRequirement(requirement, invalid, execution, 'source').status, 'PARTIAL');
  for (const invalid of [null, { ...execution, exit_code: 1 }, { ...execution, skipped: 1 }, { ...execution, source_fingerprint: 'old' }, { ...execution, tests: [] }]) assert.equal(assessRequirement(requirement, review, invalid, 'source').status, 'PARTIAL');
  assert.equal(assessRequirement(requirement, { ...review, status: 'BLOCKED_EXTERNAL', software_complete: false, blocker_reason: 'Hardware' }, execution, 'source').status, 'PARTIAL');
});

test('NFR-TST-001: execution parser preserves failures and rejects skipped tests as proof', () => {
  const result = parseTap('ok 1 - first\nnot ok 2 - adversarial\nok 3 - third # SKIP\n# tests 3\n# pass 1\n# fail 1\n# skipped 1\n# cancelled 0\n# todo 0\n');
  assert.equal(result.failed, 1); assert.equal(result.skipped, 1);
  assert.deepEqual(result.tests.map(t => t.passed), [true, false, false]);
});
