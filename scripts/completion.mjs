import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
export const sha256 = value => createHash('sha256').update(value).digest('hex');
const specPath = 'spec/Invariant_Fabric_SRS_and_System_Architecture.md';
const json = path => existsSync(join(root, path)) ? JSON.parse(readFileSync(join(root, path), 'utf8')) : null;
const save = (path, value) => writeFileSync(join(root, path), JSON.stringify(value, null, 2) + '\n');

export function enumerateRequirements(source) {
  const rows = []; let section = '', component = 0, failure = 0;
  const counts = {};
  const additionalTables = {
    '# 8. Canonical data model': 'OBJ',
    '# 9. External and internal interfaces': 'IFC',
    '## 9.1 Error and decision semantics': 'ERR',
    '# 11. Verification strategy and traceability': 'VFY',
    '# 12. Release baselines and acceptance gates': 'REL',
    '# 14. Open design decisions requiring prototype evidence': 'DSN'
  };
  for (const [index, line] of source.split('\n').entries()) {
    if (line.startsWith('#')) section = line;
    const parts = line.split('|').map(s => s.trim());
    if (/^(?:[A-Z]{2,3}|NFR-[A-Z]+)-\d{3}$/.test(parts[1] ?? '')) {
      rows.push({ id: parts[1], requirement: parts[2], acceptance: parts[3], line: index + 1, numbered: true });
    } else if (parts.length >= 5 && parts[1] && !parts[1].startsWith('*') && !parts[1].startsWith('-')) {
      if (section === '## 4.1 Component responsibilities') rows.push({ id: `ARCH-${String(++component).padStart(3, '0')}`, requirement: `${parts[1]}: ${parts[2]}`, acceptance: `Must not: ${parts[3]}`, line: index + 1, numbered: false });
      if (section === '# 10. Failure, compromise and recovery behaviour') rows.push({ id: `FAIL-${String(++failure).padStart(3, '0')}`, requirement: `${parts[1]}: ${parts[2]}`, acceptance: `Forbidden: ${parts[3]}`, line: index + 1, numbered: false });
      const prefix = additionalTables[section];
      if (prefix) rows.push({ id: `${prefix}-${String(counts[prefix] = (counts[prefix] ?? 0) + 1).padStart(3, '0')}`, requirement: `${parts[1]}: ${parts[2]}`, acceptance: parts[3], line: index + 1, numbered: false });
    }
    const boundary = /^- (TB-\d+): (.+)$/.exec(line);
    if (boundary) rows.push({ id: boundary[1], requirement: boundary[2], acceptance: 'Demonstrate the stated trust boundary under compromise.', line: index + 1, numbered: false });
    const useCase = /^(UC-\d+) (.+)$/.exec(parts[1] ?? '');
    if (section === '# 5. Principal use cases' && useCase) rows.push({ id: useCase[1], requirement: useCase[2], acceptance: parts[2], line: index + 1, numbered: false });
    if (line.startsWith('> **Traceability rule.**')) rows.push({ id: 'TRACE-001', requirement: line.slice(2), acceptance: 'Owner, baseline, method and stored evidence for every mandatory requirement.', line: index + 1, numbered: false });
  }
  if (new Set(rows.map(r => r.id)).size !== rows.length) throw new Error('Duplicate SRS requirement identifier');
  return rows;
}

export function sourceFingerprint() {
  const files = [];
  function visit(path) {
    if (!existsSync(join(root, path))) return;
    for (const entry of readdirSync(join(root, path), { withFileTypes: true })) {
      const next = join(path, entry.name);
      if (entry.isDirectory()) visit(next); else files.push(next);
    }
  }
  for (const path of ['src', 'tests', 'scripts', 'web', 'spec', 'examples', '.github', 'deploy']) visit(path);
  for (const path of ['package.json', 'package-lock.json', '.hoplite/settings.json']) if (existsSync(join(root, path))) files.push(path);
  return sha256(files.sort().map(path => `${path}\0${sha256(readFileSync(join(root, path)))}`).join('\n'));
}

export function parseTap(output) {
  const tests = [...output.matchAll(/^(ok|not ok) \d+ - (.+)$/gm)].map(m => ({ name: m[2].replace(/\\#/g, '#'), passed: m[1] === 'ok' && !/ # (?:SKIP|TODO)/.test(m[2]) }));
  const number = name => Number(new RegExp(`^# ${name} (\\d+)$`, 'm').exec(output)?.[1] ?? -1);
  return { tests, total: number('tests'), passed: number('pass'), failed: number('fail'), skipped: number('skipped'), cancelled: number('cancelled'), todo: number('todo') };
}

export function assessRequirement(requirement, review, execution, fingerprint) {
  const pending = { status: 'PARTIAL', blocker_reason: null, remaining_work: review?.remaining_work ?? 'Review full implementation and acceptance criteria; test-name references alone do not establish closure.' };
  if (!review) return pending;
  if (review.requirement_digest !== sha256(requirement.requirement + '\n' + requirement.acceptance)) return { ...pending, remaining_work: 'SRS text changed; repeat requirement review.' };
  if (review.source_fingerprint !== fingerprint || execution?.source_fingerprint !== fingerprint) return { ...pending, remaining_work: 'Source or executable evidence changed; rerun verification and requirement review.' };
  const checks = review.tests ?? [];
  if (!checks.length || !review.implementation?.length || !review.rationale || !review.owner || !review.release_baseline || !execution || execution.exit_code !== 0 || execution.failed !== 0 || execution.skipped !== 0 || execution.cancelled !== 0 || execution.todo !== 0 || !checks.every(name => execution.tests.some(t => t.name === name && t.passed))) return { ...pending, remaining_work: 'Missing complete passing execution, implementation, owner, baseline or reviewed acceptance evidence.' };
  if (review.status === 'BLOCKED_EXTERNAL' && review.software_complete === true && review.blocker_reason?.trim()) return { status: 'BLOCKED_EXTERNAL', blocker_reason: review.blocker_reason, remaining_work: null };
  if (review.status === 'VERIFIED' && review.software_complete === true && review.acceptance_complete === true) return { status: 'VERIFIED', blocker_reason: null, remaining_work: null };
  return pending;
}

function gitHead() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) throw new Error('Cannot identify verification revision');
  return result.stdout.trim();
}

export function generateLedger() {
  const source = readFileSync(join(root, specPath), 'utf8'), requirements = enumerateRequirements(source), fingerprint = sourceFingerprint();
  const execution = json('reports/completion-tests.json'), reviews = json('docs/completion-reviews.json') ?? {};
  const testFiles = readdirSync(join(root, 'tests')).filter(f => f.endsWith('.test.mjs')).map(f => [`tests/${f}`, readFileSync(join(root, 'tests', f), 'utf8')]);
  const rows = requirements.map(r => {
    const referenced = testFiles.filter(([, text]) => text.includes(r.id));
    const implementations = [...new Set(referenced.flatMap(([, text]) => [...text.matchAll(/from ['"]\.\.\/(src\/[^'"]+)['"]/g)].map(m => m[1])))];
    return { ...r, ...assessRequirement(r, reviews[r.id], execution, fingerprint), implementation: reviews[r.id]?.implementation ?? implementations, tests: reviews[r.id]?.tests ?? execution?.tests.filter(t => t.name.includes(r.id)).map(t => t.name) ?? [], test_files: referenced.map(([p]) => p), verification_evidence: execution?.source_fingerprint === fingerprint ? 'reports/completion-tests.json' : null, owner: reviews[r.id]?.owner ?? 'Principal engineering review pending', release_baseline: reviews[r.id]?.release_baseline ?? 'Full SRS closure' };
  });
  const counts = { VERIFIED: 0, PARTIAL: 0, NOT_IMPLEMENTED: 0, BLOCKED_EXTERNAL: 0 };
  for (const row of rows) counts[row.status]++;
  const state = { format: 'IF-COMPLETION-1', baseline_commit: '7d92076602d6c6485aa96bcb2a26bfac11afd861', source_revision: gitHead(), source_fingerprint: fingerprint, srs_sha256: sha256(source), total_requirements: rows.length, numbered_requirements: rows.filter(r => r.numbered).length, counts, failing_tests: execution?.tests.filter(t => !t.passed).map(t => t.name) ?? [], execution_current: execution?.source_fingerprint === fingerprint, ci_state: json('reports/completion-ci.json') ?? { status: 'NOT_VERIFIED', reason: 'No provider result recorded for this revision.' }, performance_state: json('reports/benchmark.json'), browser_state: json('reports/browser/results.json') ?? { status: 'NOT_RUN' }, complete: false, next_action: rows.find(r => r.status === 'PARTIAL')?.id ?? 'Run independent second audit and clean final-revision verification', remaining_work: rows.filter(r => r.remaining_work).map(r => ({ id: r.id, work: r.remaining_work })), requirements: rows };
  mkdirSync(join(root, 'reports'), { recursive: true }); save('reports/completion-state.json', state);
  const escape = text => String(text ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
  writeFileSync(join(root, 'docs/COMPLETION_LEDGER.md'), '# SRS completion ledger\n\nGenerated by `node scripts/completion.mjs`. This replaces, rather than endorses, historical hard-coded completion claims. Source fingerprint: `' + fingerprint + '`. Numbered requirements: ' + state.numbered_requirements + '; additional architecture, trust-boundary, use-case, object, interface, failure, verification, release and design-evidence clauses: ' + (rows.length - state.numbered_requirements) + '.\n\nA passing test that mentions an ID is a candidate evidence link, **not** proof of the full requirement. Closure requires a source-bound acceptance review and executed test results. No inherited status is trusted.\n\nCounts: `' + JSON.stringify(counts) + '`. Final completion has not been established.\n\n| ID / SRS line | Requirement / acceptance | Implementation | Tests / evidence | Status / remaining work |\n|---|---|---|---|---|\n' + rows.map(r => `| ${r.id} / ${r.line} | ${escape(r.requirement)} **Acceptance:** ${escape(r.acceptance)} | ${escape(r.implementation.join('; '))} | ${escape(r.tests.join('; '))}; ${r.verification_evidence ?? 'No current execution'} | ${r.status}: ${escape(r.blocker_reason ?? r.remaining_work)} |`).join('\n') + '\n');
  console.log(JSON.stringify({ total: rows.length, counts, execution_current: state.execution_current }));
  return state;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--run-tests')) {
    const before = sourceFingerprint(), args = ['--test', '--test-reporter=tap', '--test-concurrency=1', ...readdirSync(join(root, 'tests')).filter(f => f.endsWith('.test.mjs')).sort().map(f => `tests/${f}`)];
    const run = spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    process.stdout.write(run.stdout ?? '');
    process.stderr.write(run.stderr ?? '');
    mkdirSync(join(root, 'reports'), { recursive: true }); writeFileSync(join(root, 'reports/completion-tests.tap'), run.stdout ?? '');
    const result = { ...parseTap(run.stdout ?? ''), source_revision: gitHead(), source_fingerprint: before, command: `node ${args.join(' ')}`, exit_code: run.status, stderr: run.stderr, environment: { node: process.version, platform: process.platform, arch: process.arch }, finished_at: new Date().toISOString(), source_unchanged: before === sourceFingerprint() };
    if (!result.source_unchanged) result.exit_code = 1;
    save('reports/completion-tests.json', result); process.exitCode = result.exit_code === 0 ? 0 : 1;
    if (result.exit_code !== 0) console.error(JSON.stringify({ failed_tests: result.tests.filter(test => !test.passed).map(test => test.name), source_unchanged: result.source_unchanged, exit_code: result.exit_code }));
  }
  const state = generateLedger();
  if (process.argv.includes('--require-complete') && (!state.complete || state.counts.PARTIAL || state.counts.NOT_IMPLEMENTED)) process.exitCode = 1;
}
