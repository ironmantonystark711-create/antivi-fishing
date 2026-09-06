import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const generated = spawnSync('python3', ['scripts/completion-ledger.py'], { encoding: 'utf8' });
if (generated.status !== 0) { console.error(generated.stderr); process.exit(1); }
const state = JSON.parse(readFileSync('reports/completion-state.json', 'utf8'));
const acceptance = JSON.parse(readFileSync('docs/production-acceptance.json', 'utf8'));
const unmet = state.requirements.filter(r => r.status !== 'VERIFIED');
const externalAcceptance = acceptance.items.filter(item => item.status !== 'VERIFIED');
const pass = unmet.length === 0 && state.current_verification?.pass === true && externalAcceptance.length === 0 && acceptance.production_ready === true;
console.log(JSON.stringify({ production_release: pass ? 'PASS' : 'BLOCKED', software_requirements: { VERIFIED: state.VERIFIED, PARTIAL: state.PARTIAL, NOT_IMPLEMENTED: state.NOT_IMPLEMENTED, BLOCKED_EXTERNAL: state.BLOCKED_EXTERNAL }, external_acceptance: externalAcceptance, engineering_tests_do_not_override_external_acceptance: true }, null, 2));
if (!pass) process.exitCode = 1;
