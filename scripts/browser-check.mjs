import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createConfiguration, seedSyntheticResources } from '../src/bootstrap.mjs';
import { Fabric } from '../src/fabric.mjs';
import { createServer } from '../src/server.mjs';
import { signed } from '../src/crypto.mjs';
import { digest } from '../src/canonical.mjs';
const directory = mkdtempSync(join(tmpdir(), 'if-browser-')), setup = createConfiguration(['acme']), fabric = new Fabric(setup.config, directory);
seedSyntheticResources(fabric, ['acme']);
const app = createServer(fabric, { port: 17788, origin: 'http://127.0.0.1:17788' }), errors = [], failures = [], checks = [];
let browser;
mkdirSync('reports/browser', { recursive: true });
const check = (name, value) => { assert.ok(value, name); checks.push(name); };
try {
 await app.listen(); browser = await chromium.launch({ headless: true }); const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' }), page = await context.newPage();
 page.on('pageerror', e => errors.push(e.message)); page.on('requestfailed', r => failures.push(r.url()));
 await page.goto('http://127.0.0.1:17788/'); await page.getByRole('heading', { name: 'Trust is a premise. Proof is a system.' }).waitFor();
 for (const width of [1440, 900, 390]) {
   await page.setViewportSize({ width, height: 1000 });
   check(`landing-no-horizontal-overflow-${width}`, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
   await page.screenshot({ path: `reports/browser/landing-${width}.png`, fullPage: true });
 }
 await page.getByRole('link', { name: 'See how it works' }).click(); check('landing-anchor-navigation', page.url().endsWith('#system'));
 await page.getByRole('link', { name: 'Open workspace', exact: false }).first().click(); await page.getByLabel('Locally provisioned access token').waitFor();
 await page.getByLabel('Locally provisioned access token').fill('x'.repeat(43)); await page.getByRole('button', { name: 'Connect to workspace' }).click(); await page.getByRole('alert').waitFor(); check('login-invalid-token-error', await page.locator('#notice').isVisible());
 await page.getByLabel('Locally provisioned access token').fill(setup.credentials.acme.operator); await page.getByRole('button', { name: 'Connect to workspace' }).click(); await page.locator('#workspace').waitFor({ state: 'visible' }); await page.locator('#empty').waitFor({ state: 'visible' });
 check('token-cleared-after-login', await page.getByLabel('Locally provisioned access token').inputValue() === ''); check('no-browser-persistent-credentials', await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0));
 await page.setViewportSize({ width: 1440, height: 1000 }); await page.screenshot({ path: 'reports/browser/workspace-empty.png', fullPage: true });
 await page.getByRole('button', { name: 'Propose action', exact: true }).click(); await page.getByLabel('Finance action').selectOption('finance.beneficiary.create'); await page.getByLabel('Target resource identifier').fill('browser-beneficiary');
 await page.getByRole('button', { name: 'Read current target state' }).click(); await page.waitForFunction(() => document.getElementById('state-preview').textContent.includes('digest'));
 await page.getByLabel('Business purpose').fill('Browser-verified synthetic beneficiary'); await page.getByLabel('vendor id', { exact: true }).fill('vendor-1'); await page.getByLabel('bank account', { exact: true }).fill('TESTBANK000009'); await page.getByLabel('currency', { exact: true }).fill('EUR'); await page.getByLabel('Validity in minutes').fill('10'); await page.getByLabel('Rollback or compensation procedure').fill('Reconcile first; submit a separate authorised action for compensation'); await page.getByRole('button', { name: 'Create immutable proposal' }).click();
 await page.locator('#detail-title').filter({ hasText: 'finance.beneficiary.create' }).waitFor(); const id = await page.locator('#detail-id').textContent();
 await page.getByRole('button', { name: 'Evaluate exact action' }).click(); await page.waitForFunction(() => document.getElementById('detail-status').textContent === 'ESCROW'); check('non-allow-cannot-mint', await page.locator('#mint').isDisabled());
 const record = fabric.getCapsule({ tenant_id: 'acme', subject_id: 'operator' }, id);
 for (const issuer of ['bank', 'registry']) {
   const now = Date.now(), payload = { evidence_id: crypto.randomUUID(), tenant_id: 'acme', capsule_digest: record.capsule_digest, kind: 'ownership', content_digest: digest({ synthetic: true, issuer }), acquired_at: now, expires_at: now + 300000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'Synthetic browser-test issuer', retention_until: now + 600000 };
   await page.getByLabel('Signed evidence envelope', { exact: true }).fill(JSON.stringify(signed(payload, setup.issuerKeys.acme[issuer], 'evidence'))); await page.getByRole('button', { name: 'Attach signed evidence' }).click(); await page.waitForFunction(() => document.getElementById('evidence-json').value === '');
 }
 for (const subject of ['custodian-1', 'custodian-2']) {
   const c = await browser.newContext(), reviewer = await c.newPage(); await reviewer.goto('http://127.0.0.1:17788/workspace'); await reviewer.getByLabel('Locally provisioned access token').fill(setup.credentials.acme[subject]); await reviewer.getByRole('button', { name: 'Connect to workspace' }).click(); await reviewer.getByRole('button', { name: 'Review exact action', exact: true }).click();
   const downloadPromise = reviewer.waitForEvent('download'); await reviewer.getByRole('button', { name: 'Download exact approval challenge' }).click(); const download = await downloadPromise; check(`exact-challenge-download-${subject}`, download.suggestedFilename().includes(id));
   const challenge = fabric.approvalChallenge({ tenant_id: 'acme', subject_id: subject }, id); await reviewer.getByLabel('Offline-signed approval envelope').fill(JSON.stringify(signed(challenge, setup.custodianKeys.acme[subject], 'action-approval'))); await reviewer.getByRole('button', { name: 'Submit signature for this exact action' }).click(); await reviewer.waitForFunction(() => document.getElementById('approval-json').value === ''); await c.close();
 }
 await page.getByRole('button', { name: 'Evaluate exact action' }).click(); await page.waitForFunction(() => document.getElementById('detail-status').textContent === 'ALLOW'); await page.getByRole('button', { name: 'Mint single-use certificate' }).click(); await page.waitForFunction(() => document.getElementById('detail-status').textContent === 'CERTIFIED');
 await page.getByRole('button', { name: 'Dry-run target gate' }).click(); await page.waitForFunction(() => document.getElementById('outcome').textContent.includes('no_mutation')); check('dry-run-does-not-mutate', fabric.target.state('acme', 'browser-beneficiary').version === 0);
 page.once('dialog', d => d.accept()); await page.getByRole('button', { name: 'Execute exact simulated change' }).click(); await page.waitForFunction(() => document.getElementById('detail-status').textContent === 'VERIFIED'); check('real-browser-exact-workflow', fabric.target.state('acme', 'browser-beneficiary').version === 1); check('verified-cannot-execute-twice', await page.locator('#execute').isDisabled());
 for (const width of [1440, 900, 390]) { await page.setViewportSize({ width, height: 1000 }); check(`detail-no-horizontal-overflow-${width}`, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); await page.screenshot({ path: `reports/browser/detail-${width}.png`, fullPage: true }); }
 await page.getByRole('button', { name: 'Coverage', exact: true }).click(); await page.locator('#coverage-cards .callout').waitFor(); check('coverage-honest-empty-state', (await page.locator('#coverage-cards').textContent()).includes('unknown'));
 await page.getByRole('button', { name: 'Runtime access', exact: true }).click(); await page.getByLabel('Allowed row identifiers, comma-separated').fill('row-1'); await page.getByLabel('Allowed columns, comma-separated').fill('id,name'); await page.getByLabel('Maximum information units for this capability').fill('4'); await page.getByRole('button', { name: 'Issue narrow capability' }).click(); await page.locator('#runtime-read').waitFor(); await page.getByRole('button', { name: 'Read exact authorised selection' }).click(); await page.waitForFunction(() => document.getElementById('runtime-result').textContent.includes('Synthetic Ada')); check('browser-scoped-data-flow', !(await page.locator('#runtime-result').textContent()).includes('passport'));
 await page.setViewportSize({ width: 1440, height: 1000 }); await page.screenshot({ path: 'reports/browser/runtime.png', fullPage: true });
 await page.getByRole('button', { name: 'Audit export', exact: true }).click(); await page.getByLabel('Export scope').selectOption('finance'); await page.getByLabel('Authorised export purpose').fill('Browser test least-privilege export'); const auditDownload = page.waitForEvent('download'); await page.getByRole('button', { name: 'Download signed audit bundle' }).click(); check('audit-projection-download', (await auditDownload).suggestedFilename().includes('finance'));
 const missing = await page.evaluate(() => [...document.querySelectorAll('input,textarea,select')].filter(el => !el.labels?.length).map(el => el.id)); check('all-controls-have-labels', missing.length === 0);
 check('reduced-motion-honored', await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior === 'auto'));
 await context.setOffline(true); await page.getByRole('button', { name: 'Actions', exact: true }).click(); await page.getByRole('alert').waitFor(); check('offline-error-visible', await page.locator('#notice').isVisible()); await context.setOffline(false);
 await page.getByRole('button', { name: 'Sign out' }).click(); await page.getByLabel('Locally provisioned access token').waitFor(); check('logout-clears-workspace', await page.locator('#workspace').isHidden());
 check('no-browser-javascript-errors', errors.length === 0); check('no-unexpected-network-failures', failures.every(url => url.endsWith('/v1/action-capsules?limit=25&offset=0')));
 writeFileSync('reports/browser/results.json', JSON.stringify({ status: 'PASS', checks, javascript_errors: errors, expected_offline_failures: failures, visual_review: 'Screenshots generated; human/model image inspection is separately required', production_ready: false }, null, 2) + '\n'); console.log(JSON.stringify({ browser: 'PASS', checks: checks.length }));
} catch (error) {
 writeFileSync('reports/browser/results.json', JSON.stringify({ status: 'FAIL', checks, error: error.message, javascript_errors: errors, failures }, null, 2) + '\n'); throw error;
} finally { if (browser) await browser.close(); await app.close(); fabric.close(); rmSync(directory, { recursive: true }); }
