# Invariant Fabric

**Engineering release — not approved for production use.** This repository contains executable software for substantial parts of IF-02, synthetic target simulations, a control workspace, adversarial tests, offline verifiers, and a source-derived requirement ledger. It is **not the complete R0–R5 production platform**. Read [production acceptance](docs/PRODUCTION-ACCEPTANCE.md) before assigning any security guarantee.

The application uses Node.js 24 built-in HTTP, SQLite, cryptography, test runner, and worker threads without third-party application dependencies. CI targets Node 24.16.0 on Linux x64; local evidence records its exact runtime (currently 24.19.0). Python 3 and Bun are required for the complete independent-verifier suite; CI pins Bun 1.3.14. Pinned Playwright is a development-only dependency for real Chromium verification.

## Start locally

From this directory, with the tested Node runtime installed:

```sh
node src/cli.mjs init --dir ./var/local
node src/cli.mjs serve --dir ./var/local --port 8080
```

Open **http://127.0.0.1:8080**. The bootstrap command prints file paths, not secret values. Use the appropriate locally generated token in `var/local/access-tokens.json` in the console sign-in form. The `acme` tenant has separate operator, security, auditor, policy administrator, and five approval/custodian identities. No credentials are shipped in this ZIP. Tokens and synthetic device-health statements expire after 24 hours; this release intentionally has no unprotected renewal or recovery override. Create a **new** isolated deployment for another evaluation; never delete an existing deployment containing needed evidence.

Bootstrap creates software execution/audit keys and separate offline custodian/issuer key files with restrictive file permissions. They are initially on one machine for synthetic evaluation; this is **not independent physical custody, MPC, an HSM quorum, or WebAuthn**. Do not load custodian private keys into the web UI. The server only knows their public keys.

The development server binds only to loopback. It rejects non-engineering mode and non-loopback binding. It must not be exposed as a public production service. The HTTPS reverse-proxy template is for controlled staging review, not an assertion that production acceptance passed.

## What runs

Typed capsules cover four finance workflows and nine additional action classes. The local flow is proposal → signed evidence → deterministic decision → independent exact-action signatures → single-use certificate → state-bound simulated mutation → signed observed outcome. Finance changes run against a separate persistent synthetic SQLite target, never a real bank or ERP. Runtime capabilities enforce subject, device, resource, destination, selection, expiry, rate and shared rolling budgets. The network module includes an actual allowlisted loopback HTTP proxy; this is **not** host-wide packet interception or proof that all target access paths are mediated.

The console provides finance proposals, exact old/new action review, signed evidence and approval submission, evaluation, certificate minting, dry run, execution, reconciliation, cancellation, coverage limitations, policy simulation, runtime synthetic reads, and audited evidence export. There are no fake approval buttons or generated claims that a normal browser is a secure display.

See [WORKFLOWS.md](docs/WORKFLOWS.md) for exact operation and signing instructions; [API.md](docs/API.md) and [openapi.json](docs/openapi.json) describe the API. The original SRS is preserved in `spec/`; its two referenced image assets were not included with the supplied document.

## Verify and reproduce

```sh
node scripts/check.mjs
node scripts/completion.mjs --run-tests
node scripts/simulate.mjs
node scripts/verify-export.mjs reports/sample-audit.json reports/sample-pinned-trust.json
python3 scripts/canonical-vectors.py examples/canonical-vectors.json
bun scripts/verify-export-webcrypto.mjs reports/sample-audit.json reports/sample-pinned-trust.json
node scripts/benchmark.mjs
node scripts/release-check.mjs
```

For browser verification, run `npm ci --ignore-scripts`, `npx playwright install --with-deps chromium`, then `npm run test:browser`. Set `IF_RECORD_BROWSER=1` to also capture the isolated finance-export flow. `node scripts/completion.mjs --require-complete` is the separate internal SRS completion gate and currently fails because acceptance work remains open.

`release-check` **must exit nonzero** for this delivery: production blockers are deliberately enforced. Do not change a status to pass without the required independently reviewed evidence. Verification reports bundled in `reports/` distinguish direct execution, simulation, analysis, and unavailable checks. Source checks are not a SAST certification. HTTP/static UI tests are not browser or accessibility certification.

All test databases and private fixture keys are generated in unique temporary directories. Tests remove only their own fixtures. The simulator writes public synthetic audit evidence and result files under `reports/`. Sample trust keys authenticate only the supplied synthetic audit, not the release publisher or a real customer.

## Boundaries that remain

Customer systems and credentials were unavailable. There is no real ERP/bank/cloud/identity/backup/secret connector, HSM or threshold cryptographic integration, packet enforcement, trusted display/input implementation, remote attestation verifier, multi-zone consensus, enterprise authentication lifecycle, or independently witnessed production deployment. SQLite plus application-level AES-GCM is a single-host engineering profile, not a high-availability customer key-management architecture.

The target system and gate use the same customer-local process privilege boundary; a process/host compromise can bypass the simulator. The supplied signature quorum is a software multisignature workflow, not protection against compromise of the machine holding generated fixture keys. An independent verifier with a previously pinned checkpoint detects a conflicting prefix; external witness hosting and publication are not deployed.

Real Chromium interaction and responsive-layout checks run locally and in CI; screenshots and a focused export recording are available as review evidence. This is not a full WCAG audit, human comprehension study, independent penetration test or production deployment acceptance. Browser tooling and documentation access are available and are not external blockers.

Current acceptance status, owners, baselines and source-bound executable evidence are in [COMPLETION_LEDGER.md](docs/COMPLETION_LEDGER.md), covering all 211 numbered requirements plus nonnumbered normative clauses. [SRS_SECOND_PASS.md](docs/SRS_SECOND_PASS.md) records the independent-review findings and remaining internal work. Historical `requirements.csv` statuses are not acceptance authority. Passing software tests does not close hardware, organisational, legal, real-system or independent-assessment requirements.
