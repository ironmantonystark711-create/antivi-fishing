# Independent SRS review checkpoint

The source of requirements is `spec/Invariant_Fabric_SRS_and_System_Architecture.md`, not historical completion arrays. The expanded ledger has 211 numbered requirements and 88 additional architecture, trust-boundary, use-case, object, interface, error, verification, release and design-evidence clauses. A requirement is not closed by its appearance in a test title.

## Findings repaired and exercised

| Area | Repair | Executable evidence |
|---|---|---|
| Composition | Atomic durable reservation of the exact child certificate set; signed aggregate outcome; journal-only restart reconciliation without redispatch. | `tests/governance-hardening.test.mjs`, `tests/composition-crash-worker.mjs`, `tests/composition-http.test.mjs` |
| Identity | Key/subject/device revocation, epoch-invalidated bearer/cookie sessions, device-bound JIT, threshold credential reissue with current custodian assurance. | `tests/key-identity-hardening.test.mjs`, `tests/session-lifecycle.test.mjs` |
| Key lifecycle | Linked threshold ceremonies, predecessor-chain restoration, stale-operation rejection, persisted suite migration deadlines. | `tests/key-identity-hardening.test.mjs` |
| Runtime | Signed bounded local gates, resource-state binding, durable ordered revocation outbox/acknowledgements, loopback HTTP proxy and constrained remediation. | `tests/runtime-network-proxy.test.mjs`, `tests/runtime-hardening.test.mjs` |
| Coverage | Removed fabricated caller evidence and the toy bypass predicate. The runner executes real isolated Fabric/certificate/target operations. Direct simulator-target mutation is detected, so it does not claim total mediation. | `tests/coverage-advisory-hardening.test.mjs` |
| Advisory | Internally bound runtime provenance, stored signed executable regressions, no caller-supplied model evaluation promoted as trusted evidence. | `tests/coverage-advisory-hardening.test.mjs` |
| SHIELD | A transformed export is a new immutable proposal with a new nonce/digest and no inherited evidence or approvals. The original SHIELD decision never mints ALLOW authority. | `tests/data-audit-hardening.test.mjs`, `tests/runtime-audit.test.mjs` |
| Retention | Local encrypted-record erasure includes secure delete, WAL checkpoint and vacuum; legal holds remain enforced. | `tests/data-audit-hardening.test.mjs` |
| Perception | Each delivery revalidates scoped session, device/measurement/attestor revocation and trusted time. Software transport never asserts hostile-OS protection. | `tests/perception-lifecycle.test.mjs` |
| Release provenance | Exact build/review/observation bindings and threshold rollback; revoked or mismatched release evidence fails closed. | `tests/governance-hardening.test.mjs` |
| HTTP/UI | Bounded streaming bodies and aborted transport lifecycle; origin/CSRF/epoch-bound sessions; audit reviewers cannot navigate to unauthorized action or coverage data. | `tests/transport-abort.test.mjs`, `tests/preview-origin.test.mjs`, `tests/audit-ui.test.mjs`, `scripts/browser-check.mjs` |
| Reproducible verification | CI installs the independent Bun verifier instead of assuming it exists; complete TAP and a failure summary are retained. | `.github/workflows/verification.yml`, `scripts/completion.mjs` |

These are findings-level repairs, not blanket acceptance of every requirement in the corresponding family. Source-bound acceptance entries are stored separately in `docs/completion-reviews.json`; the current run must match their fingerprint.

## Internal work still open

- **Coverage and resource boundaries:** the controlled target remains directly mutable by code with access to its privileged object/database. Full total-mediation acceptance requires a precisely defined resource boundary and real bypass resistance, not a renamed simulator result.
- **Identity and keys:** customer-owned signer adapters and bootstrap custody separation, universal JIT enforcement for administrative paths, independent out-of-band identity proof, and replacement of long-lived engineering bootstrap credentials are not complete.
- **Runtime and deployment:** loopback proxy enforcement does not establish host-wide packet mediation, multi-zone state recovery, or production traffic containment. Current health hooks, telemetry, configuration authorization and soak coverage require complete per-clause review.
- **Connector and evidence acquisition:** real provider adapters, independently verified source onboarding and field-level contract acceptance are not made complete by synthetic signed fixtures. Software adapters and contract tests are internal work; only actual provider access is external.
- **Operations and compliance:** control matrices, vulnerability/disclosure processes, named maintainers, change evidence, alert ownership/escalation and incident lifecycle acceptance remain to be implemented or exercised. Legal or assessor sign-off is not a substitute for this software/documentation work.
- **UX and verification:** browser workflows and responsive checks pass, but a full accessibility assessment, approval-comprehension study, all-surface browser coverage and the remaining source-bound acceptance reviews are still required.

Physical HSM/trusted-display hardware, real customer/provider credentials, independent assessment and legal/customer sign-off are genuine external dependencies. No ledger row is promoted to `BLOCKED_EXTERNAL` until its adjacent internal software is complete and independently evidenced.

## Evidence boundaries

`reports/completion-tests.json` records the exact source fingerprint, command, environment and test results. `reports/benchmark.json` distinguishes core evaluation, durable audited work, cached local decisions and loopback transport. `reports/runtime-stress.json` is a measured one-minute synthetic stress run, not a production soak or availability claim. `reports/browser/results.json` records real Chromium assertions; screenshots and recordings require separate visual/privacy inspection. The production acceptance gate remains separate and blocked.
