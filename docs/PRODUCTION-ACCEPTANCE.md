# Production acceptance: BLOCKED

This is **not an MVP sold as a complete product** and is **not a production-ready R0–R5 release**. It is a concrete engineering delivery with runnable software, tests and simulations, plus an explicit unfulfilled-scope register. The full user request cannot be truthfully certified complete from the available environment. The machine-readable gate intentionally exits nonzero.

## Executed versus unavailable

The Computer executed local code, a real local HTTP service, complete API workflows, actual Ed25519/AES-GCM operations, separate persistent SQLite gate/target stores, independent concurrent gate workers, fail-safe fault simulations, canonical fuzz-style vectors, policy/runtime microbenchmarks and offline verification in multiple runtimes. These checks validate the stated software behavior, not real banking execution, physical key custody or production resilience.

The current engineering environment has Chromium browser automation, package/documentation access, independent review agents, and repository CI. Their availability is not a blocker. Fresh browser results are stored in `reports/browser/results.json`; source-bound tests and acceptance reviews are tracked by `scripts/completion.mjs`. Historical statements that browser tooling or package installation were unavailable are not current evidence.

No real customer target credentials, physical HSM or trusted-display hardware, deployment infrastructure, independent assessment, or organisational approval have been supplied. These external dependencies do not excuse missing software: signer adapters and custody separation, total mediation, identity proofing/JIT integration, multi-zone state recovery, and operational/compliance workflows still require implementation or acceptance review. They remain internal work until their software portions are complete.

## Smallest enabling inputs for further work

A named target ERP and payment provider, their approved schemas/API versions, a non-production account and narrowly scoped credentials are needed for real integration acceptance. A customer-owned staging environment is needed for deployment-specific recovery evidence. Approved HSM/threshold hardware, custodian structure, identity provider/WebAuthn and trusted-display platform selections are needed for hardware tests. Independent security and qualified legal/operational owners are needed for external assessments and organisational sign-off. Adapter implementation, synthetic adversarial tests, browser verification and documentation do not depend on these approvals.

Supplying these resources would not automatically make the build complete: the corresponding integrations and software in `COMPLETION_LEDGER.md` must be implemented, adversarially tested, reviewed, and accepted. Historical `requirements.csv` statuses are not completion authority.

## Required release sequence

Freeze and approve a complete release contract from the full SRS; assign named accountable owners; implement outstanding requirements rather than relabelling them; provision independent customer trust/identity; integrate real targets and prove total mediation; establish durable multi-zone/audit/revocation architecture; complete browser, accessibility and human comprehension testing; perform realistic adversarial load/failover/DR; refresh the supply-chain/advisory evidence; conduct independent assessment and remediate critical/high findings; then deploy to the assigned environment, verify live critical flows and rollback, and obtain signed customer production acceptance.

`docs/production-acceptance.json` contains the separate production acceptance items. Test success cannot override this gate. `reports/benchmark.json` separates cached decisions, durable audited execution, loopback proxy transport, and unconfigured external connectors. Only the cached-decision boundary is compared with the SRS 1 ms target; transport targets are declared separately. No production availability, regulatory certification, hardware security, total coverage or “unhackable” claim is made.
