# API and compatibility contract

The API is versioned under `/v1` and `/gate/v1`. `docs/openapi.json` enumerates 39 path templates, request schemas, roles and response/error shapes. `src/schema.mjs` and `src/policy.mjs` are the authoritative strict validators. Unknown fields fail rather than being silently ignored. The generated OpenAPI description is useful integration documentation, not an independent proof of every conditional predicate.

## Identity and tenant boundary

An Authorization header `Bearer <locally provisioned token>` identifies a tenant and subject. Callers cannot select a tenant with a request field or header. A browser may instead exchange the token at same-origin `POST /session`; subsequent POSTs require both the exact `Origin` and returned `X-CSRF-Token`. Session cookies are HttpOnly, SameSite=Strict, and Secure when the configured origin uses HTTPS. A session proves identity, not protected execution authority.

Permissions are explicit in `docs/openapi.json`. Auditor users see digest-only audit exports and conservative coverage, not full action payloads. Operators, eligible approvers, security and policy administrators have tenant-local access appropriate to the engineering workflow. Fine-grained finance/privacy assessor field projections and support-access workflows are incomplete and block enterprise acceptance.

## Post-reset credential reissue

`POST /session/credential-reissue/challenge` is a same-origin, rate-limited bootstrap operation for a subject whose reset or recovery has already invalidated sessions. It accepts only `tenant_id` and `subject_id`, then returns a five-minute, single-use challenge bound to the subject's current session epoch. It does not accept a bearer token because the prior credential is intentionally invalidated.

`POST /session/credential-reissue` accepts that challenge ID, tenant ID and `credential-reissue` envelopes. Each envelope binds the exact challenge, subject, tenant, session epoch and expiry; configured independent customer custodians must meet the tenant root threshold. It returns one 15-minute bearer credential only once. Both generated request and response schemas are in `docs/openapi.json`; callers must supply the exact `Origin` and must not treat either route as a general credential-issuance API.

## Capsule, evidence and authority

Proposal fields include actor/device, versioned schema ID/digest, typed action/resource/purpose, exact current state, requested state, destination, integer quantity, explicit exclusions, nonce, timestamps, policy version and compensation description. The server adds tenant and capsule ID. The explicitly versioned engineering currency profile supports EUR, USD, GBP, CHF, CAD, AUD, NZD and SGD, all with two decimal minor units. Other currencies are rejected, not silently interpreted with an incorrect scale. A required idempotency header provides stable proposal retry semantics; reusing a key with a changed request is rejected. Terminal denied/cancelled/dispatched instances cannot be reopened.

Evidence is an Ed25519 envelope with purpose `evidence`, signed by a configured issuer for its registered evidence kinds. The signed payload is action/tenant-bound and includes digest, acquisition/expiry, confidence, provenance, dependencies and retention. Unsigned documents and free-form prose cannot provide root authority. Adding evidence invalidates prior approvals. Evidence acquisition from real banks/ERP is not implemented.

The approval challenge includes capsule/evidence/policy digests, signer key ID and short expiry. The corresponding `action-approval` signature must match the authenticated approver and must not come from the initiating subject. A certificate is minted only after current deterministic ALLOW. It is registered, single-use and bound to exact scope, gate, policy, evidence, signer set, target state and nonce.

A SHIELD decision never mints a certificate for its original capsule. `POST /v1/action-capsules/{id}/shield` creates an immutable, reduced-scope successor for a current SHIELD data export, records its parent and transformation digests, and gives it a new nonce and capsule digest. Evidence, approvals and certificates are never inherited: attach fresh evidence, re-evaluate the successor, obtain digest-bound authority, then request its certificate only after ALLOW.

`POST /gate/v1/execute` accepts only an issued certificate plus an explicit boolean `dry_run`. There is no arbitrary mutation or fault-injection HTTP route. Test-only faults are available only through local module calls in `tests/` and `scripts/simulate.mjs`.

## Composition and recovery

`POST /v1/compositions` creates a bounded `all`-child composition from exact existing capsules. `GET /v1/compositions/{id}/challenge` returns the complete aggregate and child scope for an offline `batch-approval`; `POST /v1/batch-approvals` accepts that envelope. `POST /gate/v1/compositions/execute` atomically durably reserves its exact certificate set and marks the composition `RESERVED` before target dispatch.

`POST /gate/v1/compositions/{id}/reconcile` is the journal-only recovery operation. It never re-dispatches an action: each child is reconciled against its exact target transaction ID and a signed `IF-COMPOSITION-OUTCOME-1` aggregate is recorded. `VERIFIED` requires every child journal to verify; `FAILED` requires every child to be rejected; all mixed, unavailable, or malformed observations remain `UNCERTAIN`. The route and OpenAPI contract are available in the engineering service.

## Release evidence, staged policy, and rollback

Policy promotion and deployment staging require an exact `ReleaseEvidence` bundle:

1. `release-build`: a configured build-provenance issuer signs the immutable source commit, artifact digest, test digest, runner ID and validity interval.
2. `release-review`: an active customer custodian signs the same build/test/policy/key binding for the exact stage and environment.
3. `release-observation`: a distinct configured test-result issuer signs a healthy observation for that exact release, stage and environment.

The service verifies all signatures, issuer roles, distinct build/observation signers, freshness, and every cross-artifact binding. A source hash merely matching a regular expression is not release authority. Policy promotions persist the validated bundle digest before accepting custodian promotion signatures. Deployment rollback additionally requires three distinct customer-custodian `deployment-rollback` envelopes bound to the active deployment, target, artifact, policy/key integrity and reason digest. Revoked artifacts or releases cannot be staged or selected as rollback targets.

## Important response semantics

| Code | Handling |
|---|---|
| INV-400-SCHEMA | Correct the typed request; unchanged retries cannot fix it. |
| INV-401-AUTH / SIGNATURE / CERTIFICATE | Re-establish valid identity or separately re-authorise; never bypass. |
| INV-403-SCOPE / ROLE / HEALTH / QUARANTINE | Scope, identity, health or containment rejection. |
| INV-409-STATE | State/evidence/policy mismatch; re-canonicalise and re-review. |
| INV-409-REPLAY | Authority or request already consumed; inspect existing outcome. |
| INV-409-IDEMPOTENCY | Same idempotency key bound to different content. |
| INV-412-EVIDENCE | No current ALLOW; resolve deterministic gaps. |
| INV-429-BUDGET / RATE / FANOUT | Wait for bounded budget/rate recovery or separately review narrower authority. |
| INV-501-HARDWARE | Secure Perception unavailable; no decryption/secure-mode fallback. |
| INV-503-TIME / STORAGE / CONFIG / RELEASE | Local infrastructure/trust condition prevents safe operation. |

Policy DENY, DEFER and ESCROW are decision objects, not automatically HTTP 451/423/412 at the evaluate endpoint. UNCERTAIN is a signed **outcome status** returned with HTTP 200 after dispatch; clients must inspect the payload and must not treat all 2xx as execution success. This is an explicit difference from the SRS’s illustrative `INV-599-UNCERTAIN` transport code. The decision’s reasons and next action remain machine-readable.

The composition reconciliation POST may append a new signed reconciliation result to the log. It does not re-dispatch the mutation. Clients must disable shared caching, as enforced by `Cache-Control: no-store`.

## Bounds and unsupported behavior

The HTTP body limit is 1 MiB; JSON nesting is bounded, object keys are ASCII and safe-integer quantities only are accepted. Evidence is bounded at 32 items per action. List pagination is limit/offset (max 100). Policy simulation scans at most 500 recent actions. Retention stops conservatively if it cannot establish all references within its batch bound. Engineering audit export is in-memory rather than a production streaming/pagination API.

There are no external URL fetch, plaintext-key extraction, raw SQL, universal administrator bypass, automatic compensating mutation, real bank connector, root-key enrollment, arbitrary capability widening, or production-enable API. Distributed revocation, true emergency policies, crypto migration, external build/SCM adapters and several long-term SRS features remain in the explicit gap register.
