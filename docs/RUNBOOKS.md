# Operator runbooks

These are actionable local engineering procedures and proposed production response sequences. No organisational on-call assignment, SLA, external incident exercise or production DR has been validated. Security, platform, finance/data owners and customer custodians must be formally assigned before production acceptance.

## Certificate rejection

Use the machine-readable error and request ID; do not log the request body or token. For `INV-409-STATE`, compare the current target state, active policy version and evidence graph to the exact signed capsule. Cancel undispatched authority and create a separately reviewed new capsule if the business request remains valid. Do not edit a certified capsule or re-use its nonce. For expiry, re-propose and obtain fresh evidence/approval. For replay, inspect the existing certificate outcome; a replay error is not a request to mint a duplicate payment.

## Target uncertainty

An operator uses `GET /gate/v1/outcomes/{certificate_id}` or Reconcile target outcome. VERIFIED is valid only after observed target journal state matches the authorised fields. If no authoritative outcome exists, the result remains UNCERTAIN. Stop replacements for the same business transaction and have the real target owner establish execution/non-execution through an authoritative reconciliation channel. Never infer success or failure from a timeout. The simulation has no manual “mark successful” override and no blind retry button.

## Gate/process outage and restart

Preserve the deployment directory, private configuration and both SQLite databases. Stop the service gracefully (`SIGTERM`) rather than deleting state. Restart the same reviewed code with the same directory and configuration. A consumed reservation remains consumed after restart. Reconcile any EXECUTING/UNCERTAIN records. The included restart test demonstrates reservation persistence, not a production RTO or multi-zone failover.

For an actual database backup, use a SQLite online-backup mechanism or stop the single writer and copy a coherent database state, including the matching target store and key/configuration version. Do not copy a live `.db` file alone while ignoring its WAL. Retain original checkpoints and encrypt backups under separately controlled keys. Test restoration in an isolated environment before deleting any source. Production backup scheduling and remote key escrow are not implemented.

## Key or issuer compromise

The security role invokes `POST /v1/revocations` with the affected key/issuer/subject/certificate, an incident reason, and a separately authenticated token. This blocks future local use and preserves evidence. If the execution/audit-key host is compromised, isolate it first; application-level revocation cannot make a malicious host trustworthy. Preserve external checkpoints and forensic copies. Do not rotate keys unilaterally: use an independently witnessed customer ceremony, confirm pending authority and historical verifier trust, and authorize the rotation explicitly. Key rotation/recovery tooling is not included.

## Suspected tenant isolation incident

Stop affected ingress, preserve encrypted state and minimal request-ID logs, record UTC times and affected component versions, and engage the assigned incident lead and privacy/legal owner. Keep tenant payloads compartmentalized. Revoke compromised principals and credentials under the approved customer process. Reproduce the suspected boundary failure only against isolated synthetic data. Document containment, scope, impact, recovery, root cause and corrective actions. Notification obligations require legal review, not a blanket product claim.

## Policy defect

Cancel unexecuted affected actions and revoke pending certificates. Use the exact policy simulator to review a correction. Root activation requires sequential policy version, reviewed exact diff, required evidence, delay and customer quorum. Never clear the revocation store or rewrite audit history to roll back a policy. Code rollback and authority rollback are distinct operations.

## Clock, evidence and hardware failures

A detected backward clock movement stops security mutations with `INV-503-TIME`. Restore an authoritative clock under operator control and preserve evidence; do not change stored last-seen time to bypass the check. Missing, expired or dependent evidence remains escrow. Synthetic health expires after 24 hours. Real attestation and protected recovery are unavailable; there is no universal refresh override. Secure Perception always fails closed in this release.

## Staging release and rollback

Verify archive checksums, the complete test suite and machine-readable release gate. Install to a new versioned directory, preserve the existing application version and data, and test against a restored synthetic copy before traffic changes. Do not run different incompatible binaries against live state. Current schema version is 1; the program refuses a newer schema. No destructive migration exists. Do not claim safe rollback across future migrations without an independently tested plan.

Before production change, establish the exact target, recovery owner and rollback method, then build, migrate non-destructively, restart only the assigned service, verify health/logs and run an authorised critical flow. Those live steps could not be executed without an assigned customer environment.

### Signed runtime snapshot renewal and rollback rejection

Renew `/v1/runtime/configuration` before the snapshot expires, advancing its
version and collecting at least three distinct, non-revoked customer custodians
from three independent failure domains. Snapshot validity is bounded to seven
days. A durable database high-water mark binds each accepted version to its
exact digest, including across restart and concurrent processes. An older
process withdraws authority after another process accepts a higher version.
Reload all gates with the newly accepted snapshot; do not restore an older
configuration file over newer gate state. A crash between configuration-file
replacement and state acceptance fails closed and the signed file is rechecked
on restart. Rollback of the entire host *and* its database requires an external
witness/hardware monotonic anchor; local storage cannot attest its own rollback.

### Local network decision gate and performance paths

`LocalNetworkGate` validates a customer-quorum signed runtime snapshot before
accepting capabilities. It continues enforcing imported capabilities without the
control plane until their/configuration expiry. Runtime-control messages are
verified against constructor-pinned keys and bound to tenant, gate, sequence and
expiry; callers cannot substitute their own verification keys. Quarantine permits
only an independently authorised, registered remediation destination named by the
signed configuration. Bounded cache/control growth fails closed rather than
silently evicting authority or consuming unbounded memory. This is an in-process
service-dispatch gate, not a claim of OS/kernel packet filtering.

`node scripts/benchmark.mjs` measures deterministic core, durable Commit Gate,
durable runtime/audit, and cached local decision paths separately. The exact SRS
cached-decision p99 ≤1 ms target is applied to the cached decision path, not the
SQLite/signature/audit path. Both measurements remain visible. Commit evaluation
p95 ≤250 ms, p99 ≤750 ms and throughput ≥100/s apply to the integrated evaluation.
Virtual policy time advances to respect unchanged signed budgets and TTLs; these
are local microbenchmarks, not proof of external latency or production capacity.
The command exits nonzero if any applicable measured SRS target fails.
