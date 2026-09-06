import { mkdirSync, writeFileSync, existsSync, chmodSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKey, signed } from './crypto.mjs';
import { hashBytes, canonical, digest } from './canonical.mjs';
import { defaultPolicy } from './policy.mjs';
import { requireThat } from './errors.mjs';
import { Fabric } from './fabric.mjs';
import { runtimeConfiguration, signRuntimeConfiguration } from './runtime-config.mjs';
import { proposal } from './schema.mjs';
import { tmpdir } from 'node:os';

export function createConfiguration(tenantNames = ['acme'], now = Date.now()) {
  const config = { format: 'IF-CONFIG-1', profile: 'engineering', gate_id: 'local-software-gate', tenants: {} }, credentials = {}, custodianKeys = {}, issuerKeys = {}, deviceKeys = {};
  for (const tenant of tenantNames) {
    requireThat(/^[a-z][a-z0-9-]{1,31}$/.test(tenant), 'INV-400-SCHEMA', 'Tenant must use lowercase alphanumeric characters');
    const policy = defaultPolicy(tenant), identities = {}, auth = {}, identityPrivate = {};
    const roles = [['operator', ['operator'], 'workforce'], ['security', ['security'], 'workforce'], ['auditor', ['auditor'], 'workforce'], ['privacy-reviewer', ['audit_privacy'], 'workforce'], ['finance-reviewer', ['audit_finance'], 'workforce'], ['technical-reviewer', ['audit_technical'], 'workforce'], ['security-reviewer', ['audit_security'], 'workforce'], ['policy-admin', ['policy_admin'], 'workforce'], ['workload-agent', ['workload'], 'workload'], ['device-agent', ['operator'], 'device'], ['counterparty-agent', ['operator'], 'counterparty'], ...Array.from({ length: 5 }, (_, i) => [`custodian-${i + 1}`, ['approver', 'custodian'], 'workforce'])];
    credentials[tenant] = {}; custodianKeys[tenant] = {}; issuerKeys[tenant] = {}; deviceKeys[tenant] = null;
    for (const [subject, role, identityClass] of roles) {
      const key = generateKey(), token = randomBytes(32).toString('base64url');
      identities[key.key_id] = { public_key: key.public_key, suite: key.suite, subject_id: subject, identity_class: identityClass, roles: role, device_id: `${subject}-device`, failure_domain: `${tenant}-${subject}`, hardware_backed: false, health_expires_at: now + 86400000, proofing_level: 2, authenticator: { id: `${subject}-authenticator`, phishing_resistant: true, enrolled_at: now }, component: { id: `${subject}-component`, firmware: 'simulated-1', trusted: true }, grants: { resources: ['dataset-1', 'erp-service'], actions: ['data.read', 'service.connect'], destinations: ['customer-vault', 'erp-service'], columns: ['id', 'name', 'region'], row_ids: ['row-1', 'row-2', 'row-3'] } };
      auth[hashBytes(token)] = { subject_id: subject, expires_at: now + 86400000 }; credentials[tenant][subject] = token; identityPrivate[subject] = key;
      if (role.includes('custodian')) custodianKeys[tenant][subject] = key;
      if (subject === 'device-agent') deviceKeys[tenant] = key;
    }
    const issuers = {};
    for (const [name, channel] of [['bank', 'authoritative'], ['registry', 'authoritative'], ['governance', 'authoritative'], ['email', 'communication']]) {
      const key = generateKey(); issuerKeys[tenant][name] = key;
      issuers[key.key_id] = { public_key: key.public_key, suite: key.suite, failure_domain: `${tenant}-${name}`, channel, kinds: ['ownership', 'dataset_authority', 'identity_proof', 'recovery_authority', 'build_provenance', 'test_result', 'workload_attestation', 'governance_review'] };
    }
    const policyKey = generateKey(), execution = generateKey(), audit = generateKey(), support = generateKey(), coverageAssessor = generateKey();
    config.tenants[tenant] = { runtime_snapshot: signRuntimeConfiguration(runtimeConfiguration(tenant, config.gate_id, now, [deviceKeys[tenant].key_id]), Object.values(custodianKeys[tenant]).slice(0, 3)), encryption_key: randomBytes(32).toString('base64url'), keys: { policy: policyKey, execution, audit, support, coverage_assessor: coverageAssessor }, key_governance: { root_threshold: 3, root_custodians: Object.keys(custodianKeys[tenant]), recovery_delay_ms: 60000, trusted_component_firmware: ['simulated-1'], randomness_source: 'node:crypto CSPRNG; optional quantum entropy is not asserted' }, identities, issuers, auth, genesis_policy: policy, genesis_signatures: Object.values(custodianKeys[tenant]).slice(0, 3).map(k => signed(policy, k, 'root-policy')) };
  }
  return { config, credentials, custodianKeys, issuerKeys, deviceKeys };
}
export function bootstrap(directory, tenants = ['acme'], now = Date.now()) {
  directory = resolve(directory);
  requireThat(!existsSync(directory), 'INV-409-CONFLICT', 'Refusing to overwrite an existing deployment directory', 409);
  const setup = createConfiguration(tenants, now);
  mkdirSync(directory, { recursive: true, mode: 0o700 }); chmodSync(directory, 0o700);
  const signingDir = join(directory, 'offline-custodians'); mkdirSync(signingDir, { mode: 0o700 });
  const save = (path, value) => writeFileSync(path, canonical(value) + '\n', { mode: 0o600, flag: 'wx' });
  save(join(directory, 'config.json'), setup.config); save(join(directory, 'access-tokens.json'), setup.credentials);
  for (const tenant of tenants) {
    const audit = setup.config.tenants[tenant].keys.audit;
    save(join(directory, `trust-public-${tenant}.json`), { [audit.key_id]: { public_key: audit.public_key } });
    for (const [subject, key] of Object.entries(setup.custodianKeys[tenant])) save(join(signingDir, `${tenant}-${subject}.json`), key);
    for (const [name, key] of Object.entries(setup.issuerKeys[tenant])) save(join(signingDir, `${tenant}-issuer-${name}.json`), key);
  }
  const fabric = new Fabric(setup.config, directory, () => now);
  seedSyntheticResources(fabric, tenants); fabric.close();
  return { directory, config_path: join(directory, 'config.json'), credentials_path: join(directory, 'access-tokens.json'), signing_directory: signingDir, profile: 'engineering', production_ready: false };
}
export function seedSyntheticResources(fabric, tenants) {
  for (const tenant of tenants) {
    fabric.target.seed(tenant, 'beneficiary-1', { bank_account: 'TESTBANK000001', currency: 'EUR', first_payment_done: false, payment_eligible_at: 0 });
    fabric.target.seed(tenant, 'vendor-1', { name: 'Synthetic Vendor', bank_account: 'TESTBANK000001', currency: 'EUR' });
    fabric.target.seed(tenant, 'dataset-1', { columns: ['id', 'name', 'region', 'passport'], classification: 'internal', jurisdiction: 'EU', rows: [{ id: 'row-1', name: 'Synthetic Ada', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-1' }, { id: 'row-2', name: 'Synthetic Lin', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-2' }, { id: 'row-3', name: 'Synthetic Sam', region: 'EU', passport: 'SYNTHETIC-NOT-REAL-3' }] });
  }
}
export function runIsolatedCoverageBypass(path, now) {
  const directory = mkdtempSync(join(tmpdir(), 'if-coverage-'));
  const setup = createConfiguration(['coverage', 'other'], now), tenant = 'coverage', principal = { subject_id: 'operator', tenant_id: tenant }, foreignPrincipal = { subject_id: 'operator', tenant_id: 'other' };
  for (const name of ['coverage', 'other']) {
    const policy = setup.config.tenants[name].genesis_policy; policy.rules['finance.bank.change'].cooldown_ms = 0;
    setup.config.tenants[name].genesis_signatures = Object.values(setup.custodianKeys[name]).slice(0, 3).map(key => signed(policy, key, 'root-policy'));
  }
  const fabric = new Fabric(setup.config, directory, () => now); seedSyntheticResources(fabric, [tenant, 'other']);
  const rejected = operation => { try { operation(); return false; } catch { return true; } };
  try {
    const certified = suffix => {
      const resource = `coverage-${suffix}-${randomUUID()}`;
      fabric.target.seed(tenant, resource, { bank_account: 'TESTBANK000001', currency: 'EUR', first_payment_done: false, payment_eligible_at: 0 });
      const record = fabric.propose(principal, proposal('finance.bank.change', { subject_id: 'operator', identity_class: 'workforce', device_id: 'operator-device' }, fabric.target.state(tenant, resource), { bank_account: 'TESTBANK000009', currency: 'EUR' }, now, { action: { type: 'finance.bank.change', target_resource: resource, purpose: 'Isolated coverage bypass verification' } }), randomUUID());
      for (const issuer of ['bank', 'registry']) {
        const evidence = { evidence_id: randomUUID(), tenant_id: tenant, capsule_digest: record.capsule_digest, kind: 'ownership', content_digest: digest({ issuer, suffix }), acquired_at: now, expires_at: now + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: { connector_id: `coverage-${issuer}`, source_type: 'direct', source_reference_digest: digest({ issuer, suffix }), transformations: [] }, verification_method: 'issuer-signature', acquisition_purpose: 'Isolated coverage bypass verification', retention_until: now + 120000 };
        fabric.attachEvidence(principal, record.capsule.capsule_id, signed(evidence, setup.issuerKeys[tenant][issuer], 'evidence'));
      }
      for (const number of [1, 2]) { const approver = { subject_id: `custodian-${number}`, tenant_id: tenant }, challenge = fabric.approvalChallenge(approver, record.capsule.capsule_id); fabric.approve(approver, signed(challenge, setup.custodianKeys[tenant][approver.subject_id], 'action-approval')); }
      return { record, certificate: fabric.certificate(principal, record.capsule.capsule_id) };
    };
    const noCertificateRejected = rejected(() => fabric.execute(principal, null));
    const wrongTenant = certified('wrong-tenant'); const wrongTenantRejected = rejected(() => fabric.execute(foreignPrincipal, wrongTenant.certificate));
    const stateRace = certified('state-race'); fabric.target.seed(tenant, stateRace.record.capsule.action.target_resource, { bank_account: 'TESTBANK000010', currency: 'EUR', first_payment_done: false, payment_eligible_at: 0 }); const stateRaceRejected = rejected(() => fabric.execute(principal, stateRace.certificate));
    const replay = certified('replay'); const firstExecution = fabric.execute(principal, replay.certificate).payload.status === 'VERIFIED'; const replayRejected = firstExecution && rejected(() => fabric.execute(principal, replay.certificate));
    const directBypass = certified('direct-bypass'); const before = fabric.target.state(tenant, directBypass.record.capsule.action.target_resource); const directOutcome = fabric.target.execute(directBypass.record.capsule, randomUUID(), now); const directBypassRejected = digest(before) === digest(fabric.target.state(tenant, directBypass.record.capsule.action.target_resource)) && directOutcome === null;
    const actualRootGate = certified('root-gate'); const rootGateVerified = fabric.execute(principal, actualRootGate.certificate).payload.status === 'VERIFIED';
    const result = { 'no-certificate': noCertificateRejected, 'wrong-tenant': wrongTenantRejected, 'state-race': stateRaceRejected, replay: replayRejected, 'direct-bypass': directBypassRejected };
    return { format: 'IF-COVERAGE-TEST-3', runner: 'IF-ISOLATED-FABRIC-BYPASS-RUNNER-1', tenant_id: path.tenant_id, path_id: path.path_id, target: path.target, configuration_digest: path.configuration_digest, connector_version: path.connector_version, tested_at: now, expires_at: now + Math.min(path.max_age_ms, 10000), credential_owner: 'root-gate', permissions: ['read', 'exact-mutation'], negative_tests: Object.entries(result).map(([name, wasRejected]) => ({ name, rejected: wasRejected, result_digest: digest({ name, wasRejected, rootGateVerified }) })), environment: path.environment, root_gate_verified: rootGateVerified };
  } finally { fabric.close(); rmSync(directory, { recursive: true, force: true }); }
}
export function loadConfiguration(directory) { return JSON.parse(readFileSync(join(resolve(directory), 'config.json'), 'utf8')); }
