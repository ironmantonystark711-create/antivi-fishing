import { writeFileSync } from 'node:fs';
import { SCHEMAS, SUPPORTED_CURRENCIES } from '../src/schema.mjs';
import { SUITES } from '../src/suites.mjs';
import { digest } from '../src/canonical.mjs';
const type = { text: { type: 'string', minLength: 1, maxLength: 512 }, id: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9_.:-]*$', maxLength: 128 }, positive: { type: 'integer', minimum: 1, maximum: 1000000000000 }, currency: { type: 'string', enum: SUPPORTED_CURRENCIES }, account: { type: 'string', pattern: '^[A-Z0-9-]{6,64}$' }, hash: { type: 'string', pattern: '^[a-f0-9]{64}$' }, strings: { type: 'array', uniqueItems: true, maxItems: 256, items: { type: 'string', minLength: 1, maxLength: 128 } }, object: { type: 'object' } };
const object = (properties, required = Object.keys(properties)) => ({ type: 'object', additionalProperties: false, required, properties });
const Str = { type: 'string' }, Int = { type: 'integer' }, Ref = name => ({ $ref: `#/components/schemas/${name}` });
const components = {
  Error: object({ error: object({ code: Str, message: Str, request_id: Str }) }),
  Envelope: { oneOf: Object.values(SUITES).map(s => object({ protected: object({ profile: { const: 'IF-CJSON-1' }, suite: { const: s.id }, key_id: Str, purpose: Str }), payload: { type: 'object' }, signature: { type: 'string', pattern: `^[A-Za-z0-9_-]{${Math.ceil(s.signature_bytes * 4 / 3)}}$` } })) },
  State: object({ version: { type: 'integer', minimum: 0 }, digest: type.hash, material_fields: { type: 'object' } }),
  Empty: object({}),
  CertificateRequest: object({ capsule_id: type.id }),
  ExecuteRequest: object({ certificate: Ref('Envelope'), dry_run: { type: 'boolean' } }),
  Revocation: object({ kind: { enum: ['certificate', 'evidence', 'issuer', 'key', 'subject', 'device', 'capability'] }, id: type.id, reason: type.text }),
  CoverageDeclaration: object({ path_id: type.id, action_type: Str, target: type.id, environment: Str, connector_version: Str, owner: type.id, status: { enum: ['MONITORED', 'UNKNOWN'] }, max_age_ms: { type: 'integer', minimum: 1000, maximum: 2592000000 }, configuration_digest: type.hash }),
  AuditRequest: object({ purpose: type.text }),
  RetentionHold: object({ evidence_id: type.id, legal_hold: { type: 'boolean' } }),
  Session: object({ token: { type: 'string', minLength: 43, maxLength: 43 } }),
  Policy: { type: 'object', description: 'Strict executable schema is validatePolicy in src/policy.mjs; examples/default-policy.json is the complete schema-shaped instance. Unknown fields and governance weakening are rejected.' },
  CapabilityRequest: object({ device_id: type.id, resource: type.id, destination: type.text, action: { enum: ['data.read', 'service.connect'] }, purpose: type.text, columns: type.strings, row_ids: type.strings, classification: type.text, jurisdiction: type.text, max_cost: { type: 'integer', minimum: 1, maximum: 1000000000 }, ttl_ms: { type: 'integer', minimum: 1000, maximum: 300000 } }),
  RuntimeRequest: object({ capability: Ref('Envelope'), device_id: type.id, resource: type.id, destination: type.text, action: Str, purpose: type.text, columns: type.strings, row_ids: type.strings, request_id: type.id, protocol: { const: 'https' }, port: { const: 443 } })
};
Object.assign(components, {
  EmergencyPolicy: object({ format: { const: 'IF-EMERGENCY-1' }, emergency_id: type.id, tenant_id: type.id, actions: type.strings, resources: type.strings, max_quantity: type.positive, deny: { type: 'boolean' }, issued_at: Int, expires_at: Int, reason_digest: type.hash }),
  EmergencyActivate: object({ policy: Ref('EmergencyPolicy'), signatures: { type: 'array', minItems: 3, maxItems: 5, items: Ref('Envelope') } }),
  RuntimeSnapshot: object({ config: object({ format: { const: 'IF-RUNTIME-CONFIG-1' }, tenant_id: type.id, gate_id: type.id, version: type.positive, issued_at: Int, expires_at: Int, fail_policy: { enum: ['cached-allow','fail-closed'] }, cache_entries: type.positive, reload_interval_ms: type.positive, remediation_services: type.strings, environment: { const: 'simulation' } }), signatures: { type: 'array', minItems: 3, maxItems: 5, items: Ref('Envelope') } }),
  KeyPrepare: object({ purpose: { enum: ['execution','audit'] }, suite: { enum: Object.keys(SUITES) }, not_before: Int }),
  KeyActivate: object({ rotation_id: type.id, signatures: { type: 'array', minItems: 3, maxItems: 5, items: Ref('Envelope') } }),
  PolicyStage: object({ candidate: Ref('Policy'), stage: { enum: ['DEVELOPMENT','SHADOW','CANARY'] }, evidence: Ref('Envelope') }),
  PolicyRollback: object({ version: type.positive }),
  CoverageRevalidate: object({ path_id: type.id, evidence: Ref('Envelope') }),
  CoverageDrift: object({ path_id: type.id, configuration_digest: type.hash, connector_version: Str }),
  VersionLifecycle: object({ kind: { enum: ['connector','schema'] }, id: type.id, version: Str, status: { enum: ['SUPPORTED','DEPRECATED','END_OF_SUPPORT','REVOKED'] }, end_of_support: { type: ['integer','null'] }, replacement: Str, migration: Str, compatibility_digest: type.hash }),
  Composition: object({ tree: object({ root: type.id, nodes: { type: 'object', minProperties: 1, maxProperties: 64, additionalProperties: { oneOf: [object({ kind: { const: 'action' }, capsule_id: type.id }), object({ kind: { const: 'all' }, children: { type: 'array', minItems: 1, maxItems: 32, uniqueItems: true, items: type.id } })] } } }), expires_at: Int }),
  CompositionExecute: object({ composition_id: type.id, certificates: { type: 'array', minItems: 1, maxItems: 32, items: Ref('Envelope') } }),
  AuditView: object({ role: { enum: ['finance','security','privacy','technical'] }, purpose: type.text }),
  AdvisoryCapability: object({ capsule_id: type.id, source_digests: type.strings, fields: type.strings, max_output_bytes: type.positive, ttl_ms: type.positive }),
  AdvisoryExtract: object({ capability: Ref('Envelope'), source: { type: 'string', maxLength: 65536 }, context: object({ provider: Str, model: Str, version: Str, prompt_digest: type.hash, configuration_digest: type.hash, tools: type.strings }) }),
  Incident: object({ title: type.text, severity: { enum: ['HIGH','CRITICAL'] }, detected_at: Int, evidence_digest: type.hash }),
  IncidentTransition: { ...object({ incident_id: type.id, expected_state: Str, state: { enum: ['CONTAINED','RECOVERED','ROOT_CAUSE','CLOSED'] }, evidence_digest: type.hash, summary: type.text, corrective_action: object({ owner: type.id, action: type.text, evidence_digest: type.hash, implemented_at: Int }) }, ['incident_id','expected_state','state','evidence_digest','summary']), allOf: [{ if: { properties: { state: { const: 'CLOSED' } } }, then: { required: ['corrective_action'] } }] }
});
const variants = [];
for (const s of Object.values(SCHEMAS)) {
  const name = s.type.replaceAll('.', '_');
  const variant = object({ schema_id: { const: s.id }, schema_digest: { const: digest(s) }, actor: object({ subject_id: type.id, identity_class: { enum: ['workforce', 'workload', 'device', 'counterparty'] }, device_id: type.id }), action: object({ type: { const: s.type }, target_resource: type.id, purpose: type.text }), current_state: Ref('State'), requested_state: object(Object.fromEntries(Object.entries(s.requested).map(([k, v]) => [k, type[v]]))), destination: type.text, quantity: type.positive, exclusions: type.strings, evidence_refs: type.strings, policy_version: { type: 'integer', minimum: 1 }, nonce: { ...type.id, minLength: 16 }, created_at: Int, expires_at: Int, rollback_or_compensation: type.text, privacy_classification: { enum: ['internal', 'confidential', 'restricted'] } });
  components[name] = variant; variants.push(Ref(name));
}
components.Proposal = { oneOf: variants };
const paths = {};
function operation(path, method, description, role, request = null, status = 200) {
  const op = { operationId: method + path.replace(/[^a-zA-Z0-9]+/g, '_'), summary: description, description: `Roles: ${role}. Engineering profile; all target mutations are simulated.`, tags: [path.startsWith('/gate') ? 'Gate' : 'Control'], responses: { [status]: { description: 'Successful response; see API.md for exact record contracts', content: { 'application/json': { schema: { type: 'object' } } } }, default: { description: 'Reason-coded rejection', content: { 'application/json': { schema: Ref('Error') } } } } };
  if (request) op.requestBody = { required: true, content: { 'application/json': { schema: Ref(request) } } };
  const params = [...path.matchAll(/\{([^}]+)\}/g)].map(m => ({ name: m[1], in: 'path', required: true, schema: type.id }));
  if (path === '/v1/action-capsules' && method === 'post') params.push({ name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{8,128}$' } });
  if (params.length) op.parameters = params;
  paths[path] ??= {}; paths[path][method] = op;
}
for (const row of [
 ['/v1/me','get','Current principal','authenticated'], ['/v1/schemas','get','Typed schema definitions and digests','authenticated'], ['/v1/policy','get','Read active constitution','operator, approver, custodian, policy_admin, security'],
 ['/v1/action-capsules','get','List capsules (limit 1–100 and offset)','operator, approver, custodian, security, policy_admin'], ['/v1/action-capsules','post','Propose exact action','operator, policy_admin, workload','Proposal',201], ['/v1/action-capsules/{id}','get','Read exact capsule','operator, approver, custodian, security, policy_admin'],
 ['/v1/action-capsules/{id}/evidence','post','Attach signed evidence','operator, security, policy_admin','Envelope',201], ['/v1/action-capsules/{id}/evaluate','post','Evaluate deterministic policy','operator, policy_admin, approver, custodian','Empty'], ['/v1/action-capsules/{id}/cancel','post','Cancel undispatched authority','operator, security, policy_admin','Empty'], ['/v1/action-capsules/{id}/approval-challenge','get','Get exact digest-bound challenge','approver, custodian'],
 ['/v1/approvals','post','Submit offline-signed approval','approver, custodian','Envelope',201], ['/v1/certificates','post','Mint single-use authority after ALLOW','operator, policy_admin','CertificateRequest',201], ['/v1/certificates/{id}','get','Read issued certificate','operator, policy_admin, security'],
 ['/gate/v1/execute','post','Verify and execute or dry-run simulated target','operator, policy_admin','ExecuteRequest'], ['/gate/v1/outcomes/{id}','get','Reconcile target journal (may append outcome evidence)','operator, policy_admin, security'],
 ['/v1/resources/{id}','get','Read non-dataset synthetic target state','operator, policy_admin'], ['/v1/capabilities','post','Issue narrow local capability','operator, workload','CapabilityRequest',201], ['/gate/v1/runtime','post','Consume capability under shared budgets','bound subject','RuntimeRequest'],
 ['/v1/revocations','post','Permanently revoke local authority','security','Revocation',201], ['/v1/coverage','get','Read signed conservative coverage manifest','operator, approver, custodian, security, auditor, policy_admin'], ['/v1/coverage','post','Declare monitored or unknown path','security','CoverageDeclaration',201],
 ['/v1/connectors','get','Read simulator connector limitations','authenticated'], ['/v1/policies/simulate','post','Compare exact candidate without activation','policy_admin, security','Policy'], ['/v1/audit-exports','post','Export audited purpose-bound integrity metadata','auditor, security','AuditRequest'],
 ['/v1/retention/hold','post','Set or release evidence legal hold','security','RetentionHold'], ['/v1/retention/sweep','post','Apply conservative logical retention','security','Empty'], ['/v1/metrics','get','Read process-wide counters without target payloads','security'],
 ['/session','post','Establish same-origin session','token holder','Session'], ['/session/logout','post','Destroy current cookie session','authenticated','Empty']
]) operation(...row);
for (const row of [
 ['/v1/emergencies/simulate','post','Simulate exact bounded emergency restrictions','policy_admin, security','EmergencyPolicy'], ['/v1/emergencies/activate','post','Activate scoped emergency with customer quorum','policy_admin','EmergencyActivate',201], ['/v1/emergencies/expire','post','Expire emergencies without restoring revoked authority','security, policy_admin','Empty'],
 ['/v1/connectors/manifest','get','Signed scoped connector manifest','operator, security, auditor, policy_admin'],
 ['/v1/runtime/configuration','post','Quorum-verified runtime configuration renewal','security','RuntimeSnapshot'],
 ['/v1/keys/prepare','post','Prepare delayed exact key/suite transition','security','KeyPrepare',201], ['/v1/keys/activate','post','Activate exact customer-quorum transition','security','KeyActivate'], ['/v1/keys/history','get','Public key transitions and approvals','security, auditor'],
 ['/v1/policies/stage','post','Advance exact reviewed candidate through required stages','policy_admin','PolicyStage'], ['/v1/policies/rollback-candidate','post','Propose forward-version rollback without activation','policy_admin','PolicyRollback'],
 ['/v1/coverage/revalidate','post','Verify scope-bound signed technical evidence','security','CoverageRevalidate'], ['/v1/coverage/drift','post','Withdraw changed coverage and schedule revalidation','security','CoverageDrift'], ['/v1/coverage/revalidation-tasks','get','Assigned coverage revalidation work','security'], ['/v1/coverage/{id}/history','get','Historical half-open coverage intervals','security, auditor'],
 ['/v1/versions','get','Read support and deprecation lifecycle','operator, policy_admin, security'],
 ['/v1/versions','post','Announce support lifecycle and compatibility evidence','security','VersionLifecycle',201],
 ['/v1/compositions','get','List exact compositions','operator, approver, custodian, policy_admin, security'],
 ['/v1/compositions','post','Propose an exact atomic composition','operator, policy_admin','Composition',201], ['/v1/compositions/{id}/challenge','get','Action-complete batch approval challenge','approver, custodian'], ['/v1/batch-approvals','post','Submit exact child-intersection approval','approver, custodian','Envelope',201], ['/gate/v1/compositions/execute','post','Atomically reserve and execute all children','operator, policy_admin','CompositionExecute'], ['/gate/v1/compositions/{id}/outcome','get','Reconcile without redispatch after restart or expiry','operator, policy_admin, security'],
 ['/v1/audit-views','post','Role-minimal signed audit projection','projection-specific role','AuditView'],
 ['/v1/advisory/capabilities','post','Issue source-bound single-use advisory authority','operator, policy_admin','AdvisoryCapability',201], ['/v1/advisory/extract','post','Bounded deterministic advisory extraction','operator, policy_admin','AdvisoryExtract'],
 ['/v1/notifications','get','List owned durable alerts','security, policy_admin'], ['/v1/notifications/{id}/acknowledge','post','Acknowledge once within owner scope','security','Empty'], ['/v1/notifications/escalate','post','Evaluate escalation SLO immediately','security','Empty'],
 ['/v1/incidents','post','Record evidenced high-severity detection','security','Incident',201], ['/v1/incidents/transition','post','Advance owned incident lifecycle with closure evidence','security','IncidentTransition'], ['/v1/incidents/{id}','get','Read tenant-scoped incident history','security, auditor']
]) operation(...row);
for (const path of ['/v1/compositions']) paths[path].post.parameters = [{ name: 'Idempotency-Key', in: 'header', required: true, schema: type.id }];
paths['/session'].post.security = [];
const result = { openapi: '3.1.0', info: { title: 'Invariant Fabric engineering API', version: '1.1.0', description: 'Exact-action software enforcement and synthetic target execution. Not a production-certified deployment. JSON is restricted to IF-CJSON-1. Cookie mutations require Origin and X-CSRF-Token; bearer credentials are also supported. Strict runtime validation is authoritative.' }, servers: [{ url: 'http://127.0.0.1:8080' }], security: [{ bearerAuth: [] }], paths, components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas: components } };
writeFileSync('docs/openapi.json', JSON.stringify(result, null, 2) + '\n');
writeFileSync('examples/schema-catalog.json', JSON.stringify(SCHEMAS, null, 2) + '\n');
const { defaultPolicy } = await import('../src/policy.mjs'); writeFileSync('examples/default-policy.json', JSON.stringify(defaultPolicy('acme'), null, 2) + '\n');
console.log(JSON.stringify({ api_paths: Object.keys(paths).length, action_schemas: Object.keys(SCHEMAS).length }));
