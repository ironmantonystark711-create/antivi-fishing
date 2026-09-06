import { digest, clone } from './canonical.mjs';
import { fields, identifier, text, integer, oneOf } from './schema.mjs';
import { SCHEMAS } from './schema.mjs';
import { requireThat } from './errors.mjs';

function versionParts(version) {
  text(version, 'version', 64); requireThat(/^\d+(?:\.\d+){0,3}$/.test(version), 'INV-400-SCHEMA', 'Version must use canonical numeric components');
  return version.split('.').map(Number);
}
function compareVersion(left, right) {
  const a = versionParts(left), b = versionParts(right);
  for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0) ? -1 : 1;
  return 0;
}

export class VersionLifecycle {
  constructor(fabric) { this.f = fabric; }
  registerDefaults(tenant, now) {
    for (const schema of Object.values(SCHEMAS)) {
      const id = `schema:${schema.id}:1`;
      if (!this.f.store.get(tenant, 'version-lifecycle', id)) this.f.store.insert(tenant, 'version-lifecycle', id, { kind: 'schema', id: schema.id, version: '1', status: 'SUPPORTED', end_of_support: null, replacement: null, migration: null, compatibility_digest: digest(schema), announced_at: now, updated_at: now, registered_by: 'bootstrap' }, now);
    }
  }
  publish(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['kind', 'id', 'version', 'status', 'end_of_support', 'replacement', 'migration', 'compatibility_digest']);
    oneOf(input.kind, ['schema', 'connector'], 'lifecycle kind'); identifier(input.id); versionParts(input.version); oneOf(input.status, ['SUPPORTED', 'DEPRECATED', 'END_OF_SUPPORT'], 'lifecycle state');
    requireThat(/^[a-f0-9]{64}$/.test(input.compatibility_digest), 'INV-400-SCHEMA', 'Compatibility digest required');
    if (input.status !== 'SUPPORTED') { text(input.replacement, 'replacement'); text(input.migration, 'migration instructions', 2048); integer(input.end_of_support, 'end of support', 1); }
    else requireThat(input.end_of_support === null && input.replacement === null && input.migration === null, 'INV-400-SCHEMA', 'Supported version must not imply unannounced migration');
    return this.f.transaction(p, now => {
      const id = `${input.kind}:${input.id}:${input.version}`, old = this.f.store.get(p.tenant_id, 'version-lifecycle', id), known = this.f.store.list(p.tenant_id, 'version-lifecycle', 10000).filter(r => r.kind === input.kind && r.id === input.id);
      requireThat(!old || ['SUPPORTED', 'DEPRECATED', 'END_OF_SUPPORT'].indexOf(input.status) >= ['SUPPORTED', 'DEPRECATED', 'END_OF_SUPPORT'].indexOf(old.status), 'INV-409-LIFECYCLE', 'Ended or deprecated authority cannot be silently revived', 409);
      requireThat(old || !known.some(r => compareVersion(input.version, r.version) < 0), 'INV-409-LIFECYCLE', 'Older versions must be registered before a newer lifecycle floor is published', 409);
      const record = { ...clone(input), announced_at: old?.announced_at ?? now, updated_at: now };
      this.f.store.put(p.tenant_id, 'version-lifecycle', id, record, now); this.f.store.audit(p.tenant_id, 'VERSION_LIFECYCLE_CHANGED', p.subject_id, id, { lifecycle_digest: digest(record), status: record.status }, now); return record;
    });
  }
  check(t, kind, id, version) {
    const r = this.f.store.get(t, 'version-lifecycle', `${kind}:${id}:${version}`);
    requireThat(r && (r.status !== 'END_OF_SUPPORT' && (r.end_of_support === null || r.end_of_support > this.f.clock())), 'INV-410-VERSION', 'Version is unregistered or no longer supported; follow the published migration', 410); return r;
  }
}
