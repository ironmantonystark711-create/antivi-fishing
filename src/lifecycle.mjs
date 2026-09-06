import { digest, clone } from './canonical.mjs';
import { fields, identifier, text, integer, oneOf } from './schema.mjs';
import { requireThat } from './errors.mjs';

export class VersionLifecycle {
  constructor(fabric) { this.f = fabric; }
  publish(p, input) {
    this.f.authorize(p, ['security']); fields(input, ['kind', 'id', 'version', 'status', 'end_of_support', 'replacement', 'migration', 'compatibility_digest']);
    oneOf(input.kind, ['schema', 'connector'], 'lifecycle kind'); identifier(input.id); text(input.version, 'version', 64); oneOf(input.status, ['SUPPORTED', 'DEPRECATED', 'END_OF_SUPPORT'], 'lifecycle state');
    requireThat(/^[a-f0-9]{64}$/.test(input.compatibility_digest), 'INV-400-SCHEMA', 'Compatibility digest required');
    if (input.status !== 'SUPPORTED') { text(input.replacement, 'replacement'); text(input.migration, 'migration instructions', 2048); integer(input.end_of_support, 'end of support', 1); }
    else requireThat(input.end_of_support === null && input.replacement === null && input.migration === null, 'INV-400-SCHEMA', 'Supported version must not imply unannounced migration');
    return this.f.transaction(p, now => {
      const id = `${input.kind}:${input.id}:${input.version}`, old = this.f.store.get(p.tenant_id, 'version-lifecycle', id);
      requireThat(!old || ['SUPPORTED', 'DEPRECATED', 'END_OF_SUPPORT'].indexOf(input.status) >= ['SUPPORTED', 'DEPRECATED', 'END_OF_SUPPORT'].indexOf(old.status), 'INV-409-LIFECYCLE', 'Ended or deprecated authority cannot be silently revived', 409);
      requireThat(!old || old.end_of_support === null || (input.end_of_support !== null && input.end_of_support <= old.end_of_support), 'INV-409-LIFECYCLE', 'Published end-of-support cannot be extended to revive authority', 409);
      const record = { ...clone(input), announced_at: old?.announced_at ?? now, updated_at: now };
      if (input.kind === 'connector') {
        for (const path of this.f.coverageLifecycle.inventory(p.tenant_id)) if (path.connector_version === input.version && input.status !== 'SUPPORTED') {
          path.status = 'UNKNOWN'; this.f.store.put(p.tenant_id, 'coverage', path.path_id, path, now); this.f.coverageLifecycle.history(p.tenant_id, path, now, 'CONNECTOR_LIFECYCLE_REVALIDATION_REQUIRED');
          this.f.store.put(p.tenant_id, 'coverage-task', path.path_id, { path_id: path.path_id, owner: path.owner, reason: 'CONNECTOR_LIFECYCLE_REVALIDATION_REQUIRED', created_at: now }, now);
        }
      }
      this.f.store.put(p.tenant_id, 'version-lifecycle', id, record, now); this.f.store.audit(p.tenant_id, 'VERSION_LIFECYCLE_CHANGED', p.subject_id, id, { lifecycle_digest: digest(record), status: record.status }, now); return record;
    });
  }
  check(t, kind, id, version) {
    const r = this.f.store.get(t, 'version-lifecycle', `${kind}:${id}:${version}`);
    requireThat(!r || (r.status !== 'END_OF_SUPPORT' && (r.end_of_support === null || r.end_of_support > this.f.clock())), 'INV-410-VERSION', 'Version no longer supported; follow the published migration', 410); return r;
  }
}
