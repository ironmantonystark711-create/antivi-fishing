import { randomUUID } from 'node:crypto';
import { digest, hashBytes, clone } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, identifier, integer, text, uniqueStrings } from './schema.mjs';
import { requireThat } from './errors.mjs';
export const ADVISORY_EVALUATION_VERSION = 'IF-AI-EVAL-1';
export function extractAdvisory(source, keys) {
  // Deterministic extractor; source is data, never instructions or executable policy.
  const proposed = [];
  for (const field of keys) {
    const pattern = new RegExp(`(?:^|\\n)${field.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: ([^\\n]{1,256})`, 'g');
    const matches = [...source.matchAll(pattern)];
    if (matches.length !== 1) continue;
    const match = matches[0], value = match[1], start = match.index + match[0].length - value.length;
    proposed.push({ field, value, source_digest: hashBytes(source), span: { start, end: start + value.length }, confidence: 80, uncertainty: 'Uncorroborated source; deterministic validation required', status: 'ADVISORY' });
  }
  return proposed;
}
export class AdvisoryPlane {
  constructor(fabric) { this.f = fabric; }
  issue(p, input) {
    this.f.authorize(p, ['operator', 'policy_admin']); fields(input, ['capsule_id', 'source_digests', 'fields', 'max_output_bytes', 'ttl_ms']);
    identifier(input.capsule_id); uniqueStrings(input.source_digests, 'source digests', 8); uniqueStrings(input.fields, 'extraction fields', 16);
    requireThat(input.source_digests.length && input.source_digests.every(x => /^[a-f0-9]{64}$/.test(x)) && input.fields.length && input.fields.every(x => /^[a-z][a-z0-9_]{0,63}$/.test(x)), 'INV-400-SCHEMA', 'Explicit sources and bounded fields required');
    integer(input.max_output_bytes, 'output ceiling', 128, 16384); integer(input.ttl_ms, 'advisory TTL', 1000, 60000);
    return this.f.transaction(p, now => { const record = this.f.store.must(p.tenant_id, 'capsule', input.capsule_id); requireThat(record.capsule.actor.subject_id === p.subject_id, 'INV-403-SCOPE', 'Advisory capability is bound to its action owner', 403); const cap = { format: 'IF-AI-CAPABILITY-1', capability_id: randomUUID(), tenant_id: p.tenant_id, subject_id: p.subject_id, action: 'advisory.extract', capsule_digest: record.capsule_digest, ...clone(input), issued_at: now, expires_at: Math.min(now + input.ttl_ms, record.capsule.expires_at) }; this.f.store.insert(p.tenant_id, 'ai-capability', cap.capability_id, cap, now); return signed(cap, this.f.keys(p.tenant_id).execution, 'ai-tool'); });
  }
  extract(p, input) {
    this.f.authorize(p, ['operator', 'policy_admin']); fields(input, ['capability', 'source', 'context']);
    requireThat(typeof input.source === 'string' && Buffer.byteLength(input.source) <= 65536, 'INV-413-BODY', 'Advisory source exceeds bound', 413);
    fields(input.context, ['provider', 'model', 'version', 'prompt_digest', 'configuration_digest', 'tools']);
    for (const k of ['provider', 'model', 'version']) text(input.context[k], k, 128);
    requireThat(input.context.provider === 'local' && input.context.model === 'deterministic-extractor' && input.context.version === '1' && input.context.tools?.length === 1 && input.context.tools[0] === 'advisory.extract' && /^[a-f0-9]{64}$/.test(input.context.prompt_digest) && /^[a-f0-9]{64}$/.test(input.context.configuration_digest), 'INV-403-AI-TOOL', 'Only configured local advisory provider and extraction tool may run', 403);
    return this.f.transaction(p, now => {
      const cap = verifySigned(input.capability, this.f.executionPublic(p.tenant_id), 'ai-tool');
      requireThat(cap.tenant_id === p.tenant_id && cap.subject_id === p.subject_id && cap.action === 'advisory.extract' && cap.expires_at > now && cap.issued_at <= now && cap.source_digests.includes(hashBytes(input.source)) && !this.f.revoked(p.tenant_id, 'capability', cap.capability_id) && !this.f.revoked(p.tenant_id, 'key', input.capability.protected.key_id), 'INV-403-AI-TOOL', 'Advisory capability scope, source or expiry denied', 403);
      const registered = this.f.store.must(p.tenant_id, 'ai-capability', cap.capability_id);
      requireThat(digest(registered) === digest(cap) && !this.f.store.get(p.tenant_id, 'ai-run', cap.capability_id), 'INV-409-REPLAY', 'Advisory capability already used or altered', 409);
      const fields = extractAdvisory(input.source, cap.fields), out = { format: 'IF-ADVISORY-1', advisory: true, authority: false, capsule_digest: cap.capsule_digest, fields, context: { ...clone(input.context), timestamp: now, source_digest: hashBytes(input.source), evaluation_suite: ADVISORY_EVALUATION_VERSION } };
      requireThat(Buffer.byteLength(JSON.stringify(out)) <= cap.max_output_bytes, 'INV-413-AI-OUTPUT', 'Advisory output limit exceeded', 413);
      this.f.store.insert(p.tenant_id, 'ai-run', cap.capability_id, { context: out.context, output_digest: digest(out), field_count: fields.length, plaintext_retained: false }, now);
      this.f.store.audit(p.tenant_id, 'AI_ADVISORY_EXECUTED', p.subject_id, cap.capability_id, { context_digest: digest(out.context), output_digest: digest(out), advisory: true }, now); return out;
    });
  }
}
export function compareEvaluations(baseline, candidate) {
  fields(candidate, ['suite', 'provider', 'model', 'version', 'results']);
  requireThat(candidate.suite === ADVISORY_EVALUATION_VERSION && baseline.suite === candidate.suite && Array.isArray(candidate.results), 'INV-400-AI-EVAL', 'Unknown evaluation version');
  const required = ['injection', 'provenance', 'structured-output', 'ambiguous-fields', 'tenant-isolation'];
  const pass = required.every(name => candidate.results.some(x => x.name === name && x.pass === true)) && baseline.results.filter(x => x.pass).every(x => candidate.results.some(y => y.name === x.name && y.pass === true)) && new Set(candidate.results.map(x => x.name)).size === candidate.results.length;
  return { suite: candidate.suite, promotion: pass ? 'ALLOW' : 'DENY', baseline_digest: digest(baseline), candidate_digest: digest(candidate), actual_provider_validation: candidate.provider === 'local' };
}
