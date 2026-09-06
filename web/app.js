export function nextAction(status) {
  return ({ CANONICALISED: 'Attach independently signed evidence, then evaluate.', EVIDENCED: 'Evaluate the exact evidence set and collect eligible approvals.', ALLOW: 'Mint the single-use certificate before its evidence or approval expires.', ESCROW: 'Resolve the listed evidence or approval gaps, then re-evaluate.', SHIELD: 'Create a new proposal with the specified field removal; this action cannot execute.', DEFER: 'Wait until the mandatory condition is met, then re-evaluate.', DENY: 'This action is permanently denied. Investigate the reason; any revised request needs a new capsule.', CERTIFIED: 'Dry-run the gate or execute the exact reviewed change before expiry.', EXECUTING: 'Reconcile the durable transaction. Never blindly repeat the mutation.', UNCERTAIN: 'Reconcile the target journal. Do not submit a replacement until the operator resolves uncertainty.', VERIFIED: 'The observed synthetic outcome matches the authorised action. No repeat execution is allowed.', FAILED: 'The target rejected execution. Inspect state before creating any separately authorised replacement.', CANCELLED: 'The action is closed. Its prior authority cannot execute.' })[status] ?? 'Inspect the current state before continuing.';
}
export function actionAvailability(status, roles) {
  const mutable = !['DENY', 'CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED'].includes(status);
  const can = (...r) => r.some(x => roles.includes(x));
  return { evaluate: mutable && can('operator', 'policy_admin', 'approver', 'custodian'), mint: mutable && status === 'ALLOW' && can('operator', 'policy_admin'), evidence: mutable && can('operator', 'security', 'policy_admin'), approval: mutable && can('approver', 'custodian'), execute: status === 'CERTIFIED' && can('operator', 'policy_admin'), reconcile: ['EXECUTING', 'UNCERTAIN', 'VERIFIED', 'FAILED'].includes(status) && can('operator', 'security', 'policy_admin'), cancel: !['EXECUTING', 'UNCERTAIN', 'VERIFIED', 'FAILED', 'CANCELLED'].includes(status) && can('operator', 'security', 'policy_admin') };
}
export function typedValue(value, rule) {
  if (rule === 'positive') { if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error('Enter a positive integer without decimals or exponent notation.'); return Number(value); }
  if (!value.trim()) throw new Error('Complete all required action fields.'); return value;
}
export function csvSelection(value) { const items = value.split(',').map(x => x.trim()).filter(Boolean); if (!items.length || new Set(items).size !== items.length) throw new Error('Provide a nonempty list without duplicates.'); return items; }
export function formatQuantity(c) { if (c.action.type === 'finance.payment.first') return `${c.requested_state.currency} ${(c.quantity / 100).toFixed(2)} (${c.quantity} minor units)`; return `${c.quantity} unit${c.quantity === 1 ? '' : 's'}`; }
export function auditOptions(roles) {
  return [['full', 'Full signed chain', ['auditor', 'security']], ['finance', 'Finance: workflow metadata', ['audit_finance']], ['security', 'Security: incident metadata', ['audit_security']], ['privacy', 'Privacy: retention metadata', ['audit_privacy']], ['technical', 'Technical: integrity digests', ['audit_technical']]].filter(([, , allowed]) => roles.some(role => allowed.includes(role))).map(([value, label]) => ({ value, label }));
}
export function workspaceAccess(roles) {
  const can = (...allowed) => roles.some(role => allowed.includes(role));
  const actions = can('operator', 'approver', 'custodian', 'security', 'policy_admin');
  return { batches: actions, actions, propose: can('operator'), coverage: actions || can('auditor'), policy: can('policy_admin', 'security'), runtime: can('operator'), audit: auditOptions(roles).length > 0 };
}

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  const state = { me: null, csrf: null, schemas: [], policy: null, selected: null, currentState: null, currentResource: null, offset: 0, pageCount: 0, runtime: null, batches: [], batch: null };
  function notify(message, error = false) { const el = $('notice'); el.hidden = false; el.textContent = message; el.dataset.error = String(error); if (error) el.setAttribute('role', 'alert'); else el.setAttribute('role', 'status'); }
  async function api(path, { method = 'GET', body, headers = {} } = {}) {
    const response = await fetch(path, { method, credentials: 'same-origin', headers: { ...headers, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(state.csrf ? { 'X-CSRF-Token': state.csrf } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const value = await response.json();
    if (!response.ok) { if (response.status === 401) { state.me = null; state.csrf = null; $('login-panel').hidden = false; $('workspace').hidden = true; $('logout').hidden = true; $('identity').textContent = 'Session expired'; } throw new Error(`${value.error?.code ?? response.status}: ${value.error?.message ?? 'Request failed'}`); }
    return value;
  }
  function handle(id, event, fn) {
    $(id).addEventListener(event, async e => {
      e.preventDefault(); const buttons = event === 'submit' ? [...e.currentTarget.querySelectorAll('button')] : [e.currentTarget]; const wasDisabled = buttons.map(b => b.disabled); buttons.forEach(b => { b.disabled = true; b.setAttribute('aria-busy', 'true'); });
      try { await fn(e); } catch (error) { notify(error.message || 'Network unavailable. Retry after checking connection.', true); }
      finally { buttons.forEach((b, i) => { b.disabled = wasDisabled[i]; b.removeAttribute('aria-busy'); }); if (state.selected) applyAvailability(); $('previous').disabled = state.offset === 0; $('next').disabled = state.pageCount < 25; }
    });
  }
  function node(tag, value, className) { const n = document.createElement(tag); if (value !== undefined) n.textContent = value; if (className) n.className = className; return n; }
  function show(view) { document.querySelectorAll('.view').forEach(el => { el.hidden = el.id !== `view-${view}`; }); document.querySelectorAll('nav button').forEach(b => { if (b.dataset.view === view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); }); }
  function download(value, filename) { const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }), url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  async function loadList() {
    const page = await api(`/v1/action-capsules?limit=25&offset=${state.offset}`); $('action-rows').replaceChildren();
    for (const r of page.items) {
      const tr = node('tr'), title = node('td', r.capsule.action.type); title.append(node('span', r.capsule.action.target_resource, 'resource')); tr.append(title, node('td', formatQuantity(r.capsule)));
      const status = node('td'), badge = node('span', r.status, 'badge'); badge.dataset.state = r.status; status.append(badge); tr.append(status, node('td', new Date(r.capsule.expires_at).toLocaleString()));
      const cell = node('td'), button = node('button', 'Review exact action', 'secondary'); button.addEventListener('click', () => detail(r.capsule.capsule_id).catch(e => notify(e.message, true))); cell.append(button); tr.append(cell); $('action-rows').append(tr);
    }
    state.pageCount = page.items.length; $('count-total').textContent = page.items.length; $('count-pending').textContent = page.items.filter(x => !['VERIFIED', 'DENY', 'FAILED', 'CANCELLED'].includes(x.status)).length; $('count-verified').textContent = page.items.filter(x => x.status === 'VERIFIED').length;
    $('empty').hidden = page.items.length !== 0; $('previous').disabled = state.offset === 0; $('next').disabled = page.items.length < 25; $('page-label').textContent = `Page ${Math.floor(state.offset / 25) + 1}`;
  }
  function applyAvailability() {
    if (!state.selected || !state.me) return; const available = actionAvailability(state.selected.status, state.me.roles);
    for (const [id, key] of [['evaluate', 'evaluate'], ['mint', 'mint'], ['dry-run', 'execute'], ['execute', 'execute'], ['reconcile', 'reconcile'], ['cancel', 'cancel'], ['challenge', 'approval']]) $(id).disabled = !available[key];
    for (const [id, key] of [['evidence-form', 'evidence'], ['approval-form', 'approval']]) for (const control of $(id).elements) control.disabled = !available[key];
  }
  async function detail(id) {
    const r = await api(`/v1/action-capsules/${id}`); state.selected = r; const c = r.capsule;
    $('detail-title').textContent = c.action.type; $('detail-id').textContent = c.capsule_id; $('detail-status').textContent = r.status; $('detail-status').dataset.state = r.status;
    $('material-details').replaceChildren();
    for (const [key, value] of Object.entries({ Resource: c.action.target_resource, Destination: c.destination, Quantity: formatQuantity(c), Purpose: c.action.purpose, Owner: c.actor.subject_id, Expires: new Date(c.expires_at).toLocaleString(), Exclusions: c.exclusions.join(', ') || 'None', Coverage: 'Simulation only; production enforcement not established' })) $('material-details').append(node('dt', key), node('dd', value));
    $('old-values').textContent = JSON.stringify(c.current_state.material_fields, null, 2); $('new-values').textContent = JSON.stringify(c.requested_state, null, 2); $('next-action').textContent = nextAction(r.status);
    $('decision-reasons').replaceChildren(); for (const reason of r.decision?.reasons ?? []) $('decision-reasons').append(node('p', `${reason.code}: ${reason.message}`, 'help'));
    $('binding-digests').textContent = `Capsule SHA-256: ${r.capsule_digest}\nEvidence: ${r.evidence.length} · Signed approvals: ${r.approvals.length}`;
    $('outcome').hidden = true; applyAvailability(); show('detail');
  }
  function renderRequested() {
    $('requested-fields').replaceChildren(); const schema = state.schemas.find(s => s.type === $('action-type').value); if (!schema) return;
    for (const [key, rule] of Object.entries(schema.requested)) {
      const id = `requested-${key}`, label = node('label', key === 'amount_minor' ? 'Amount in minor currency units (for example cents)' : key.replaceAll('_', ' ')); label.htmlFor = id;
      const input = node('input'); input.id = id; input.name = key; input.required = true; input.dataset.rule = rule;
      if (rule === 'positive') { input.type = 'number'; input.min = '1'; input.step = '1'; input.max = '1000000000000'; } else { input.type = 'text'; input.maxLength = '512'; }
      $('requested-fields').append(label, input);
    }
    state.currentState = null; $('state-preview').textContent = 'Read current target state before creating the proposal.';
  }
  handle('login-form', 'submit', async () => {
    const login = await api('/session', { method: 'POST', body: { token: $('token').value } }); $('token').value = ''; state.csrf = login.csrf_token; state.me = await api('/v1/me');
    $('identity').textContent = `${state.me.tenant_id} / ${state.me.subject_id}`; $('logout').hidden = false; $('login-panel').hidden = true; $('workspace').hidden = false;
    state.schemas = await api('/v1/schemas'); $('action-type').replaceChildren(new Option('Choose action type', '')); for (const s of state.schemas.filter(s => s.type.startsWith('finance.'))) $('action-type').append(new Option(s.type, s.type));
    const canActions = state.me.roles.some(r => ['operator', 'approver', 'custodian', 'security', 'policy_admin'].includes(r));
    const projections = auditOptions(state.me.roles);
    const access = workspaceAccess(state.me.roles);
    $('audit-view').replaceChildren(new Option('Choose an authorised projection', ''));
    for (const { value, label } of projections) $('audit-view').append(new Option(label, value));
    for (const el of $('batch-form').elements) el.disabled = !state.me.roles.some(r => ['operator', 'policy_admin'].includes(r));
    document.querySelectorAll('nav button').forEach(b => { b.hidden = !access[b.dataset.view]; });
    if (canActions) { show('actions'); await loadList(); } else if (access.audit) { show('audit'); } else { show('coverage'); await loadCoverage(); }
    notify('Connected to the isolated engineering workspace. Targets and evidence issuers are synthetic.');
  });
  handle('logout', 'click', async () => { await api('/session/logout', { method: 'POST', body: {} }); state.csrf = null; state.me = null; state.selected = null; state.runtime = null; state.currentState = null; location.reload(); });
  document.querySelectorAll('nav button').forEach(button => button.addEventListener('click', async () => { show(button.dataset.view); try { if (button.dataset.view === 'coverage') await loadCoverage(); if (button.dataset.view === 'actions') await loadList(); if (button.dataset.view === 'batches') await loadBatches(); } catch (e) { notify(e.message, true); } }));
  handle('refresh', 'click', loadList); handle('previous', 'click', async () => { state.offset = Math.max(0, state.offset - 25); await loadList(); }); handle('next', 'click', async () => { state.offset += 25; await loadList(); }); handle('back-actions', 'click', async () => { show('actions'); await loadList(); });
  $('action-type').addEventListener('change', renderRequested); $('resource').addEventListener('input', () => { state.currentState = null; state.currentResource = null; });
  handle('load-state', 'click', async () => { if (!$('resource').checkValidity() || !$('resource').value) throw new Error('Enter a valid target resource identifier.'); const resource = $('resource').value; state.currentState = await api(`/v1/resources/${encodeURIComponent(resource)}`); state.currentResource = resource; $('state-preview').textContent = JSON.stringify(state.currentState, null, 2); });
  handle('propose-form', 'submit', async () => {
    if (!state.currentState || state.currentResource !== $('resource').value) throw new Error('Read current target state for this exact resource first.');
    const schema = state.schemas.find(s => s.type === $('action-type').value), requested = {}; for (const input of $('requested-fields').querySelectorAll('input')) requested[input.name] = typedValue(input.value, input.dataset.rule);
    const policy = await api('/v1/policy'), now = Date.now(), ttl = typedValue($('ttl').value, 'positive');
    const input = { schema_id: schema.id, schema_digest: schema.digest, actor: { subject_id: state.me.subject_id, identity_class: 'workforce', device_id: state.me.device_id }, action: { type: schema.type, target_resource: $('resource').value, purpose: $('purpose').value }, current_state: state.currentState, requested_state: requested, destination: requested.bank_account, quantity: requested.amount_minor ?? 1, exclusions: [], evidence_refs: [], policy_version: policy.version, nonce: crypto.randomUUID(), created_at: now, expires_at: now + ttl * 60000, rollback_or_compensation: $('rollback').value, privacy_classification: 'confidential' };
    const r = await api('/v1/action-capsules', { method: 'POST', body: input, headers: { 'Idempotency-Key': crypto.randomUUID() } }); notify('Immutable proposal created. No target execution has occurred.'); await detail(r.capsule.capsule_id);
  });
  handle('evaluate', 'click', async () => { await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/evaluate`, { method: 'POST', body: {} }); await detail(state.selected.capsule.capsule_id); });
  handle('mint', 'click', async () => { await api('/v1/certificates', { method: 'POST', body: { capsule_id: state.selected.capsule.capsule_id } }); await detail(state.selected.capsule.capsule_id); notify('Single-use certificate issued. It expires shortly and cannot authorise a different action.'); });
  async function execute(dry) {
    const r = state.selected;
    if (!dry && !window.confirm(`Execute this exact synthetic change?\n${r.capsule.action.type}\nTarget: ${r.capsule.action.target_resource}\nDestination: ${r.capsule.destination}\nQuantity: ${formatQuantity(r.capsule)}\nNo real bank or ERP will be changed.`)) return;
    const certificate = await api(`/v1/certificates/${r.certificate_id}`), result = await api('/gate/v1/execute', { method: 'POST', body: { certificate, dry_run: dry } }); await detail(r.capsule.capsule_id); $('outcome').hidden = false; $('outcome').textContent = JSON.stringify(result, null, 2); notify(dry ? 'Dry-run passed without target mutation.' : `Synthetic outcome: ${result.payload.status}.`);
  }
  handle('dry-run', 'click', () => execute(true)); handle('execute', 'click', () => execute(false));
  handle('reconcile', 'click', async () => { const result = await api(`/gate/v1/outcomes/${state.selected.certificate_id}`); await detail(state.selected.capsule.capsule_id); $('outcome').hidden = false; $('outcome').textContent = JSON.stringify(result, null, 2); });
  handle('cancel', 'click', async () => { await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/cancel`, { method: 'POST', body: {} }); await detail(state.selected.capsule.capsule_id); });
  handle('evidence-form', 'submit', async () => { await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/evidence`, { method: 'POST', body: JSON.parse($('evidence-json').value) }); $('evidence-json').value = ''; await detail(state.selected.capsule.capsule_id); notify('Signed evidence attached. Earlier approvals were invalidated.'); });
  handle('challenge', 'click', async () => { const challenge = await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/approval-challenge`); download(challenge, `approval-challenge-${challenge.capsule_id}.json`); notify('Challenge downloaded. Sign it outside the browser with your independently controlled software key.'); });
  handle('approval-form', 'submit', async () => { const envelope = JSON.parse($('approval-json').value); if (envelope.payload?.capsule_id !== state.selected.capsule.capsule_id) throw new Error('Approval does not match the currently reviewed action.'); await api('/v1/approvals', { method: 'POST', body: envelope }); $('approval-json').value = ''; await detail(state.selected.capsule.capsule_id); notify('Exact-action signature accepted. Policy must still be evaluated.'); });
  async function loadCoverage() {
    const manifest = (await api('/v1/coverage')).payload; $('coverage-json').textContent = JSON.stringify(manifest, null, 2); $('connector-json').textContent = JSON.stringify(await api('/v1/connectors'), null, 2); $('coverage-cards').replaceChildren();
    if (!manifest.paths.length) $('coverage-cards').append(node('p', 'No execution paths declared. Coverage is unknown; no enforcement guarantee is available.', 'callout'));
    for (const path of manifest.paths) { const card = node('article', undefined, 'coverage-card'), badge = node('span', path.effective_status, 'badge'); badge.dataset.state = path.effective_status === 'ENFORCED' ? 'VERIFIED' : 'DEFER'; card.append(node('h3', path.path_id), badge, node('p', `${path.action_type} · ${path.environment}`), node('p', `Owner: ${path.owner} · Connector: ${path.connector_version}`), node('p', path.next_action)); $('coverage-cards').append(card); }
  }
  handle('refresh-coverage', 'click', loadCoverage); handle('load-policy', 'click', async () => { $('policy-json').value = JSON.stringify(await api('/v1/policy'), null, 2); });
  handle('policy-form', 'submit', async () => { $('policy-result').textContent = JSON.stringify(await api('/v1/policies/simulate', { method: 'POST', body: JSON.parse($('policy-json').value) }), null, 2); notify('Simulation complete. No policy was activated.'); });
  handle('runtime-form', 'submit', async () => {
    state.runtime = await api('/v1/capabilities', { method: 'POST', body: { device_id: state.me.device_id, resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: csvSelection($('runtime-columns').value), row_ids: csvSelection($('runtime-rows').value), classification: 'internal', jurisdiction: 'EU', max_cost: typedValue($('runtime-cost').value, 'positive'), ttl_ms: 60000 } }); $('runtime-read').disabled = false; $('runtime-result').textContent = JSON.stringify(state.runtime.payload, null, 2); notify('Narrow capability issued. Each read will consume the shared rolling budget.');
  });
  handle('runtime-read', 'click', async () => { const c = state.runtime.payload; $('runtime-result').textContent = JSON.stringify(await api('/gate/v1/runtime', { method: 'POST', body: { capability: state.runtime, device_id: c.device_id, resource: c.resource, destination: c.destination, action: c.action, purpose: c.purpose, columns: c.columns, row_ids: c.row_ids, request_id: crypto.randomUUID(), protocol: 'https', port: 443 } }), null, 2); });
  handle('audit-form', 'submit', async () => { const role = $('audit-view').value; if (!role) throw new Error('Choose your authorised export scope.'); const bundle = await api(role === 'full' ? '/v1/audit-exports' : '/v1/audit-views', { method: 'POST', body: { purpose: $('audit-purpose').value, ...(role === 'full' ? {} : { role }) } }); download(bundle, `invariant-audit-${role}-${state.me.tenant_id}.json`); notify(role === 'full' ? `Exported ${bundle.entries.length} linked records. Verify with independently pinned trust.` : `Exported ${bundle.payload.entries.length} least-privilege records. This signed projection is not the full chain.`); });
  async function loadBatches() { state.batches = await api('/v1/compositions'); state.batch = null; $('batch-select').replaceChildren(new Option('Choose a batch', '')); for (const envelope of state.batches) $('batch-select').append(new Option(`${envelope.payload.children.length} actions · ${envelope.payload.composition_id}`, envelope.payload.composition_id)); renderBatch(); }
  function renderBatch() {
    const c = state.batch; $('batch-children').replaceChildren(); const canApprove = c && state.me.roles.some(r => ['approver', 'custodian'].includes(r)) && c.expires_at > Date.now(); $('batch-challenge').disabled = !canApprove; $('batch-approval-submit').disabled = !canApprove;
    if (!c) { $('batch-summary').textContent = 'Select a batch to inspect every material change and aggregate constraint.'; return; }
    $('batch-summary').textContent = `${c.children.length} exact actions · Aggregate: ${JSON.stringify(c.aggregate)} · Expires: ${new Date(c.expires_at).toLocaleString()} · All children required. Changes invalidate the batch.`;
    for (const child of c.children) { const card = node('article', undefined, 'batch-child'), a = child.action; card.append(node('h3', `${a.action.type} · ${a.action.target_resource}`), node('p', `Destination: ${a.destination} · Quantity: ${formatQuantity(a)} · Purpose: ${a.action.purpose}`, 'help'), node('h3', 'Current → requested state'), node('pre', JSON.stringify({ current: a.current_state.material_fields, requested: a.requested_state, exclusions: a.exclusions }, null, 2), 'code'), node('p', `SHA-256 ${child.capsule_digest}`, 'mono wrap')); $('batch-children').append(card); }
  }
  $('batch-select').addEventListener('change', () => { state.batch = state.batches.find(e => e.payload.composition_id === $('batch-select').value)?.payload ?? null; renderBatch(); });
  handle('refresh-batches', 'click', loadBatches);
  handle('batch-form', 'submit', async () => { const ids = csvSelection($('batch-ids').value), ttl = typedValue($('batch-ttl').value, 'positive'); if (ids.length > 32 || ttl > 300) throw new Error('A batch permits up to 32 actions and 300 seconds.'); const tree = { root: 'root', nodes: { root: { kind: 'all', children: ids.map((_, i) => `child-${i}`) }, ...Object.fromEntries(ids.map((id, i) => [`child-${i}`, { kind: 'action', capsule_id: id }])) } }; const result = await api('/v1/compositions', { method: 'POST', body: { tree, expires_at: Date.now() + ttl * 1000 }, headers: { 'Idempotency-Key': crypto.randomUUID() } }); await loadBatches(); $('batch-select').value = result.payload.composition_id; state.batch = result.payload; renderBatch(); notify('Exact batch created. No execution authority was added.'); });
  handle('batch-challenge', 'click', async () => { if (!state.batch) throw new Error('Select a batch first.'); const challenge = await api(`/v1/compositions/${state.batch.composition_id}/challenge`); download(challenge, `batch-challenge-${state.batch.composition_id}.json`); notify('Review every visible action and aggregate before signing offline.'); });
  handle('batch-approval-form', 'submit', async () => { const envelope = JSON.parse($('batch-approval-json').value); if (!state.batch || envelope.payload?.composition_id !== state.batch.composition_id) throw new Error('Signature does not match the visible batch.'); await api('/v1/batch-approvals', { method: 'POST', body: envelope }); $('batch-approval-json').value = ''; notify('Exact batch signature accepted. Each child must still satisfy policy and receive its own certificate.'); });
}
