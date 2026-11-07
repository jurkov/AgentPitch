// Agent Pitch — Admin section (users + teams management)
//
// Two audiences share this section, gated by role (window.authState):
//   - Admin: full user CRUD, role changes, password resets, team CRUD, and
//            member/lead assignment on every team.
//   - Team lead (non-admin): sees only the teams they lead, and may add/remove
//            members and promote/demote leads within those teams. No user CRUD.
//
// All enforcement is server-side; this UI only hides controls the caller
// can't use, to avoid dead buttons. Uses design-system classes exclusively.

const ADMIN_ROOT = () => document.getElementById('admin-root');

let _usersCache = [];   // [{id, username, role, teams, leads, ...}]
let _teamsCache = [];   // [{slug, name, lead_user_ids, member_user_ids}]

// ── small helpers ───────────────────────────────────────────────

function _esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

async function _api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  let body = null;
  try { body = await res.json(); } catch (_) {}
  return { ok: res.ok, status: res.status, body };
}

// Turn a FastAPI error body into a human string. `detail` can be a plain
// string (our HTTPException raises) OR an array of validation-error objects
// (Pydantic 422). Rendering the array directly gave "[object Object]"; this
// flattens it to readable text.
function _detailText(body, fallback = 'Request failed.') {
  if (!body || body.detail == null) return fallback;
  const d = body.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) {
    return d.map(e => (e && e.msg) ? e.msg : (typeof e === 'string' ? e : JSON.stringify(e)))
            .join('; ') || fallback;
  }
  if (typeof d === 'object') return d.msg || JSON.stringify(d);
  return String(d);
}

function _state() {
  return window.authState || { user: null, teams: [], isTeamLead: false };
}
function _isAdmin() { return _state().user && _state().user.role === 'admin'; }
function _username(userId) {
  const u = _usersCache.find(x => x.id === userId);
  return u ? u.username : userId.slice(0, 8);
}

// ── data loading ────────────────────────────────────────────────

async function _loadData() {
  // Both calls are attempted unconditionally — the SERVER is the authority on
  // authorization (/api/users is admin-only and returns 401/403 otherwise).
  // We must NOT gate on the client-side role here: on a fresh page reload
  // window.authState may not be populated yet, which previously left the
  // lists empty. A 401/403 simply yields an empty users list.
  const [teamsRes, usersRes] = await Promise.all([
    _api('/api/teams'),
    _api('/api/users'),
  ]);
  _teamsCache = (teamsRes.ok && teamsRes.body && teamsRes.body.teams) || [];
  _usersCache = (usersRes.ok && usersRes.body && usersRes.body.users) || [];
}

// ── rendering ───────────────────────────────────────────────────

function render() {
  const root = ADMIN_ROOT();
  if (!root) return;
  const admin = _isAdmin();

  const teamsForLead = admin
    ? _teamsCache
    : _teamsCache.filter(t => (_state().teams || []).some(mt => mt.slug === t.slug && mt.is_lead));

  root.innerHTML = `
    <div class="admin-wrap">
      ${admin ? _renderUsersPanel() : ''}
      ${_renderTeamsPanel(teamsForLead, admin)}
    </div>
  `;
  _wire(admin);
}

function _renderUsersPanel() {
  const rows = _usersCache.map(u => {
    const teamLabel = (u.teams && u.teams.length)
      ? u.teams.map(_esc).join(', ')
      : '<span class="dimer">no teams</span>';
    const leadBadge = (u.leads && u.leads.length)
      ? ` · leads ${u.leads.map(_esc).join(', ')}` : '';
    const emailLabel = u.email
      ? _esc(u.email)
      : '<span class="dimer">no email</span>';
    return `
      <div class="list-row" data-user-id="${_esc(u.id)}">
        <div class="list-row-content">
          <div class="list-row-line-1">
            ${_esc(u.username)}
            <span class="admin-role-tag admin-role-${_esc(u.role)}">${_esc(u.role)}</span>
          </div>
          <div class="list-row-line-2">${emailLabel} · ${teamLabel}${leadBadge}</div>
        </div>
        <div class="list-row-actions">
          <select class="sel admin-role-sel" data-user-id="${_esc(u.id)}" aria-label="Role for ${_esc(u.username)}">
            <option value="user" ${u.role === 'user' ? 'selected' : ''}>user</option>
            <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>admin</option>
          </select>
          <button class="btn btn-sm" data-action="edit-email" data-user-id="${_esc(u.id)}">Email</button>
          <button class="btn btn-sm" data-action="reset-pw" data-user-id="${_esc(u.id)}">Reset PW</button>
          <button class="btn btn-sm btn-danger" data-action="del-user" data-user-id="${_esc(u.id)}">Delete</button>
        </div>
      </div>`;
  }).join('');

  return `
    <section class="admin-panel">
      <div class="ap-section"><span>Users</span><span class="rule"></span></div>

      <div class="admin-create-row">
        <input class="ipt" id="admin-new-username" placeholder="username" autocomplete="off" spellcheck="false">
        <input class="ipt" id="admin-new-email" type="email" placeholder="email (required)" autocomplete="off" spellcheck="false" required>
        <input class="ipt" id="admin-new-password" type="password" placeholder="password (min 8)" autocomplete="new-password">
        <select class="sel" id="admin-new-role">
          <option value="user" selected>user</option>
          <option value="admin">admin</option>
        </select>
        <button class="btn btn-primary" id="admin-create-user-btn">+ Create user</button>
      </div>
      <div id="admin-user-error" class="form-error" hidden role="alert"></div>

      <div class="list-body">
        ${rows || '<div class="list-row skeleton">No users yet.</div>'}
      </div>
    </section>`;
}

function _renderTeamsPanel(teams, admin) {
  const teamCards = teams.map(t => _renderTeamCard(t, admin)).join('');
  return `
    <section class="admin-panel">
      <div class="ap-section"><span>Teams</span><span class="rule"></span></div>

      ${admin ? `
      <div class="admin-create-row">
        <input class="ipt" id="admin-new-team-name" placeholder="Display name (e.g. My Team)">
        <input class="ipt" id="admin-new-team-slug" placeholder="slug (optional — auto from name)" autocomplete="off" spellcheck="false">
        <button class="btn btn-primary" id="admin-create-team-btn">+ Create team</button>
      </div>
      <div id="admin-team-error" class="form-error" hidden role="alert"></div>
      ` : '<div class="field-help">You can manage members of the teams you lead.</div>'}

      <div class="admin-team-grid">
        ${teamCards || '<div class="list-row skeleton">No teams.</div>'}
      </div>
    </section>`;
}

function _renderTeamCard(t, admin) {
  const members = (t.member_user_ids || []).map(uid => {
    const isLead = (t.lead_user_ids || []).includes(uid);
    return `
      <div class="admin-member-row">
        <span class="admin-member-name">
          ${_esc(_username(uid))}
          ${isLead ? '<span class="admin-lead-tag">LEAD</span>' : ''}
        </span>
        <span class="admin-member-actions">
          ${isLead
            ? `<button class="btn btn-sm" data-action="demote" data-slug="${_esc(t.slug)}" data-user-id="${_esc(uid)}">Demote</button>`
            : `<button class="btn btn-sm" data-action="promote" data-slug="${_esc(t.slug)}" data-user-id="${_esc(uid)}">Make lead</button>`}
          <button class="btn btn-sm btn-danger" data-action="remove-member" data-slug="${_esc(t.slug)}" data-user-id="${_esc(uid)}">Remove</button>
        </span>
      </div>`;
  }).join('');

  // Candidate users to add (admins have the full list; leads only see it if
  // the users list was returned — which it isn't for non-admins, so leads add
  // by picking from all known members across teams is not possible; admins do
  // the heavy lifting of user creation). We still render an add control for
  // admins.
  const addControl = admin ? `
    <div class="admin-add-member-row">
      <select class="sel admin-add-member-sel" data-slug="${_esc(t.slug)}">
        <option value="">+ add member…</option>
        ${_usersCache
          .filter(u => !(t.member_user_ids || []).includes(u.id))
          .map(u => `<option value="${_esc(u.id)}">${_esc(u.username)}</option>`)
          .join('')}
      </select>
    </div>` : '';

  return `
    <div class="admin-team-card" data-slug="${_esc(t.slug)}">
      <div class="admin-team-head">
        <span class="admin-team-name">${_esc(t.name)}</span>
        <span class="admin-team-slug">${_esc(t.slug)}</span>
        ${admin ? `<button class="btn btn-sm btn-danger admin-team-del" data-action="del-team" data-slug="${_esc(t.slug)}">Delete</button>` : ''}
      </div>
      <div class="admin-member-list">
        ${members || '<div class="dimer admin-empty">No members.</div>'}
      </div>
      ${addControl}
    </div>`;
}

// ── actions ─────────────────────────────────────────────────────

function _err(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  if (msg) { el.textContent = msg; el.hidden = false; }
  else { el.textContent = ''; el.hidden = true; }
}

async function _reload() {
  await _loadData();
  render();
}

function _wire(admin) {
  const root = ADMIN_ROOT();
  if (!root) return;

  if (admin) {
    const createUserBtn = document.getElementById('admin-create-user-btn');
    if (createUserBtn) createUserBtn.addEventListener('click', _createUser);
    const createTeamBtn = document.getElementById('admin-create-team-btn');
    if (createTeamBtn) createTeamBtn.addEventListener('click', _createTeam);

    root.querySelectorAll('.admin-role-sel').forEach(sel =>
      sel.addEventListener('change', _changeRole));
    root.querySelectorAll('.admin-add-member-sel').forEach(sel =>
      sel.addEventListener('change', _addMember));
  }

  // Click-delegated actions (present for both admin + lead where allowed).
  root.querySelectorAll('[data-action]').forEach(btn =>
    btn.addEventListener('click', _handleAction));
}

async function _createUser() {
  _err('admin-user-error', '');
  const username = document.getElementById('admin-new-username').value.trim();
  const email = document.getElementById('admin-new-email').value.trim();
  const password = document.getElementById('admin-new-password').value;
  const role = document.getElementById('admin-new-role').value;
  if (!username || !password || !email) {
    _err('admin-user-error', 'Username, email and password are all required.');
    return;
  }
  const payload = { username, email, password, role, must_change_password: true };
  const { ok, body } = await _api('/api/users', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!ok) { _err('admin-user-error', _detailText(body, 'Could not create user.')); return; }
  await _reload();
}

async function _changeRole(e) {
  const userId = e.target.dataset.userId;
  const role = e.target.value;
  const { ok, body } = await _api(`/api/users/${userId}/role`, {
    method: 'PUT', body: JSON.stringify({ role }),
  });
  if (!ok) { _err('admin-user-error', _detailText(body, 'Could not change role.')); await _reload(); return; }
  await _reload();
}

// Turn arbitrary user input into a server-valid slug (^[a-z0-9_-]+$):
// lowercase, spaces/invalid chars → hyphens, collapse repeats, trim ends.
function _slugify(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

async function _createTeam() {
  _err('admin-team-error', '');
  const nameEl = document.getElementById('admin-new-team-name');
  const slugEl = document.getElementById('admin-new-team-slug');
  const name = nameEl.value.trim();
  // If the slug field is blank, derive it from the name. Either way, sanitize
  // so a natural-language entry ("My Team") becomes a valid slug ("my-team")
  // instead of hitting a 422 the user can't easily interpret.
  const rawSlug = slugEl.value.trim() || name;
  const slug = _slugify(rawSlug);
  if (!name) { _err('admin-team-error', 'Team name is required.'); return; }
  if (!slug) { _err('admin-team-error', 'Could not derive a valid slug — use letters, numbers, - or _.'); return; }
  const { ok, body } = await _api('/api/teams', {
    method: 'POST', body: JSON.stringify({ slug, name }),
  });
  if (!ok) { _err('admin-team-error', _detailText(body, 'Could not create team.')); return; }
  await _reload();
}

async function _addMember(e) {
  const slug = e.target.dataset.slug;
  const userId = e.target.value;
  if (!userId) return;
  const { ok, body } = await _api(`/api/teams/${slug}/members`, {
    method: 'POST', body: JSON.stringify({ user_id: userId }),
  });
  if (!ok) { _err('admin-team-error', _detailText(body, 'Could not add member.')); }
  await _reload();
}

async function _handleAction(e) {
  const btn = e.currentTarget;
  const action = btn.dataset.action;
  const slug = btn.dataset.slug;
  const userId = btn.dataset.userId;

  let res;
  switch (action) {
    case 'del-user':
      if (!confirm(`Delete user "${_username(userId)}"? This cannot be undone.`)) return;
      res = await _api(`/api/users/${userId}`, { method: 'DELETE' });
      break;
    case 'reset-pw': {
      const pw = prompt('New password for this user (min 8 chars):');
      if (!pw) return;
      res = await _api(`/api/users/${userId}/password`, {
        method: 'PUT', body: JSON.stringify({ new_password: pw, must_change_password: true }),
      });
      break;
    }
    case 'edit-email': {
      const current = (_usersCache.find(u => u.id === userId) || {}).email || '';
      const email = prompt('New email for this user:', current);
      if (email === null) return;            // cancelled
      if (!email.trim()) {                   // email is required
        _err('admin-user-error', 'Email cannot be empty.');
        return;
      }
      res = await _api(`/api/users/${userId}/email`, {
        method: 'PUT', body: JSON.stringify({ email: email.trim() }),
      });
      break;
    }
    case 'del-team':
      if (!confirm(`Delete team "${slug}"? Member accounts are kept.`)) return;
      res = await _api(`/api/teams/${slug}`, { method: 'DELETE' });
      break;
    case 'remove-member':
      res = await _api(`/api/teams/${slug}/members/${userId}`, { method: 'DELETE' });
      break;
    case 'promote':
      res = await _api(`/api/teams/${slug}/leads`, {
        method: 'POST', body: JSON.stringify({ user_id: userId }),
      });
      break;
    case 'demote':
      res = await _api(`/api/teams/${slug}/leads/${userId}`, { method: 'DELETE' });
      break;
    default:
      return;
  }
  if (res && !res.ok) {
    const where = (action.includes('team') || action === 'remove-member'
      || action === 'promote' || action === 'demote') ? 'admin-team-error' : 'admin-user-error';
    _err(where, _detailText(res.body, 'Action failed.'));
  }
  await _reload();
}

// ── section lifecycle ───────────────────────────────────────────

const ALL_SECTION_IDS = [
  'section-matches', 'section-strategies', 'section-arena',
  'section-config', 'section-cup', 'section-league', 'section-admin',
];

// Ensure window.authState is populated before we decide admin-vs-lead layout.
// On a hard reload the section can activate before auth-ui's async
// /api/auth/me has resolved — so if the role is unknown, resolve it now.
async function _ensureAuthReady() {
  if (window.authState && window.authState.user) return;
  if (window.authUI && typeof window.authUI.refresh === 'function') {
    try { await window.authUI.refresh(); } catch (_) {}
  }
}

window.adminSection = {
  async activate() {
    ALL_SECTION_IDS.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      if (id === 'section-admin') el.removeAttribute('hidden');
      else el.setAttribute('hidden', '');
    });
    const root = ADMIN_ROOT();
    if (root) root.innerHTML = '<div class="section-placeholder">Loading…</div>';
    try {
      await _ensureAuthReady();
      await _loadData();
      render();
    } catch (err) {
      console.error('[admin] load failed', err);
      if (root) root.innerHTML = '<div class="section-placeholder">Failed to load admin data.</div>';
    }
  },
  deactivate() {
    const el = document.getElementById('section-admin');
    if (el) el.setAttribute('hidden', '');
  },
};

// If auth resolves a moment after the admin section already rendered (reload
// race), re-render so the correct admin/lead view + lists show up.
window.addEventListener('auth:ready', () => {
  const sec = document.getElementById('section-admin');
  if (sec && !sec.hasAttribute('hidden')) {
    _loadData().then(render).catch(() => {});
  }
});

console.log('[admin.js] loaded');
