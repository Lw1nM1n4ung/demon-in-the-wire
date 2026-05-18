/* Wire_Ghost — AD Recon Cockpit.
 *
 * Three-panel layout:
 *   Left:  Credential profiles list + Quick Unauth form
 *   Right: Session history table with status polling
 *
 * API surface (all under /api/ad-recon/):
 *   GET    /profiles/            — list user's credential profiles
 *   POST   /profiles/            — create profile (password accepted, never returned)
 *   PUT    /profiles/<id>/       — update profile
 *   DELETE /profiles/<id>/       — delete profile
 *   GET    /sessions/            — list all sessions
 *   POST   /sessions/            — create + dispatch session
 *   GET    /sessions/<id>/       — session detail
 *   GET    /sessions/<id>/users/      — domain users
 *   GET    /sessions/<id>/groups/     — domain groups
 *   GET    /sessions/<id>/computers/  — domain computers
 *   GET    /sessions/<id>/findings/   — SPNs, ACLs, cert services, trusts */

WG.AD = WG.AD || {};
WG.AD._pollTimer = null;

/* ── Render ── */

WG.renderADRecon = function() {
  var esc = WG.escHtml;

  /* Kick off async data loads — they populate the DOM when they resolve. */
  WG.AD.loadProfiles();
  WG.AD.loadSessions();

  return '' +
    '<div class="page-header">' +
      '<div class="page-header-left"><h1>AD Recon</h1><p>Active Directory reconnaissance cockpit</p></div>' +
      '<div class="page-header-actions">' +
        '<button class="btn btn-primary" onclick="WG.AD.openSessionModal()"><span>+</span> New Session</button>' +
      '</div>' +
    '</div>' +

    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">' +

      /* ── Left column ── */
      '<div>' +

        /* Credential Profiles card */
        '<div class="panel" style="margin-bottom:20px;">' +
          '<div class="panel-header" style="display:flex;justify-content:space-between;align-items:center;">' +
            '<div><h2 style="margin:0;font-size:0.95rem;">Credential Profiles</h2>' +
            '<p style="margin:4px 0 0;font-size:0.72rem;color:var(--text-dim);">Passwords encrypted at rest (AES-256-GCM)</p></div>' +
            '<button class="btn btn-sm btn-primary" onclick="WG.AD.openProfileModal()">+ Add</button>' +
          '</div>' +
          '<div class="panel-body" id="adProfilesList"><div class="panel-empty">Loading...</div></div>' +
        '</div>' +

        /* Quick Unauth card */
        '<div class="panel">' +
          '<div class="panel-header"><h2 style="margin:0;font-size:0.95rem;">Quick Start &mdash; Unauthenticated</h2></div>' +
          '<div class="panel-body">' +
            '<div class="form-group"><label class="form-label">Domain</label>' +
            '<input class="form-input" id="adQuickDomain" placeholder="lab.local"></div>' +
            '<div class="form-group"><label class="form-label">DC IP Address</label>' +
            '<input class="form-input" id="adQuickDC" placeholder="10.0.0.1"></div>' +
            '<button class="btn btn-primary btn-block" onclick="WG.AD.startUnauth()">Run Unauth Recon</button>' +
          '</div>' +
        '</div>' +

      '</div>' +

      /* ── Right column ── */
      '<div class="panel">' +
        '<div class="panel-header"><h2 style="margin:0;font-size:0.95rem;">Session History</h2></div>' +
        '<div class="panel-body" id="adSessionList"><div class="panel-empty">Loading...</div></div>' +
      '</div>' +

    '</div>' +

    /* ── Profile editor modal ── */
    '<div class="modal-overlay" id="profileModal">' +
      '<div class="modal" style="width:480px;">' +
        '<div class="modal-header"><h2 id="profileModalTitle">New Profile</h2></div>' +
        '<div class="modal-body">' +
          '<input type="hidden" id="profEditId" value="">' +
          '<div class="form-group"><label class="form-label">Profile Name</label>' +
          '<input class="form-input" id="profName" placeholder="Production Lab"></div>' +
          '<div class="form-group"><label class="form-label">Domain</label>' +
          '<input class="form-input" id="profDomain" placeholder="lab.local"></div>' +
          '<div class="form-group"><label class="form-label">Username</label>' +
          '<input class="form-input" id="profUser" placeholder="DOMAIN\\Administrator"></div>' +
          '<div class="form-group"><label class="form-label">Password</label>' +
          '<input class="form-input" type="password" id="profPass" placeholder="Password (never returned by API)"></div>' +
          '<div class="form-group"><label class="form-label">NT Hash <span style="font-weight:400;color:var(--text-dim);">(optional)</span></label>' +
          '<input class="form-input" id="profNTHash" placeholder="aad3b435b51404ee..."></div>' +
        '</div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-secondary" onclick="WG.closeModal(\'profileModal\')">Cancel</button>' +
          '<button class="btn btn-primary" onclick="WG.AD.saveProfile()">Save</button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    /* ── New session modal ── */
    '<div class="modal-overlay" id="sessionModal">' +
      '<div class="modal" style="width:480px;">' +
        '<div class="modal-header"><h2>New AD Recon Session</h2></div>' +
        '<div class="modal-body">' +
          '<div class="form-group"><label class="form-label">Credential Profile</label>' +
          '<select class="form-select" id="sessProfile"><option value="">-- None (Unauthenticated) --</option></select></div>' +
          '<div class="form-group"><label class="form-label">Domain</label>' +
          '<input class="form-input" id="sessDomain" placeholder="lab.local"></div>' +
          '<div class="form-group"><label class="form-label">DC IP Address</label>' +
          '<input class="form-input" id="sessDC" placeholder="10.0.0.1"></div>' +
        '</div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-secondary" onclick="WG.closeModal(\'sessionModal\')">Cancel</button>' +
          '<button class="btn btn-primary" onclick="WG.AD.startSession()">Start Recon</button>' +
        '</div>' +
      '</div>' +
    '</div>' +

    /* ── Session detail modal ── */
    '<div class="modal-overlay" id="sessionDetailModal">' +
      '<div class="modal" style="width:720px;max-height:80vh;">' +
        '<div class="modal-header"><h2 id="sessDetailTitle">Session Detail</h2></div>' +
        '<div class="modal-body" id="sessDetailBody" style="max-height:55vh;overflow-y:auto;"></div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-secondary" onclick="WG.closeModal(\'sessionDetailModal\')">Close</button>' +
        '</div>' +
      '</div>' +
    '</div>';
};


/* ── Profile CRUD ── */

WG.AD.loadProfiles = function() {
  WG.fetchData('/ad-recon/profiles/').then(function(profiles) {
    var el = document.getElementById('adProfilesList');
    if (!el) return;
    if (!profiles || !profiles.length) {
      el.innerHTML = '<div class="panel-empty">No credential profiles yet.<br><small>Add one to run authenticated AD recon.</small></div>';
      return;
    }
    var esc = WG.escHtml;
    var html = '';
    profiles.forEach(function(p) {
      html += '' +
        '<div class="ad-profile-row" style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border-dim);">' +
          '<div style="flex:1;min-width:0;">' +
            '<div style="font-weight:600;color:var(--text-bright);font-size:0.85rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(p.name) + '</div>' +
            '<div style="font-size:0.72rem;color:var(--text-dim);">' + esc(p.domain) + ' / ' + esc(p.username) + '</div>' +
          '</div>' +
          '<div style="display:flex;gap:4px;flex-shrink:0;margin-left:8px;">' +
            '<button class="btn btn-xs btn-ghost" onclick="WG.AD.openProfileModal(\'' + p.id + '\')">Edit</button>' +
            '<button class="btn btn-xs btn-ghost" style="color:var(--critical);" onclick="WG.AD.deleteProfile(\'' + p.id + '\')">Del</button>' +
          '</div>' +
        '</div>';
    });
    el.innerHTML = html;
  });
};


WG.AD.openProfileModal = function(id) {
  document.getElementById('profEditId').value = '';
  document.getElementById('profName').value = '';
  document.getElementById('profDomain').value = '';
  document.getElementById('profUser').value = '';
  document.getElementById('profPass').value = '';
  document.getElementById('profNTHash').value = '';
  document.getElementById('profileModalTitle').textContent = 'New Profile';

  if (id) {
    WG.api('/ad-recon/profiles/' + id + '/').then(function(p) {
      if (!p) return;
      document.getElementById('profEditId').value = p.id;
      document.getElementById('profName').value = p.name;
      document.getElementById('profDomain').value = p.domain;
      document.getElementById('profUser').value = p.username;
      document.getElementById('profileModalTitle').textContent = 'Edit Profile';
    });
  }

  WG.openModal('profileModal');
};


WG.AD.saveProfile = function() {
  var id = document.getElementById('profEditId').value;
  var body = JSON.stringify({
    name: document.getElementById('profName').value.trim(),
    domain: document.getElementById('profDomain').value.trim(),
    username: document.getElementById('profUser').value.trim(),
    password: document.getElementById('profPass').value,
    nt_hash: document.getElementById('profNTHash').value.trim() || undefined,
  });

  var method = id ? 'PUT' : 'POST';
  var path = '/ad-recon/profiles/' + (id ? id + '/' : '');
  var opts = { method: method, body: body };

  WG.api(path, opts).then(function(data) {
    if (!data) return;
    WG.closeModal('profileModal');
    WG.AD.loadProfiles();
  });
};


WG.AD.deleteProfile = function(id) {
  if (!confirm('Delete this credential profile? This cannot be undone.')) return;
  WG.api('/ad-recon/profiles/' + id + '/', { method: 'DELETE' }).then(function() {
    WG.AD.loadProfiles();
  });
};


/* ── Session lifecycle ── */

WG.AD.loadSessions = function() {
  WG.fetchData('/ad-recon/sessions/').then(function(sessions) {
    var el = document.getElementById('adSessionList');
    if (!el) return;
    if (!sessions || !sessions.length) {
      el.innerHTML = '<div class="panel-empty">No sessions yet.<br><small>Start an unauth scan or use a credential profile.</small></div>';
      return;
    }
    var esc = WG.escHtml;
    var html = '<div style="overflow-x:auto;"><table class="data-table">' +
      '<thead><tr><th>Domain</th><th>DC</th><th>Scope</th><th>Status</th><th>Actions</th></tr></thead><tbody>';

    sessions.forEach(function(s) {
      var statusClass = s.status === 'complete' ? 'completed' : s.status === 'failed' ? 'cancelled' : s.status === 'running' ? 'info' : '';

      html += '<tr>' +
        '<td style="font-weight:600;">' + esc(s.domain) + '</td>' +
        '<td class="mono" style="font-size:0.78rem;">' + esc(s.dc_ip) + '</td>' +
        '<td><span class="tag" style="font-size:0.62rem;">' + esc(s.scope) + '</span></td>' +
        '<td><span class="status-badge ' + statusClass + '"><span class="dot"></span> ' + esc(s.status) + '</span></td>' +
        '<td>' +
          '<button class="btn btn-xs btn-ghost" onclick="WG.AD.viewSession(\'' + s.id + '\')">View</button>' +
          (s.status !== 'running' ? '<button class="btn btn-xs btn-ghost" onclick="WG.AD.rerunSession(\'' + s.id + '\')">Re-run</button>' : '') +
        '</td>' +
        '</tr>';

      /* Auto-poll running sessions */
      if (s.status === 'running' || s.status === 'pending') {
        WG.AD._startPolling(s.id);
      }
    });

    html += '</tbody></table></div>';
    el.innerHTML = html;
  });
};


WG.AD.openSessionModal = function() {
  /* Populate profile dropdown */
  WG.fetchData('/ad-recon/profiles/').then(function(profiles) {
    var sel = document.getElementById('sessProfile');
    sel.innerHTML = '<option value="">-- None (Unauthenticated) --</option>';
    if (profiles) {
      profiles.forEach(function(p) {
        sel.insertAdjacentHTML('beforeend', '<option value="' + p.id + '">' + WG.escHtml(p.name) + ' (' + WG.escHtml(p.domain) + ')</option>');
      });
    }
  });

  document.getElementById('sessDomain').value = '';
  document.getElementById('sessDC').value = '';
  WG.openModal('sessionModal');
};


WG.AD.startSession = function() {
  var profileId = document.getElementById('sessProfile').value;
  var domain = document.getElementById('sessDomain').value.trim();
  var dc = document.getElementById('sessDC').value.trim();

  if (!domain || !dc) {
    alert('Domain and DC IP are required.');
    return;
  }

  var body = JSON.stringify({
    scope: profileId ? 'authenticated' : 'unauth',
    domain: domain,
    dc_ip: dc,
    profile: profileId || undefined,
  });

  WG.api('/ad-recon/sessions/', { method: 'POST', body: body }).then(function(s) {
    if (!s) return;
    WG.closeModal('sessionModal');
    WG.AD.loadSessions();
    WG.AD._startPolling(s.id);
  });
};


WG.AD.startUnauth = function() {
  var domain = document.getElementById('adQuickDomain').value.trim();
  var dc = document.getElementById('adQuickDC').value.trim();

  if (!domain || !dc) {
    alert('Domain and DC IP are required.');
    return;
  }

  var body = JSON.stringify({ scope: 'unauth', domain: domain, dc_ip: dc });

  WG.api('/ad-recon/sessions/', { method: 'POST', body: body }).then(function(s) {
    if (!s) return;
    WG.AD.loadSessions();
    WG.AD._startPolling(s.id);
  });
};


WG.AD._startPolling = function(sessionId) {
  if (WG.AD._pollTimer) clearInterval(WG.AD._pollTimer);
  WG.AD._pollTimer = setInterval(function() {
    WG.api('/ad-recon/sessions/' + sessionId + '/').then(function(s) {
      if (!s) { clearInterval(WG.AD._pollTimer); WG.AD._pollTimer = null; return; }
      if (s.status === 'complete' || s.status === 'failed') {
        clearInterval(WG.AD._pollTimer);
        WG.AD._pollTimer = null;
      }
      WG.AD.loadSessions();
    });
  }, 3000);
};


WG.AD.rerunSession = function(id) {
  WG.api('/ad-recon/sessions/' + id + '/').then(function(s) {
    if (!s) return;
    var body = JSON.stringify({
      scope: s.scope, domain: s.domain, dc_ip: s.dc_ip,
      profile: s.profile || undefined,
    });
    WG.api('/ad-recon/sessions/', { method: 'POST', body: body }).then(function(newS) {
      if (!newS) return;
      WG.AD.loadSessions();
      WG.AD._startPolling(newS.id);
    });
  });
};


/* ── Session detail view ── */

WG.AD.viewSession = function(id) {
  WG.api('/ad-recon/sessions/' + id + '/').then(function(s) {
    if (!s) return;
    var esc = WG.escHtml;

    /* Build tool status table */
    var toolRows = '';
    var statuses = s.tool_status || {};
    Object.keys(statuses).forEach(function(name) {
      var ts = statuses[name];
      var ok = ts.status === 'ok';
      toolRows += '<tr><td class="mono" style="font-size:0.75rem;">' + esc(name) + '</td>' +
        '<td><span class="status-badge ' + (ok ? 'completed' : 'cancelled') + '"><span class="dot"></span> ' + esc(ts.status) + '</span></td>' +
        '</tr>';
    });

    document.getElementById('sessDetailTitle').textContent = 'Session: ' + s.domain + ' (' + esc(s.scope) + ')';
    document.getElementById('sessDetailBody').innerHTML = '' +
      '<div class="info-grid" style="margin-bottom:16px;">' +
        '<div class="info-item"><div class="info-label">Status</div><div class="info-value"><span class="status-badge ' + (s.status === 'complete' ? 'completed' : s.status === 'failed' ? 'cancelled' : 'info') + '"><span class="dot"></span> ' + esc(s.status) + '</span></div></div>' +
        '<div class="info-item"><div class="info-label">DC IP</div><div class="info-value mono">' + esc(s.dc_ip) + '</div></div>' +
        '<div class="info-item"><div class="info-label">Scope</div><div class="info-value">' + esc(s.scope) + '</div></div>' +
        '<div class="info-item"><div class="info-label">Profile</div><div class="info-value">' + esc(s.profile_name || 'N/A') + '</div></div>' +
        (s.error ? '<div class="info-item" style="grid-column:1/-1;"><div class="info-label">Error</div><div class="info-value" style="color:var(--critical);">' + esc(s.error) + '</div></div>' : '') +
      '</div>' +

      (toolRows ? '<h3 style="font-size:0.85rem;margin-bottom:8px;">Tool Status</h3>' +
      '<div style="overflow-x:auto;"><table class="data-table"><thead><tr><th>Tool</th><th>Result</th></tr></thead><tbody>' + toolRows + '</tbody></table></div>' : '') +

      /* Load detailed findings */
      '<div id="sessFindings" style="margin-top:16px;"><div class="panel-empty">Loading findings...</div></div>';

    WG.openModal('sessionDetailModal');

    /* Fetch findings from the nested endpoint */
    WG.api('/ad-recon/sessions/' + id + '/findings/').then(function(f) {
      var fel = document.getElementById('sessFindings');
      if (!fel || !f) { if (fel) fel.innerHTML = ''; return; }

      var html = '';
      function section(title, items, fields) {
        if (!items || !items.length) return '';
        var h = '<h3 style="font-size:0.82rem;margin:12px 0 6px;color:var(--text-bright);">' + esc(title) + ' (' + items.length + ')</h3>' +
          '<div style="overflow-x:auto;"><table class="data-table" style="font-size:0.72rem;"><thead><tr>';
        fields.forEach(function(fld) { h += '<th>' + esc(fld) + '</th>'; });
        h += '</tr></thead><tbody>';
        items.forEach(function(item) {
          h += '<tr>';
          fields.forEach(function(fld) { h += '<td>' + esc(String(item[fld] || '')) + '</td>'; });
          h += '</tr>';
        });
        h += '</tbody></table></div>';
        return h;
      }

      html += section('SPNs', f.spns, ['service_name', 'sam_account_name', 'host', 'category']);
      html += section('Interesting ACLs', f.acls, ['identity', 'active_directory_rights', 'object_dn']);
      html += section('Certificate Services', f.cert_services, ['ca_name', 'host', 'vulnerable_template']);
      html += section('Domain Trusts', f.trusts, ['source_domain', 'target_domain', 'direction', 'trust_type']);

      fel.innerHTML = html || '<div class="panel-empty">No findings available.</div>';
    });
  });
};
