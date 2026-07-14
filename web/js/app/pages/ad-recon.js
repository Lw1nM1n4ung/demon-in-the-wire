/* Wire_Ghost — AD Recon Cockpit.
 *
 * Three-panel layout:
 *   Left:  Credential profiles list + Quick Unauth form
 *   Right: Session history table with status polling
 *
 * Session detail (/ad-recon/<id>): full-page view with tabs:
 *   Overview, AD Tree, Users, Computers, Groups */

WG.AD = WG.AD || {};
WG.AD._pollTimer = null;

/* ── Render ── */

WG.renderADRecon = function() {
  var esc = WG.escHtml;

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

      '<div>' +
        '<div class="panel" style="margin-bottom:20px;">' +
          '<div class="panel-header" style="display:flex;justify-content:space-between;align-items:center;">' +
            '<div><h2 style="margin:0;font-size:0.95rem;">Credential Profiles</h2>' +
            '<p style="margin:4px 0 0;font-size:0.72rem;color:var(--text-dim);">Passwords encrypted at rest (AES-256-GCM)</p></div>' +
            '<button class="btn btn-sm btn-primary" onclick="WG.AD.openProfileModal()">+ Add</button>' +
          '</div>' +
          '<div class="panel-body" id="adProfilesList"><div class="panel-empty">Loading...</div></div>' +
        '</div>' +

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

      '<div class="panel">' +
        '<div class="panel-header"><h2 style="margin:0;font-size:0.95rem;">Session History</h2></div>' +
        '<div class="panel-body" id="adSessionList"><div class="panel-empty">Loading...</div></div>' +
      '</div>' +

    '</div>' +

    /* Profile editor modal */
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

    /* New session modal */
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
        '<td style="font-weight:600;"><a href="javascript:void(0)" onclick="WG.navigate(\'ad-recon-session\',{id:\'' + s.id + '\'})" style="color:var(--accent);text-decoration:none;">' + esc(s.domain) + '</a></td>' +
        '<td class="mono" style="font-size:0.78rem;">' + esc(s.dc_ip) + '</td>' +
        '<td><span class="tag" style="font-size:0.62rem;">' + esc(s.scope) + '</span></td>' +
        '<td><span class="status-badge ' + statusClass + '"><span class="dot"></span> ' + esc(s.status) + '</span></td>' +
        '<td>' +
          '<a href="javascript:void(0)" onclick="WG.navigate(\'ad-recon-session\',{id:\'' + s.id + '\'})" class="btn btn-xs btn-ghost">View</a>' +
          (s.status !== 'running' ? '<button class="btn btn-xs btn-ghost" onclick="WG.AD.rerunSession(\'' + s.id + '\')">Re-run</button>' : '') +
        '</td>' +
        '</tr>';

      if (s.status === 'running' || s.status === 'pending') {
        WG.AD._startPolling(s.id);
      }
    });

    html += '</tbody></table></div>';
    el.innerHTML = html;
  });
};


WG.AD.openSessionModal = function() {
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
      /* Refresh detail page if viewing this session */
      var detailEl = document.getElementById('adDetailPage');
      if (detailEl && detailEl.dataset.sessionId === sessionId) {
        WG.AD._refreshDetailTabs(s);
      }
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


/* ── Session Detail Page (full-page with tabs) ── */

WG.AD.renderSessionDetail = function(id) {
  WG.api('/ad-recon/sessions/' + id + '/').then(function(s) {
    if (!s) {
      document.getElementById('mainContent').innerHTML = '<div class="panel-empty">Session not found. <a href="javascript:void(0)" onclick="WG.navigate(\'ad-recon\')">Back to AD Recon</a></div>';
      return;
    }

    var esc = WG.escHtml;
    var statusClass = s.status === 'complete' ? 'completed' : s.status === 'failed' ? 'cancelled' : s.status === 'running' ? 'info' : '';

    /* Tool status rows */
    var toolRows = '';
    var statuses = s.tool_status || {};
    Object.keys(statuses).forEach(function(name) {
      var ts = statuses[name];
      var ok = ts.status === 'ok';
      toolRows += '<tr><td class="mono" style="font-size:0.75rem;">' + esc(name) + '</td>' +
        '<td><span class="status-badge ' + (ok ? 'completed' : 'cancelled') + '"><span class="dot"></span> ' + esc(ts.status) + '</span></td>' +
        '</tr>';
    });

    var html = '' +
      '<div class="page-header">' +
        '<div class="page-header-left">' +
          '<a href="javascript:void(0)" onclick="WG.navigate(\'ad-recon\')" style="color:var(--text-dim);font-size:0.8rem;text-decoration:none;">&larr; Back to AD Recon</a>' +
          '<h1>' + esc(s.domain) + ' <span class="tag" style="font-size:0.65rem;vertical-align:middle;">' + esc(s.scope) + '</span></h1>' +
          '<p style="margin:0;">DC: <span class="mono">' + esc(s.dc_ip) + '</span> &middot; Status: <span class="status-badge ' + statusClass + '"><span class="dot"></span> ' + esc(s.status) + '</span></p>' +
        '</div>' +
        '<div class="page-header-actions">' +
          (s.status !== 'running' ? '<button class="btn btn-primary" onclick="WG.AD.rerunSession(\'' + s.id + '\')">Re-run</button>' : '') +
        '</div>' +
      '</div>' +

      '<div class="tabs" style="margin-bottom:16px;" id="adDetailTabs">' +
        '<button class="tab active" data-tab="overview" onclick="WG.AD._switchTab(\'' + s.id + '\',\'overview\')">Overview</button>' +
        '<button class="tab" data-tab="tree" onclick="WG.AD._switchTab(\'' + s.id + '\',\'tree\')">AD Tree</button>' +
        '<button class="tab" data-tab="users" onclick="WG.AD._switchTab(\'' + s.id + '\',\'users\')">Users</button>' +
        '<button class="tab" data-tab="computers" onclick="WG.AD._switchTab(\'' + s.id + '\',\'computers\')">Computers</button>' +
        '<button class="tab" data-tab="groups" onclick="WG.AD._switchTab(\'' + s.id + '\',\'groups\')">Groups</button>' +
      '</div>' +

      '<div id="adDetailPage" data-session-id="' + s.id + '" data-session-status="' + s.status + '">' +
        /* Overview tab (default) */
        '<div id="adTab-overview" class="ad-tab-content">' +
          (s.error ? '<div class="panel" style="border-left:3px solid var(--critical);margin-bottom:16px;"><div class="panel-body" style="color:var(--critical);">' + esc(s.error) + '</div></div>' : '') +

          '<div class="panel" style="margin-bottom:16px;">' +
            '<div class="panel-header"><h3 style="margin:0;font-size:0.85rem;">Session Info</h3></div>' +
            '<div class="panel-body">' +
              '<div class="info-grid">' +
                '<div class="info-item"><div class="info-label">Domain</div><div class="info-value">' + esc(s.domain) + '</div></div>' +
                '<div class="info-item"><div class="info-label">DC IP</div><div class="info-value mono">' + esc(s.dc_ip) + '</div></div>' +
                '<div class="info-item"><div class="info-label">Scope</div><div class="info-value">' + esc(s.scope) + '</div></div>' +
                '<div class="info-item"><div class="info-label">Profile</div><div class="info-value">' + esc(s.profile_name || 'N/A') + '</div></div>' +
                '<div class="info-item"><div class="info-label">Created</div><div class="info-value">' + esc(s.created_at || '') + '</div></div>' +
                (s.completed_at ? '<div class="info-item"><div class="info-label">Completed</div><div class="info-value">' + esc(s.completed_at) + '</div></div>' : '') +
              '</div>' +
            '</div>' +
          '</div>' +

          (toolRows ? '<div class="panel" style="margin-bottom:16px;">' +
            '<div class="panel-header"><h3 style="margin:0;font-size:0.85rem;">Tool Status</h3></div>' +
            '<div class="panel-body"><div style="overflow-x:auto;"><table class="data-table"><thead><tr><th>Tool</th><th>Result</th></tr></thead><tbody>' + toolRows + '</tbody></table></div></div>' +
          '</div>' : '') +

          '<div class="panel">' +
            '<div class="panel-header"><h3 style="margin:0;font-size:0.85rem;">Findings</h3></div>' +
            '<div class="panel-body" id="sessOverviewFindings"><div class="panel-empty">Loading...</div></div>' +
          '</div>' +
        '</div>' +

        /* AD Tree tab */
        '<div id="adTab-tree" class="ad-tab-content" style="display:none;"><div class="panel"><div class="panel-body" id="adTreeContainer"><div class="panel-empty">Loading tree...</div></div></div></div>' +

        /* Users tab */
        '<div id="adTab-users" class="ad-tab-content" style="display:none;"><div class="panel"><div class="panel-body" id="adUsersContainer"><div class="panel-empty">Loading users...</div></div></div></div>' +

        /* Computers tab */
        '<div id="adTab-computers" class="ad-tab-content" style="display:none;"><div class="panel"><div class="panel-body" id="adComputersContainer"><div class="panel-empty">Loading computers...</div></div></div></div>' +

        /* Groups tab */
        '<div id="adTab-groups" class="ad-tab-content" style="display:none;"><div class="panel"><div class="panel-body" id="adGroupsContainer"><div class="panel-empty">Loading groups...</div></div></div></div>' +
      '</div>';

    return html;
  });
};


WG.AD._switchTab = function(sessionId, tabName) {
  /* Update tab button active states */
  document.querySelectorAll('#adDetailTabs .tab').forEach(function(btn) {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });

  /* Show/hide tab content */
  document.querySelectorAll('#adDetailPage .ad-tab-content').forEach(function(el) {
    el.style.display = 'none';
  });
  var target = document.getElementById('adTab-' + tabName);
  if (target) target.style.display = '';

  /* Lazy-load tab content */
  switch (tabName) {
    case 'overview':
      WG.AD._loadOverviewFindings(sessionId);
      break;
    case 'tree':
      WG.AD._loadTree(sessionId);
      break;
    case 'users':
      WG.AD._loadDataTable(sessionId, 'users', 'adUsersContainer', ['sam_account_name', 'upn', 'display_name', 'dn'], ['SAM', 'UPN', 'Display Name', 'DN']);
      break;
    case 'computers':
      WG.AD._loadDataTable(sessionId, 'computers', 'adComputersContainer', ['name', 'dns_hostname', 'os', 'os_version', 'dn'], ['Name', 'DNS Hostname', 'OS', 'Version', 'DN']);
      break;
    case 'groups':
      WG.AD._loadDataTable(sessionId, 'groups', 'adGroupsContainer', ['name', 'sam_account_name', 'member_count', 'dn'], ['Name', 'SAM', 'Members', 'DN']);
      break;
  }
};


WG.AD._refreshDetailTabs = function(s) {
  /* Update status badge */
  var detailEl = document.getElementById('adDetailPage');
  if (!detailEl) return;

  var oldStatus = detailEl.dataset.sessionStatus;
  if (oldStatus !== s.status) {
    detailEl.dataset.sessionStatus = s.status;
    /* Refresh current tab */
    var activeTab = document.querySelector('#adDetailTabs .tab.active');
    if (activeTab) {
      WG.AD._switchTab(detailEl.dataset.sessionId, activeTab.dataset.tab);
    }
  }
};


/* ── Overview: Findings ── */

WG.AD._loadOverviewFindings = function(sessionId) {
  var el = document.getElementById('sessOverviewFindings');
  if (!el || el.dataset.loaded) return;
  el.dataset.loaded = '1';

  WG.api('/ad-recon/sessions/' + sessionId + '/findings/').then(function(f) {
    if (!f) { el.innerHTML = '<div class="panel-empty">No findings.</div>'; return; }
    var esc = WG.escHtml;

    function section(title, items, fields) {
      if (!items || !items.length) return '';
      var h = '<h4 style="font-size:0.78rem;margin:12px 0 6px;color:var(--text-bright);">' + esc(title) + ' (' + items.length + ')</h4>' +
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

    var html = '';
    html += section('SPNs', f.spns, ['service_name', 'sam_account_name', 'host', 'category']);
    html += section('Interesting ACLs', f.acls, ['identity', 'active_directory_rights', 'object_dn']);
    html += section('Certificate Services', f.cert_services, ['ca_name', 'host', 'vulnerable_template']);
    html += section('Domain Trusts', f.trusts, ['source_domain', 'target_domain', 'direction', 'trust_type']);
    html += section('Shares', f.shares, ['name', 'path', 'access']);

    el.innerHTML = html || '<div class="panel-empty">No findings available.</div>';
  });
};


/* ── AD Tree Visualization ── */

WG.AD._loadTree = function(sessionId) {
  var el = document.getElementById('adTreeContainer');
  if (!el || el.dataset.loaded) return;
  el.dataset.loaded = '1';

  WG.api('/ad-recon/sessions/' + sessionId + '/tree/').then(function(tree) {
    if (!tree) { el.innerHTML = '<div class="panel-empty">No tree data available.</div>'; return; }
    el.innerHTML = WG.AD._renderTree(tree);
    WG.AD._initTreeInteractions();
  });
};


WG.AD._renderTree = function(node, level) {
  level = level || 0;
  var esc = WG.escHtml;

  var typeColors = {
    domain: 'var(--accent)',
    ou: '#22c55e',
    container: '#94a3b8',
    user: '#f59e0b',
    computer: '#8b5cf6',
    group: '#3b82f6'
  };
  var typeIcons = {
    domain: '\u{1F310}',
    ou: '\u{1F4C2}',
    container: '\u{1F4C1}',
    user: '\u{1F464}',
    computer: '\u{1F5A5}',
    group: '\u{1F465}'
  };

  var color = typeColors[node.type] || 'var(--text-dim)';
  var icon = typeIcons[node.type] || '';

  var hasChildren = node.children && node.children.length > 0;
  var isLeaf = node.type !== 'domain' && node.type !== 'ou' && node.type !== 'container';

  var countsHtml = '';
  if (node.counts && (node.counts.users || node.counts.computers || node.counts.groups)) {
    var parts = [];
    if (node.counts.users) parts.push(node.counts.users + ' users');
    if (node.counts.computers) parts.push(node.counts.computers + ' computers');
    if (node.counts.groups) parts.push(node.counts.groups + ' groups');
    countsHtml = ' <span style="font-size:0.65rem;color:var(--text-dim);">(' + parts.join(', ') + ')</span>';
  }

  var html = '<div class="tree-node" style="margin-left:' + (level * 24) + 'px;">';

  if (hasChildren) {
    html += '<span class="tree-toggle" onclick="WG.AD._toggleTreeNode(this)" style="cursor:pointer;user-select:none;display:inline-block;width:18px;">\u25BC</span>';
  } else {
    html += '<span style="display:inline-block;width:18px;"></span>';
  }

  html += '<span style="color:' + color + ';font-weight:' + (level === 0 ? '700' : '500') + ';font-size:' + (level === 0 ? '0.9rem' : (0.82 - level * 0.02) + 'rem') + ';">';
  html += icon + ' ' + esc(node.label);
  html += '</span>';

  if (!isLeaf) {
    html += countsHtml;
  }

  html += '</div>';

  if (hasChildren) {
    html += '<div class="tree-children">';
    node.children.forEach(function(child) {
      html += WG.AD._renderTree(child, level + 1);
    });
    html += '</div>';
  }

  return html;
};


WG.AD._initTreeInteractions = function() {
  /* Tree nodes are already rendered with onclick handlers */
};


WG.AD._toggleTreeNode = function(toggleEl) {
  var children = toggleEl.parentElement.nextElementSibling;
  if (!children || !children.classList.contains('tree-children')) return;

  var isOpen = children.style.display !== 'none';
  if (isOpen) {
    children.style.display = 'none';
    toggleEl.textContent = '\u25B6';
  } else {
    children.style.display = '';
    toggleEl.textContent = '\u25BC';
  }
};


/* ── Data Tables ── */

WG.AD._loadDataTable = function(sessionId, endpoint, containerId, fields, headers) {
  var el = document.getElementById(containerId);
  if (!el || el.dataset.loaded) return;
  el.dataset.loaded = '1';

  var esc = WG.escHtml;

  WG.api('/ad-recon/sessions/' + sessionId + '/' + endpoint + '/?page_size=500').then(function(data) {
    if (!data || !data.results || !data.results.length) {
      el.innerHTML = '<div class="panel-empty">No ' + endpoint + ' found.</div>';
      return;
    }

    var items = data.results;
    var total = data.count || items.length;

    /* Search box */
    var html = '<div style="margin-bottom:8px;">' +
      '<input class="form-input" id="adSearch-' + endpoint + '" placeholder="Search ' + total + ' ' + endpoint + '..." ' +
      'oninput="WG.AD._filterTable(\'adTable-' + endpoint + '\', this.value)" style="max-width:300px;">' +
      '</div>';

    html += '<div style="overflow-x:auto;"><table class="data-table" id="adTable-' + endpoint + '" style="font-size:0.75rem;">';
    html += '<thead><tr>';
    headers.forEach(function(h) { html += '<th>' + esc(h) + '</th>'; });
    html += '</tr></thead><tbody>';

    items.forEach(function(item) {
      html += '<tr>';
      fields.forEach(function(fld) {
        var val = item[fld];
        if (fld === 'dn' && val) {
          /* Truncate DN for display */
          var display = val.length > 80 ? val.substring(0, 77) + '...' : val;
          html += '<td title="' + esc(val) + '" style="font-size:0.68rem;color:var(--text-dim);">' + esc(display) + '</td>';
        } else {
          html += '<td>' + esc(String(val || '')) + '</td>';
        }
      });
      html += '</tr>';
    });

    html += '</tbody></table></div>';

    if (total > items.length) {
      html += '<div style="text-align:center;padding:8px;color:var(--text-dim);font-size:0.75rem;">Showing ' + items.length + ' of ' + total + ' ' + endpoint + '</div>';
    }

    el.innerHTML = html;
  });
};


WG.AD._filterTable = function(tableId, query) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = table.querySelectorAll('tbody tr');
  var q = query.toLowerCase();
  rows.forEach(function(row) {
    var text = row.textContent.toLowerCase();
    row.style.display = q === '' || text.indexOf(q) !== -1 ? '' : 'none';
  });
};
