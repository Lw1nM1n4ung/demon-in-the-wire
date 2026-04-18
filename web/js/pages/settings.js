/* Wire_Ghost — Settings page (full) */

WG.renderSettings = function() {
  var user = WG.currentUser && WG.currentUser();
  var isAdmin = user && user.role === 'owner';
  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Settings</h1><p>Portal configuration & preferences</p></div></div>' +
    '<div class="tabs" id="settingsTabs" style="flex-wrap:wrap;">' +
      '<div class="tab active" data-tab="general" onclick="WG.switchSettingsTab(\'general\')">General</div>' +
      '<div class="tab" data-tab="theme" onclick="WG.switchSettingsTab(\'theme\')">Theme</div>' +
      '<div class="tab" data-tab="notifications" onclick="WG.switchSettingsTab(\'notifications\')">Notifications</div>' +
      '<div class="tab" data-tab="tools" onclick="WG.switchSettingsTab(\'tools\')">Tools</div>' +
      '<div class="tab" data-tab="sessions" onclick="WG.switchSettingsTab(\'sessions\')">Sessions</div>' +
      '<div class="tab" data-tab="audit" onclick="WG.switchSettingsTab(\'audit\')">Audit Log</div>' +
      '<div class="tab" data-tab="export" onclick="WG.switchSettingsTab(\'export\')">Export/Import</div>' +
      '<div class="tab" data-tab="api" onclick="WG.switchSettingsTab(\'api\')">API</div>' +
      (isAdmin ? '<div class="tab" data-tab="admin" onclick="WG.switchSettingsTab(\'admin\')">Administration</div>' : '') +
      (isAdmin ? '<div class="tab" data-tab="support" onclick="WG.switchSettingsTab(\'support\')">Support</div>' : '') +
      '<div class="tab" data-tab="about" onclick="WG.switchSettingsTab(\'about\')">About</div>' +
    '</div>' +
    '<div id="settingsTabContent">' + WG._settingsGeneral() + '</div>';
};

/* ── General ── */
WG._settingsGeneral = function() {
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">General Settings</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:18px;">' +
      '<div class="form-group"><label class="form-label">API Base URL</label><input class="form-input" value="' + WG.API_BASE + '"></div>' +
      '<div class="form-group"><label class="form-label">Default Output Directory</label><input class="form-input" value="/root/output"></div>' +
      '<div class="form-group"><label class="form-label">Default Parallelism</label><input class="form-input" type="number" value="10"></div>' +
      '<div class="form-group"><label class="form-label">Default Timeout (seconds)</label><input class="form-input" type="number" value="3600"></div>' +
      '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on"></div><span class="toggle-label">Auto-generate reports on scan completion</span></div>' +
      '<div><button class="btn btn-primary" onclick="WG.toast(\'Settings saved\',\'success\')">Save Settings</button></div>' +
    '</div></div>';
};

/* ── Theme ── */
WG._settingsTheme = function() {
  var prefs = WG.getThemePrefs();
  var mode = prefs.mode || 'dark';
  var accent = prefs.accent || 'blue';
  var fontSize = prefs.fontSize || 'default';
  var colors = Object.keys(WG.ACCENT_COLORS);
  var sizes = Object.keys(WG.FONT_SIZES);

  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">Appearance</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:24px;">' +

      '<div><div class="form-label" style="margin-bottom:10px;">Mode</div>' +
      '<div style="display:flex;gap:10px;">' +
        '<div onclick="WG.setThemeMode(\'dark\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'dark' ? 'var(--accent)' : 'var(--border-soft)') + ';background:#0a0e17;text-align:center;transition:all 0.2s;">' +
          '<div style="font-size:1.2rem;margin-bottom:4px;">&#9790;</div>' +
          '<div style="font-weight:700;color:#e8ecf4;font-size:0.85rem;">Dark</div>' +
          '<div style="font-size:0.68rem;color:#5a6478;margin-top:2px;">Tactical ops</div>' +
        '</div>' +
        '<div onclick="WG.setThemeMode(\'light\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'light' ? 'var(--accent)' : 'var(--border-soft)') + ';background:#f0f2f5;text-align:center;transition:all 0.2s;">' +
          '<div style="font-size:1.2rem;margin-bottom:4px;">&#9788;</div>' +
          '<div style="font-weight:700;color:#1a1d23;font-size:0.85rem;">Light</div>' +
          '<div style="font-size:0.68rem;color:#8892a4;margin-top:2px;">Clean daylight</div>' +
        '</div>' +
        '<div onclick="WG.setThemeMode(\'cyberpunk\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'cyberpunk' ? '#ff2d95' : 'var(--border-soft)') + ';background:#0a0012;text-align:center;transition:all 0.2s;">' +
          '<div style="font-size:1.2rem;margin-bottom:4px;">&#9889;</div>' +
          '<div style="font-weight:700;color:#ff2d95;font-size:0.85rem;text-shadow:0 0 8px rgba(255,45,149,0.5);">Cyberpunk</div>' +
          '<div style="font-size:0.68rem;color:#7b5ea0;margin-top:2px;">Neon overdrive</div>' +
        '</div>' +
      '</div></div>' +

      '<div><div class="form-label" style="margin-bottom:10px;">Accent Color</div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
        colors.map(function(c) {
          var cv = WG.ACCENT_COLORS[c]['--accent'];
          return '<div onclick="WG.setAccentColor(\'' + c + '\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;width:40px;height:40px;border-radius:10px;background:' + cv + ';border:3px solid ' + (accent === c ? 'var(--text-bright)' : 'transparent') + ';display:flex;align-items:center;justify-content:center;transition:all 0.15s;">' +
            (accent === c ? '<span style="color:white;font-weight:700;">&#10003;</span>' : '') +
          '</div>';
        }).join('') +
      '</div></div>' +

      '<div><div class="form-label" style="margin-bottom:10px;">Font Size</div>' +
      '<div style="display:flex;gap:8px;">' +
        sizes.map(function(s) {
          return '<button class="btn ' + (fontSize === s ? 'btn-primary' : 'btn-secondary') + ' btn-sm" onclick="WG.setFontSize(\'' + s + '\');WG.switchSettingsTab(\'theme\')">' + s.charAt(0).toUpperCase() + s.slice(1) + '</button>';
        }).join('') +
      '</div></div>' +

    '</div></div>';
};

/* ── Notifications ── */
WG._settingsNotifications = function() {
  var prefs = WG.getNotifPrefs();
  function tog(key, label) {
    return '<div class="form-toggle" onclick="WG._toggleNotif(this,\'' + key + '\')">' +
      '<div class="toggle-track' + (prefs[key] ? ' on' : '') + '"></div>' +
      '<span class="toggle-label">' + label + '</span></div>';
  }
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">Notification Preferences</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:14px;">' +
      tog('scanComplete', 'Scan completed') +
      tog('scanFailed', 'Scan failed') +
      tog('criticalFinding', 'Critical vulnerability discovered') +
      tog('reportReady', 'Report ready for download') +
      tog('weeklyDigest', 'Weekly summary digest') +
      '<div style="border-top:1px solid var(--border-dim);padding-top:14px;margin-top:4px;">' +
        tog('email', 'Send email notifications') +
      '</div>' +
    '</div></div>';
};

WG._toggleNotif = function(el, key) {
  var track = el.querySelector('.toggle-track');
  track.classList.toggle('on');
  var prefs = WG.getNotifPrefs();
  prefs[key] = track.classList.contains('on');
  WG.saveNotifPrefs(prefs);
};

/* ── Tools ── */
WG._settingsTools = function() {
  var tools = [
    { name: 'Nmap', desc: 'Port scanning & service detection', ok: true, path: '/usr/bin/nmap' },
    { name: 'Nuclei', desc: 'Template-based vulnerability scanner', ok: true, path: '/usr/bin/nuclei' },
    { name: 'Dirsearch', desc: 'Web directory brute-forcing', ok: true, path: '/usr/bin/dirsearch' },
    { name: 'Searchsploit', desc: 'Exploit database search', ok: true, path: '/usr/bin/searchsploit' },
    { name: 'WPScan', desc: 'WordPress vulnerability scanner', ok: true, path: '/usr/bin/wpscan' },
    { name: 'httpx', desc: 'HTTP probe & tech detection', ok: true, path: '/usr/bin/httpx' },
    { name: 'fping', desc: 'Host discovery via ICMP', ok: true, path: '/usr/bin/fping' },
    { name: 'OpenVAS', desc: 'Full vulnerability assessment', ok: false, path: '' },
  ];
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">External Tools</div></div>' +
    '<table class="data-table"><thead><tr><th>Tool</th><th>Description</th><th>Path</th><th>Status</th></tr></thead><tbody>' +
    tools.map(function(t) {
      return '<tr><td style="font-weight:600;color:var(--text-bright);">' + t.name + '</td>' +
        '<td style="color:var(--text-dim);font-size:0.78rem;">' + t.desc + '</td>' +
        '<td class="mono" style="font-size:0.72rem;">' + (t.path || '\u2014') + '</td>' +
        '<td>' + (t.ok ? '<span class="status-badge completed" style="font-size:0.65rem;"><span class="dot"></span> Found</span>' : '<span class="status-badge failed" style="font-size:0.65rem;"><span class="dot"></span> Missing</span>') + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

/* ── Sessions (API-driven) ── */
WG._settingsSessions = function() {
  var sessions = WG.getCached('sessions', '/sessions/');
  WG.fetchData('/sessions/', 'sessions').then(function(data) {
    if (data && WG.state.currentPage === 'settings') {
      WG._cache['sessions'] = data; WG._cacheTime['sessions'] = Date.now();
    }
  });
  return '<div class="panel" style="max-width:800px;"><div class="panel-header"><div class="panel-title">Active Sessions <span class="count">' + sessions.length + '</span></div>' +
    '<button class="btn btn-danger btn-sm" onclick="WG._logoutAll()">Logout All Others</button></div>' +
    (sessions.length ?
      '<table class="data-table"><thead><tr><th>Session</th><th>Status</th><th>Expires</th><th></th></tr></thead><tbody>' +
      sessions.map(function(s) {
        return '<tr>' +
          '<td class="mono" style="font-size:0.78rem;">' + WG.escHtml(s.id || 'unknown') + (s.current ? ' <span class="tag" style="font-size:0.6rem;background:var(--accent-dim);color:var(--accent);border-color:var(--border-active);">Current</span>' : '') + '</td>' +
          '<td><span class="status-badge completed" style="font-size:0.65rem;"><span class="dot"></span> Active</span></td>' +
          '<td class="mono">' + (s.expires ? WG.fmtDate(s.expires) : '\u2014') + '</td>' +
          '<td>' + (!s.current ? '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG._revokeSession(\'' + WG.escHtml(s.session_key) + '\')">Revoke</button>' : '') + '</td></tr>';
      }).join('') +
      '</tbody></table>'
    : '<div class="panel-empty"><div class="icon">&#128274;</div>No active sessions found.</div>') +
    '</div>';
};

WG._revokeSession = function(sessionKey) {
  WG.api('/sessions/revoke/', { method: 'POST', body: JSON.stringify({ session_key: sessionKey }) }).then(function(res) {
    if (res && !res.error) { WG.toast('Session revoked', 'info'); WG.invalidateCache('sessions'); WG.switchSettingsTab('sessions'); }
    else WG.toast((res && res.error) || 'Revoke failed', 'error');
  });
};

WG._logoutAll = function() {
  WG.api('/sessions/revoke-all/', { method: 'POST' }).then(function(res) {
    if (res) { WG.toast('Revoked ' + (res.revoked || 0) + ' sessions', 'success'); WG.invalidateCache('sessions'); WG.switchSettingsTab('sessions'); }
  });
};

/* ── Audit Log (API-driven) ── */
WG._settingsAudit = function() {
  var log = WG.getCached('audit_log', '/audit-log/');
  WG.fetchData('/audit-log/', 'audit_log').then(function(data) {
    if (data && WG.state.currentPage === 'settings') {
      WG._cache['audit_log'] = data; WG._cacheTime['audit_log'] = Date.now();
    }
  });
  var esc = WG.escHtml;
  var typeIcons = { auth: '&#128274;', scan: '&#8862;', report: '&#128196;', admin: '&#9881;' };
  var typeColors = { auth: 'var(--accent)', scan: 'var(--success)', report: 'var(--low)', admin: 'var(--medium)' };
  return '<div class="panel" style="max-width:900px;"><div class="panel-header"><div class="panel-title">Audit Log <span class="count">' + log.length + '</span></div>' +
    '<select class="filter-select" id="auditFilter" onchange="WG._filterAudit()" style="min-width:100px;"><option value="">All Types</option><option value="auth">Auth</option><option value="scan">Scan</option><option value="report">Report</option><option value="admin">Admin</option></select></div>' +
    '<div class="panel-body" style="padding:8px 18px;max-height:500px;overflow-y:auto;" id="auditList">' +
    log.map(function(entry) {
      return '<div class="activity-item" data-type="' + entry.type + '">' +
        '<div class="activity-icon" style="background:' + (typeColors[entry.type] || 'var(--accent)') + '15;color:' + (typeColors[entry.type] || 'var(--accent)') + ';">' + (typeIcons[entry.type] || '&#9679;') + '</div>' +
        '<div class="activity-text"><strong>' + esc(entry.user) + '</strong> <span style="color:var(--text-dim);">' + esc(entry.action) + '</span><p>' + esc(entry.detail) + '</p></div>' +
        '<span class="activity-time">' + WG.timeAgo(entry.timestamp) + '</span></div>';
    }).join('') +
    '</div></div>';
};

WG._filterAudit = function() {
  var type = document.getElementById('auditFilter').value;
  document.querySelectorAll('#auditList .activity-item').forEach(function(el) {
    el.style.display = (!type || el.dataset.type === type) ? '' : 'none';
  });
};

/* ── Export/Import ── */
WG._settingsExport = function() {
  var u = WG.currentUser && WG.currentUser();
  var isOwner = u && u.role === 'owner';
  var resetSection = isOwner
    ? ('<div style="border-top:1px solid var(--border-dim);padding-top:20px;"><div style="font-weight:600;color:var(--critical);margin-bottom:8px;">Re-run Setup Wizard</div>' +
        '<p style="font-size:0.82rem;color:var(--text-dim);margin-bottom:12px;">Wipe all users and flip the portal back to first-run state. You will be signed out and have to create the Owner again. Scans, findings, and assets are preserved.</p>' +
        '<button class="btn btn-danger" onclick="WG.resetSetup()">Re-run Setup Wizard</button></div>')
    : '';
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">Export / Import Settings</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:20px;">' +
      '<div><div style="font-weight:600;color:var(--text-bright);margin-bottom:8px;">Export Settings</div>' +
        '<p style="font-size:0.82rem;color:var(--text-dim);margin-bottom:12px;">Download all portal settings as a JSON file including theme, notifications, and general configuration.</p>' +
        '<button class="btn btn-secondary" onclick="WG._exportSettings()">&#8681; Export Settings</button></div>' +
      '<div style="border-top:1px solid var(--border-dim);padding-top:20px;"><div style="font-weight:600;color:var(--text-bright);margin-bottom:8px;">Import Settings</div>' +
        '<p style="font-size:0.82rem;color:var(--text-dim);margin-bottom:12px;">Upload a previously exported JSON settings file to restore configuration.</p>' +
        '<input type="file" id="settingsFileInput" accept=".json" style="display:none;" onchange="WG._importSettings(this)">' +
        '<button class="btn btn-secondary" onclick="document.getElementById(\'settingsFileInput\').click()">&#8679; Import Settings</button></div>' +
      '<div style="border-top:1px solid var(--border-dim);padding-top:20px;"><div style="font-weight:600;color:var(--critical);margin-bottom:8px;">Reset to Defaults</div>' +
        '<p style="font-size:0.82rem;color:var(--text-dim);margin-bottom:12px;">Clear all saved settings and restore factory defaults.</p>' +
        '<button class="btn btn-danger" onclick="WG._resetSettings()">Reset All Settings</button></div>' +
      resetSection +
    '</div></div>';
};

WG._exportSettings = function() {
  var data = { theme: WG.getThemePrefs(), notifications: WG.getNotifPrefs(), exportedAt: new Date().toISOString(), version: '2.0.0' };
  var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'wireghost-settings.json';
  a.click();
  WG.toast('Settings exported', 'success');
};

WG._importSettings = function(input) {
  var file = input.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(e) {
    try {
      var data = JSON.parse(e.target.result);
      if (data.theme) { localStorage.setItem('wg_theme', JSON.stringify(data.theme)); WG.applyTheme(data.theme); }
      if (data.notifications) WG.saveNotifPrefs(data.notifications);
      WG.toast('Settings imported', 'success');
      WG.switchSettingsTab('export');
    } catch (err) { WG.toast('Invalid settings file', 'error'); }
  };
  reader.readAsText(file);
  input.value = '';
};

WG._resetSettings = function() {
  localStorage.removeItem('wg_theme');
  localStorage.removeItem('wg_notifs');
  WG.applyTheme({});
  WG.toast('Settings reset to defaults', 'success');
  WG.switchSettingsTab('export');
};

/* ── API ── */
WG._settingsApi = function() {
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">API Connection</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:16px;">' +
      '<div class="info-grid" style="grid-template-columns:1fr 1fr;">' +
        '<div class="info-item"><div class="info-label">API Status</div><div class="info-value">' +
          '<span class="status-badge completed"><span class="dot"></span> Connected</span>' +
        '</div></div><div class="info-item"><div class="info-label">Base URL</div><div class="info-value mono">' + WG.API_BASE + '</div></div></div>' +
      '<div style="border-top:1px solid var(--border-dim);padding-top:16px;"><div style="font-weight:600;color:var(--text-bright);margin-bottom:8px;">API Endpoints</div>' +
        '<div class="code-block" style="font-size:0.72rem;">GET  /api/dashboard/           Dashboard stats\nGET  /api/scans/                List scans\nPOST /api/scans/                Create scan\nGET  /api/scans/:id/            Scan detail\nPOST /api/scans/:id/cancel/     Cancel scan\nGET  /api/scans/:id/findings/   Scan findings\nGET  /api/scans/:id/hosts/      Scan hosts\nGET  /api/hosts/                List hosts\nGET  /api/hosts/:id/            Host detail\nGET  /api/findings/             List findings\nGET  /api/findings/:id/         Finding detail\nGET  /api/reports/:id/download/ Download report</div></div>' +
      '<div><button class="btn btn-secondary" onclick="WG.testApi()">Test Connection</button></div>' +
    '</div></div>';
};

/* ── About ── */
WG._settingsAbout = function() {
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">About Wire_Ghost</div></div>' +
    '<div class="panel-body"><div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;"><div class="topbar-logo" style="width:48px;height:48px;font-size:18px;border-radius:12px;">WG</div><div><div style="font-weight:800;font-size:1.2rem;color:var(--text-bright);">Wire<span style="color:var(--accent);font-family:var(--font-mono);">_Ghost</span></div><div style="font-size:0.82rem;color:var(--text-dim);">Vulnerability Assessment Portal</div></div></div>' +
    '<div class="info-grid" style="grid-template-columns:1fr 1fr;"><div class="info-item"><div class="info-label">Version</div><div class="info-value">2.0.0-rewrite</div></div><div class="info-item"><div class="info-label">Branch</div><div class="info-value mono">rewrite-v2</div></div><div class="info-item"><div class="info-label">License</div><div class="info-value">MIT</div></div><div class="info-item"><div class="info-label">Author</div><div class="info-value">callmedemon</div></div></div>' +
    '<div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border-dim);font-size:0.82rem;color:var(--text-dim);line-height:1.7;">Security scanning orchestration toolkit. Coordinates Nmap, Nuclei, Dirsearch, WPScan, and more into a parallel pipeline with automated DOCX/XLSX/HTML reporting.</div></div></div>';
};

/* ── Administration (Owner/superuser only) ── */
WG.TIMEZONES = [
  'UTC',
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'America/Phoenix', 'America/Anchorage', 'America/Honolulu',
  'America/Toronto', 'America/Vancouver', 'America/Mexico_City',
  'America/Sao_Paulo', 'America/Buenos_Aires',
  'Europe/London', 'Europe/Dublin', 'Europe/Paris', 'Europe/Berlin',
  'Europe/Madrid', 'Europe/Rome', 'Europe/Amsterdam', 'Europe/Warsaw',
  'Europe/Athens', 'Europe/Istanbul', 'Europe/Moscow',
  'Africa/Cairo', 'Africa/Johannesburg', 'Africa/Lagos',
  'Asia/Dubai', 'Asia/Tehran', 'Asia/Karachi', 'Asia/Kolkata', 'Asia/Dhaka',
  'Asia/Bangkok', 'Asia/Singapore', 'Asia/Hong_Kong', 'Asia/Shanghai',
  'Asia/Tokyo', 'Asia/Seoul', 'Asia/Taipei',
  'Australia/Perth', 'Australia/Sydney', 'Australia/Melbourne', 'Australia/Brisbane',
  'Pacific/Auckland',
];

WG._settingsAdmin = function() {
  var user = WG.currentUser && WG.currentUser();
  if (!user || user.role !== 'owner') {
    return '<div class="panel" style="max-width:700px;"><div class="panel-body"><div class="panel-empty"><div class="icon">&#128274;</div>Owner access required.</div></div></div>';
  }
  // Refresh the current value from the server while we render.
  WG.api('/site-config/').then(function(data) {
    if (data && data.schedule_timezone) {
      WG._scheduleTz = data.schedule_timezone;
      var sel = document.getElementById('adminTimezone');
      if (sel) sel.value = data.schedule_timezone;
    }
  });
  var esc = WG.escHtml;
  var current = WG._scheduleTz || 'UTC';
  var browserTz = (Intl && Intl.DateTimeFormat().resolvedOptions().timeZone) || 'UTC';
  var opts = WG.TIMEZONES.map(function(tz) {
    return '<option value="' + esc(tz) + '"' + (tz === current ? ' selected' : '') + '>' + esc(tz) + '</option>';
  }).join('');
  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">Administration</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:18px;">' +
      '<div class="form-group">' +
        '<label class="form-label">Schedule Time Zone</label>' +
        '<select class="form-input" id="adminTimezone">' + opts + '</select>' +
        '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Interprets the "Run At" time on every Scheduled Scan. A schedule set to 02:00 runs at 02:00 in this zone. Current browser zone: <span class="mono">' + esc(browserTz) + '</span></div>' +
      '</div>' +
      '<div><button class="btn btn-primary" onclick="WG._saveScheduleTimezone()">Save</button></div>' +
    '</div></div>';
};

WG._saveScheduleTimezone = function() {
  var sel = document.getElementById('adminTimezone');
  if (!sel) return;
  var tz = sel.value;
  WG.api('/site-config/update/', {
    method: 'PUT',
    body: JSON.stringify({ schedule_timezone: tz }),
  }).then(function(res) {
    if (res && res.schedule_timezone) {
      WG._scheduleTz = res.schedule_timezone;
      WG.toast('Schedule timezone set to ' + res.schedule_timezone, 'success');
      WG.switchSettingsTab('admin');
    } else {
      WG.toast((res && res.error) || 'Failed to update timezone', 'error');
    }
  });
};

/* ── Support (Owner-only) ── */
WG._settingsSupport = function() {
  var user = WG.currentUser && WG.currentUser();
  if (!user || user.role !== 'owner') {
    return '<div class="panel" style="max-width:700px;"><div class="panel-body"><div class="panel-empty"><div class="icon">&#128274;</div>Owner access required.</div></div></div>';
  }
  var esc = WG.escHtml;
  var lastTs = null;
  try { lastTs = localStorage.getItem('wg_support_last'); } catch (e) {}
  var lastHint = '';
  if (lastTs) {
    lastHint = '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Last export: <span class="mono">' + esc(WG.timeAgo ? WG.timeAgo(lastTs) : lastTs) + '</span></div>';
  }
  return '<div class="panel" style="max-width:760px;"><div class="panel-header"><div class="panel-title">Support Diagnostic Bundle</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:18px;">' +
      '<div style="font-size:0.85rem;color:var(--text-dim);line-height:1.6;">' +
        'Generates a <span class="mono">.tar.gz</span> archive containing the most recent Django, Celery worker, Celery beat, and nginx logs, plus a non-sensitive system snapshot (version, permissions matrix, user/scan/asset counts, and the last 500 audit rows). ' +
        'Hand this file to Wire_Ghost support when opening a ticket.' +
      '</div>' +
      '<div style="border-left:3px solid var(--accent);background:var(--accent-dim);padding:12px 14px;border-radius:8px;font-size:0.78rem;color:var(--text-bright);">' +
        '<strong>Redaction</strong> — Authorization headers, session / CSRF cookies, password JSON fields, and DSN-style credentials are stripped before bundling. IPs, usernames, stack traces, and file paths are preserved so the logs stay debuggable.' +
      '</div>' +
      '<div>' +
        '<button class="btn btn-primary" id="btnSupportBundle" onclick="WG._downloadSupportBundle()">' +
          '<span>&#8681;</span> Download support bundle' +
        '</button>' +
        lastHint +
      '</div>' +
      '<div style="border-top:1px solid var(--border-dim);padding-top:14px;font-size:0.78rem;color:var(--text-dim);">' +
        'Logs persist on the host at the directory set via <span class="mono">WIREGHOST_LOG_DIR</span> in <span class="mono">.env</span> (default <span class="mono">./logs</span>). Per-container subdirectories: <span class="mono">api/</span>, <span class="mono">nginx/</span>.' +
      '</div>' +
    '</div></div>';
};

WG._downloadSupportBundle = function() {
  var btn = document.getElementById('btnSupportBundle');
  if (btn) { btn.disabled = true; btn.dataset.orig = btn.innerHTML; btn.textContent = 'Building…'; }
  var url = (WG.API_BASE || '/api') + '/support-bundle/';
  fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
  }).then(function(res) {
    if (!res.ok) {
      if (res.status === 403) { WG.toast('Owner role required to export a support bundle.', 'error'); }
      else { WG.toast('Bundle export failed (HTTP ' + res.status + ')', 'error'); }
      throw new Error('bundle');
    }
    var disp = res.headers.get('Content-Disposition') || '';
    var m = disp.match(/filename="([^"]+)"/);
    var fname = m ? m[1] : ('wireghost-support-' + Date.now() + '.tar.gz');
    return res.blob().then(function(blob) { return { blob: blob, fname: fname }; });
  }).then(function(obj) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(obj.blob);
    a.download = obj.fname;
    document.body.appendChild(a);
    a.click();
    setTimeout(function() { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    try { localStorage.setItem('wg_support_last', new Date().toISOString()); } catch (e) {}
    WG.toast('Support bundle downloaded', 'success');
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig || '&#8681; Download support bundle'; }
  }).catch(function() {
    if (btn) { btn.disabled = false; btn.innerHTML = btn.dataset.orig || '&#8681; Download support bundle'; }
  });
};

/* ── Tab switcher ── */
WG.switchSettingsTab = function(tab) {
  document.querySelectorAll('#settingsTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('settingsTabContent');
  var tabs = {
    general: WG._settingsGeneral, theme: WG._settingsTheme, notifications: WG._settingsNotifications,
    tools: WG._settingsTools, sessions: WG._settingsSessions,
    audit: WG._settingsAudit, export: WG._settingsExport, api: WG._settingsApi,
    admin: WG._settingsAdmin, support: WG._settingsSupport, about: WG._settingsAbout,
  };
  el.innerHTML = (tabs[tab] || WG._settingsGeneral)();
};
