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
      '<div class="tab" data-tab="security" onclick="WG.switchSettingsTab(\'security\')">Security</div>' +
      '<div class="tab" data-tab="audit" onclick="WG.switchSettingsTab(\'audit\')">Audit Log</div>' +
      '<div class="tab" data-tab="export" onclick="WG.switchSettingsTab(\'export\')">Export/Import</div>' +
      '<div class="tab" data-tab="api" onclick="WG.switchSettingsTab(\'api\')">API</div>' +
      '<div class="tab" data-tab="tokens" onclick="WG.switchSettingsTab(\'tokens\')">API Tokens</div>' +
      (isAdmin ? '<div class="tab" data-tab="admin" onclick="WG.switchSettingsTab(\'admin\')">Administration</div>' : '') +
      (isAdmin ? '<div class="tab" data-tab="support" onclick="WG.switchSettingsTab(\'support\')">Support</div>' : '') +
      '<div class="tab" data-tab="about" onclick="WG.switchSettingsTab(\'about\')">About</div>' +
    '</div>' +
    '<div id="settingsTabContent">' + WG._settingsGeneral() + '</div>';
};

/* ── General ──
 * Scan defaults that drive new scans when the client doesn't override them.
 * Owner sees editable inputs; everyone else sees the current values read-only. */
WG._settingsGeneral = function() {
  var user = WG.currentUser && WG.currentUser();
  var isOwner = user && user.role === 'owner';
  var cfg = WG._cache['site_config'] || {};
  WG.api('/site-config/').then(function(data) {
    if (data && WG.state.currentPage === 'settings') {
      WG._cache['site_config'] = data;
      /* Populate input values live after the GET resolves. */
      var set = function(id, v) { var el = document.getElementById(id); if (el) el.value = v; };
      set('genParallelism', data.default_parallelism);
      set('genTimeout', data.default_timeout);
      set('genReportFormats', data.default_report_formats);
    }
  });
  var esc = WG.escHtml;
  var ro = isOwner ? '' : 'disabled readonly';
  return '<div class="panel" style="max-width:720px;"><div class="panel-header"><div class="panel-title">Scan Defaults</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:18px;">' +
      '<div style="font-size:0.82rem;color:var(--text-dim);line-height:1.6;">' +
        'These values fill in when a scan is launched without an explicit override (e.g. via the <span class="mono">/api/scans/</span> API). ' +
        (isOwner ? 'Edit them here and click Save.' : 'Ask your Owner to change these in Settings.') +
      '</div>' +
      '<div class="form-group"><label class="form-label">Default Parallelism</label>' +
        '<input class="form-input" id="genParallelism" type="number" min="1" max="500" value="' + esc(cfg.default_parallelism || 10) + '" ' + ro + '>' +
        '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Number of concurrent hosts the pipeline processes (1–500).</div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Default Timeout (seconds)</label>' +
        '<input class="form-input" id="genTimeout" type="number" min="60" max="86400" value="' + esc(cfg.default_timeout || 3600) + '" ' + ro + '>' +
        '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Per-scan wall-clock limit (60–86400s).</div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Default Report Formats</label>' +
        '<input class="form-input mono" id="genReportFormats" value="' + esc(cfg.default_report_formats || 'dashboard,docx,xlsx') + '" ' + ro + '>' +
        '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Comma-separated from: <span class="mono">dashboard</span>, <span class="mono">html</span>, <span class="mono">docx</span>, <span class="mono">xlsx</span>.</div>' +
      '</div>' +
      (isOwner
        ? '<div><button class="btn btn-primary" onclick="WG._saveGeneralDefaults()">Save</button></div>'
        : '') +
    '</div></div>';
};

WG._saveGeneralDefaults = function() {
  var p = parseInt(document.getElementById('genParallelism').value, 10);
  var t = parseInt(document.getElementById('genTimeout').value, 10);
  var r = (document.getElementById('genReportFormats').value || '').trim();
  if (!(p >= 1 && p <= 500)) { WG.toast('Parallelism must be 1–500.', 'error'); return; }
  if (!(t >= 60 && t <= 86400)) { WG.toast('Timeout must be 60–86400s.', 'error'); return; }
  if (!r) { WG.toast('Report formats required.', 'error'); return; }
  WG.api('/site-config/update/', {
    method: 'PUT',
    body: JSON.stringify({
      default_parallelism: p, default_timeout: t, default_report_formats: r,
    }),
  }).then(function(res) {
    if (res && res.default_parallelism != null) {
      WG._cache['site_config'] = res;
      WG.toast('Scan defaults saved', 'success');
    } else {
      WG.toast((res && res.error) || 'Save failed', 'error');
    }
  });
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
      '<div style="display:flex;gap:10px;flex-wrap:wrap;">' +
        '<div onclick="WG.setThemeMode(\'dark\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;min-width:140px;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'dark' ? 'var(--accent)' : 'var(--border-soft)') + ';background:#0a0e17;text-align:center;transition:all 0.2s;">' +
          '<div style="margin-bottom:4px;"><svg style="width:20px;height:20px;fill:none;stroke:#e8ecf4;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;" viewBox="0 0 24 24"><use href="#i-moon"/></svg></div>' +
          '<div style="font-weight:700;color:#e8ecf4;font-size:0.85rem;">Dark</div>' +
          '<div style="font-size:0.68rem;color:#5a6478;margin-top:2px;">Tactical ops</div>' +
        '</div>' +
        '<div onclick="WG.setThemeMode(\'light\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;min-width:140px;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'light' ? 'var(--accent)' : 'var(--border-soft)') + ';background:#f0f2f5;text-align:center;transition:all 0.2s;">' +
          '<div style="margin-bottom:4px;"><svg style="width:20px;height:20px;fill:none;stroke:#1a1d23;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;" viewBox="0 0 24 24"><use href="#i-sun"/></svg></div>' +
          '<div style="font-weight:700;color:#1a1d23;font-size:0.85rem;">Light</div>' +
          '<div style="font-size:0.68rem;color:#8892a4;margin-top:2px;">Clean daylight</div>' +
        '</div>' +
        '<div onclick="WG.setThemeMode(\'cyberpunk\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;min-width:140px;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'cyberpunk' ? '#ff2d95' : 'var(--border-soft)') + ';background:#0a0012;text-align:center;transition:all 0.2s;">' +
          '<div style="margin-bottom:4px;"><svg style="width:20px;height:20px;fill:none;stroke:#ff2d95;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;" viewBox="0 0 24 24"><use href="#i-zap"/></svg></div>' +
          '<div style="font-weight:700;color:#ff2d95;font-size:0.85rem;text-shadow:0 0 8px rgba(255,45,149,0.5);">Cyberpunk</div>' +
          '<div style="font-size:0.68rem;color:#7b5ea0;margin-top:2px;">Neon overdrive</div>' +
        '</div>' +
        '<div onclick="WG.setThemeMode(\'onepiece\');WG.switchSettingsTab(\'theme\')" style="cursor:pointer;flex:1;min-width:140px;padding:16px;border-radius:var(--radius-lg);border:2px solid ' + (mode === 'onepiece' ? '#F5C518' : 'var(--border-soft)') + ';background:#0f1d36;text-align:center;transition:all 0.2s;">' +
          '<div style="margin-bottom:4px;font-size:20px;">&#9784;</div>' +
          '<div style="font-weight:700;color:#F5C518;font-size:0.85rem;text-shadow:0 0 8px rgba(245,197,24,0.5);">One Piece</div>' +
          '<div style="font-size:0.68rem;color:#29B6F6;margin-top:2px;">Grand Line</div>' +
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

/* ── Notifications ──
 * Telegram bot dispatches scan events to:
 *   - Shared channel (site-wide, Owner-configured)
 *   - Per-user DM (optional, each user's own chat_id)
 * Event toggles are server-side via /api/preferences/. */
WG._settingsNotifications = function() {
  var user = WG.currentUser && WG.currentUser();
  var isOwner = user && user.role === 'owner';
  var esc = WG.escHtml;

  /* Seed from cache, then fetch both endpoints to populate inputs. */
  var cfg = WG._cache['notif_config'] || { has_token: false, token_tail: '', shared_chat_id: '' };
  var prefs = WG._cache['prefs'] || {
    notifications: {}, telegram: { chat_id: '', enabled: false }
  };
  Promise.all([
    WG.api('/notifications/config/'),
    WG.api('/preferences/'),
  ]).then(function(results) {
    var c = results[0], p = results[1];
    if (c && WG.state.currentPage === 'settings') {
      WG._cache['notif_config'] = c;
      var sc = document.getElementById('tgSharedChat');
      if (sc) sc.value = c.shared_chat_id || '';
      var tt = document.getElementById('tgTokenTail');
      if (tt) tt.textContent = c.has_token ? (c.token_tail || '(configured)') : '(not set)';
    }
    if (p && WG.state.currentPage === 'settings') {
      WG._cache['prefs'] = p;
      var cid = document.getElementById('tgChatId');
      if (cid) cid.value = (p.telegram && p.telegram.chat_id) || '';
      var en = document.getElementById('tgEnabledTrack');
      if (en) en.classList.toggle('on', !!(p.telegram && p.telegram.enabled));
      /* sync event toggles */
      Object.keys(p.notifications || {}).forEach(function(k) {
        var el = document.getElementById('notifTrack_' + k);
        if (el) el.classList.toggle('on', !!p.notifications[k]);
      });
    }
  });

  function eventToggle(key, label) {
    var on = !!(prefs.notifications && prefs.notifications[key]);
    return '<div class="form-toggle" onclick="WG._toggleNotif(\'' + key + '\')">' +
      '<div class="toggle-track' + (on ? ' on' : '') + '" id="notifTrack_' + key + '"></div>' +
      '<span class="toggle-label">' + label + '</span></div>';
  }

  var sharedBlock = '<div class="form-group"><label class="form-label">Shared Channel ID</label>' +
    '<input class="form-input mono" id="tgSharedChat" placeholder="-1001234567890 or @wireghost_alerts" value="' + esc(cfg.shared_chat_id || '') + '" ' + (isOwner ? '' : 'disabled readonly') + '>' +
    '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Numeric channel/group ID or @channelname. Your bot must be a member/admin of the channel.</div>' +
    '</div>';

  var ownerTokenBlock = isOwner
    ? '<div class="form-group"><label class="form-label">Bot Token <span class="mono" style="color:var(--text-dim);font-size:0.72rem;">' +
        'current: <span id="tgTokenTail">' + esc(cfg.has_token ? (cfg.token_tail || '(configured)') : '(not set)') + '</span></span></label>' +
      '<div style="display:flex;gap:8px;">' +
        '<input class="form-input mono" id="tgBotToken" type="password" placeholder="Paste new token (e.g. 12345:ABC...) or leave blank to keep current">' +
        '<button class="btn btn-secondary btn-sm" onclick="var i=document.getElementById(\'tgBotToken\');i.type=i.type===\'password\'?\'text\':\'password\';">Show</button>' +
      '</div>' +
      '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:6px;">Create via <span class="mono">@BotFather</span>. Clear the field and save empty to remove.</div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;"><button class="btn btn-primary" onclick="WG._saveTelegramConfig()">Save Telegram config</button>' +
      (cfg.has_token ? '<button class="btn btn-secondary" onclick="WG._telegramTest(\'shared\')">Send test to shared</button>' : '') +
      '</div>'
    : '<div style="font-size:0.78rem;color:var(--text-dim);">' +
      (cfg.has_token ? '✓ Shared Telegram bot is configured by your Owner.' : '⚠ Telegram bot not configured. Ask your Owner to set it up.') +
      '</div>';

  var personalBlock = '<div style="border-top:1px solid var(--border-dim);padding-top:16px;">' +
    '<div style="font-weight:600;color:var(--text-bright);margin-bottom:8px;">Your personal DM</div>' +
    '<div style="font-size:0.78rem;color:var(--text-dim);margin-bottom:12px;">' +
      'Optional — receive Telegram DMs for scans YOU run. DM <span class="mono">@userinfobot</span> to find your chat_id, then start a DM with your Wire_Ghost bot so it can message you.' +
    '</div>' +
    '<div class="form-group"><label class="form-label">Your chat ID</label>' +
      '<input class="form-input mono" id="tgChatId" placeholder="123456789" value="' + esc((prefs.telegram && prefs.telegram.chat_id) || '') + '">' +
    '</div>' +
    '<div class="form-toggle" onclick="WG._togglePersonalTelegram()">' +
      '<div class="toggle-track' + ((prefs.telegram && prefs.telegram.enabled) ? ' on' : '') + '" id="tgEnabledTrack"></div>' +
      '<span class="toggle-label">Enable personal Telegram DMs</span>' +
    '</div>' +
    '<div style="display:flex;gap:8px;margin-top:12px;">' +
      '<button class="btn btn-primary btn-sm" onclick="WG._savePersonalTelegram()">Save DM settings</button>' +
      '<button class="btn btn-secondary btn-sm" onclick="WG._telegramTest(\'self\')">Send test to me</button>' +
    '</div>' +
    '<div style="border-top:1px solid var(--border-dim);margin-top:16px;padding-top:16px;">' +
      '<div style="font-weight:600;color:var(--text-bright);margin-bottom:8px;">Bot Account Linking</div>' +
      '<div style="font-size:0.78rem;color:var(--text-dim);margin-bottom:12px;">' +
        'Generate a 6-digit code, then send <span class="mono">/link &lt;code&gt;</span> to the bot in your Telegram group to link your account.' +
      '</div>' +
      '<button class="btn btn-secondary btn-sm" id="tgLinkCodeBtn" onclick="WG._generateLinkCode()">Generate Link Code</button>' +
      '<span id="tgLinkCodeResult" class="mono" style="margin-left:12px;color:var(--accent);font-size:0.9rem;"></span>' +
    '</div></div>';

  return '<div class="panel" style="max-width:820px;"><div class="panel-header"><div class="panel-title">Telegram Notifications</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:18px;">' +
      sharedBlock +
      ownerTokenBlock +
      personalBlock +
      '<div style="border-top:1px solid var(--border-dim);padding-top:16px;">' +
        '<div style="font-weight:600;color:var(--text-bright);margin-bottom:10px;">Events to notify on</div>' +
        '<div style="display:flex;flex-direction:column;gap:10px;">' +
          eventToggle('scanComplete', 'Scan completed') +
          eventToggle('scanFailed', 'Scan failed') +
          eventToggle('criticalFinding', 'Critical vulnerability discovered') +
          eventToggle('reportReady', 'Report ready for download') +
          eventToggle('weeklyDigest', 'Weekly summary digest') +
        '</div>' +
        '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:10px;">Controls YOUR personal DM only. The shared channel fires on every event regardless.</div>' +
      '</div>' +
    '</div></div>';
};

WG._saveTelegramConfig = function() {
  var tokenEl = document.getElementById('tgBotToken');
  var chatEl = document.getElementById('tgSharedChat');
  var body = {};
  if (tokenEl && tokenEl.value) body.bot_token = tokenEl.value;
  if (chatEl) body.shared_chat_id = chatEl.value.trim();
  WG.api('/notifications/config/', {
    method: 'PUT',
    body: JSON.stringify(body),
  }).then(function(res) {
    if (res && res.has_token !== undefined) {
      WG._cache['notif_config'] = res;
      WG.toast('Telegram config saved', 'success');
      if (tokenEl) tokenEl.value = '';  /* clear so next save doesn't re-submit */
      WG.switchSettingsTab('notifications');
    } else {
      WG.toast((res && res.error) || 'Save failed', 'error');
    }
  });
};

WG._savePersonalTelegram = function() {
  var chat = (document.getElementById('tgChatId').value || '').trim();
  var en = document.getElementById('tgEnabledTrack').classList.contains('on');
  WG.api('/preferences/', {
    method: 'PUT',
    body: JSON.stringify({ telegram: { chat_id: chat, enabled: en } }),
  }).then(function(res) {
    if (res && res.telegram) {
      WG._cache['prefs'] = res;
      WG.toast('DM settings saved', 'success');
    } else {
      WG.toast((res && res.error) || 'Save failed', 'error');
    }
  });
};

WG._togglePersonalTelegram = function() {
  var el = document.getElementById('tgEnabledTrack');
  if (el) el.classList.toggle('on');
};

WG._telegramTest = function(target) {
  WG.api('/notifications/test/', {
    method: 'POST',
    body: JSON.stringify({ target: target }),
  }).then(function(res) {
    if (res && res.ok) {
      WG.toast('Test message sent via Telegram.', 'success');
    } else {
      WG.toast((res && res.error) || 'Telegram test failed', 'error');
    }
  });
};

WG._generateLinkCode = function() {
  var btn = document.getElementById('tgLinkCodeBtn');
  var span = document.getElementById('tgLinkCodeResult');
  if (btn) btn.disabled = true;
  WG.api('/preferences/telegram-link/', { method: 'POST' }).then(function(res) {
    if (res && res.code) {
      if (span) span.textContent = res.code + '  (expires in 5 min)';
      if (btn) btn.textContent = 'Code generated';
      setTimeout(function() {
        if (btn) { btn.textContent = 'Generate Link Code'; btn.disabled = false; }
        if (span) span.textContent = '';
      }, 300000);
    } else {
      if (span) span.textContent = '';
      WG.toast((res && res.error) || 'Failed to generate code', 'error');
      if (btn) { btn.textContent = 'Generate Link Code'; btn.disabled = false; }
    }
  });
};

WG._toggleNotif = function(key) {
  var el = document.getElementById('notifTrack_' + key);
  if (!el) return;
  el.classList.toggle('on');
  var patch = { notifications: {} };
  patch.notifications[key] = el.classList.contains('on');
  WG.api('/preferences/', {
    method: 'PUT',
    body: JSON.stringify(patch),
  }).then(function(res) {
    if (res && res.notifications) {
      WG._cache['prefs'] = res;
    }
    /* Keep the legacy localStorage in sync so old code paths still behave. */
    try {
      var prefs = WG.getNotifPrefs ? WG.getNotifPrefs() : {};
      prefs[key] = el.classList.contains('on');
      if (WG.saveNotifPrefs) WG.saveNotifPrefs(prefs);
    } catch (e) {}
  });
};

/* ── Tools ──
 * Live probe of external scan tools on the api container's PATH.
 * Server caches results for 30s; the Refresh button passes ?refresh=1. */
WG._settingsTools = function() {
  var esc = WG.escHtml;
  var tools = WG._cache['tools_health'] || [];
  /* Background refresh so the next render shows fresh data. */
  WG.api('/tools-health/').then(function(data) {
    if (Array.isArray(data) && WG.state.currentPage === 'settings') {
      WG._cache['tools_health'] = data;
      /* Rerender in-place if still on Tools tab. */
      var container = document.getElementById('toolsHealthBody');
      if (container) {
        container.textContent = '';
        container.insertAdjacentHTML('beforeend', data.map(_toolsRow).join(''));
      }
    }
  });

  return '<div class="panel" style="max-width:760px;">' +
    '<div class="panel-header">' +
      '<div class="panel-title">External Tools <span class="count">' + tools.length + '</span></div>' +
      '<button class="btn btn-secondary btn-sm" onclick="WG._refreshToolsHealth()">Refresh</button>' +
    '</div>' +
    '<table class="data-table">' +
      '<thead><tr><th>Tool</th><th>Binary</th><th>Path</th><th>Version</th><th>Status</th></tr></thead>' +
      '<tbody id="toolsHealthBody">' + tools.map(_toolsRow).join('') + '</tbody>' +
    '</table>' +
    (tools.length ? '' : '<div class="panel-empty" style="padding:14px 0;font-size:0.82rem;color:var(--text-dim);">Probing tools…</div>') +
    '</div>' +
    ((WG.currentUser && WG.currentUser() && WG.currentUser().role === 'owner')
      ? '<div class="panel" style="max-width:760px;margin-top:16px;"><div class="panel-header"><div class="panel-title">Security Feeds</div></div>' +
        '<div class="panel-body">' +
          '<div style="font-size:0.82rem;color:var(--text-dim);margin-bottom:10px;">Update nuclei templates, searchsploit database, and OpenVAS NASL feeds on the worker container.</div>' +
          '<div style="display:flex;align-items:center;gap:10px;">' +
            '<button class="btn btn-secondary btn-sm" id="btnUpdateFeeds" onclick="WG._updateFeeds()">Update Security Feeds</button>' +
            '<span id="feedsUpdateStatus" style="font-size:0.78rem;color:var(--text-dim);"></span>' +
          '</div>' +
        '</div></div>'
      : '');
};

function _toolsRow(t) {
  var esc = WG.escHtml;
  return '<tr>' +
    '<td style="font-weight:600;color:var(--text-bright);">' + esc(t.name) + '</td>' +
    '<td class="mono" style="font-size:0.75rem;">' + esc(t.binary) + '</td>' +
    '<td class="mono" style="font-size:0.72rem;">' + esc(t.path || '—') + '</td>' +
    '<td class="mono" style="font-size:0.72rem;color:var(--text-dim);">' + esc(t.version || '—') + '</td>' +
    '<td>' + (t.ok
      ? '<span class="status-badge completed" style="font-size:0.65rem;"><span class="dot"></span> Found</span>'
      : '<span class="status-badge failed" style="font-size:0.65rem;"><span class="dot"></span> Missing</span>') + '</td>' +
  '</tr>';
}

WG._refreshToolsHealth = function() {
  WG.api('/tools-health/?refresh=1').then(function(data) {
    if (Array.isArray(data)) {
      WG._cache['tools_health'] = data;
      WG.toast('Tools re-probed', 'info');
      if (WG.state.currentPage === 'settings') WG.switchSettingsTab('tools');
    }
  });
};

WG._updateFeeds = function() {
  var btn = document.getElementById('btnUpdateFeeds');
  var status = document.getElementById('feedsUpdateStatus');
  if (btn) btn.disabled = true;
  if (status) status.textContent = 'Queuing...';
  WG.api('/update/feeds/', { method: 'POST' }).then(function(data) {
    if (data && data.status === 'queued') {
      if (status) status.textContent = 'Update queued (task: ' + WG.escHtml((data.task_id || '').substring(0, 8)) + '…)';
      WG.toast('Feed update queued on worker', 'success');
    } else {
      if (btn) btn.disabled = false;
      if (status) status.textContent = '';
      WG.toast((data && data.error) || 'Failed to queue feed update', 'error');
    }
  });
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

/* ── Security (MFA) ── */
WG._settingsSecurity = function() {
  var mfa = WG._cache['mfa_status'] || {};
  var prefs = WG._cache['prefs'] || {};
  var tgLinked = !!(prefs.telegram && prefs.telegram.chat_id);
  Promise.all([
    WG.api('/auth/mfa/status/'),
    WG.api('/preferences/'),
  ]).then(function(results) {
    var data = results[0], p = results[1];
    if (WG.state.currentPage !== 'settings') return;
    if (data) WG._cache['mfa_status'] = data;
    if (p) WG._cache['prefs'] = p;
    var linked = !!(p && p.telegram && p.telegram.chat_id);
    var el = document.getElementById('mfaStatusContent');
    if (el) el.innerHTML = WG._mfaStatusPanel(data || mfa, linked);
  });
  return '<div class="panel" style="max-width:800px;">' +
    '<div class="panel-header"><div class="panel-title">Multi-Factor Authentication</div></div>' +
    '<div class="panel-body" id="mfaStatusContent">' + WG._mfaStatusPanel(mfa, tgLinked) + '</div></div>';
};

WG._mfaStatusPanel = function(mfa, tgLinked) {
  if (mfa.enabled) {
    return '' +
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">' +
        '<span class="status-badge completed" style="font-size:0.75rem;"><span class="dot"></span> MFA Enabled</span>' +
        '<span class="mono" style="font-size:0.78rem;color:var(--text-dim);">' + (mfa.backup_codes_remaining || 0) + ' backup codes remaining</span>' +
      '</div>' +
      '<div style="display:flex;gap:10px;">' +
        '<button class="btn btn-secondary btn-sm" onclick="WG._mfaRegenCodes()">Regenerate Backup Codes</button>' +
        '<button class="btn btn-danger btn-sm" onclick="WG._mfaDisable()">Disable MFA</button>' +
      '</div>';
  }
  if (!tgLinked) {
    return '' +
      '<div style="margin-bottom:16px;">' +
        '<p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:12px;">Add an extra layer of security. When enabled, you\'ll need to enter a verification code sent via Telegram each time you sign in.</p>' +
        '<div style="padding:12px 14px;border-left:3px solid var(--medium);background:rgba(255,170,0,0.06);border-radius:8px;font-size:0.82rem;color:var(--text-bright);">' +
          'Link your Telegram account first. Go to <a href="#" onclick="WG.switchSettingsTab(\'notifications\');return false;" style="color:var(--accent);font-weight:600;">Settings &rarr; Notifications</a> and set your chat ID.' +
        '</div>' +
      '</div>';
  }
  return '' +
    '<div style="margin-bottom:16px;">' +
      '<p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:12px;">Add an extra layer of security. When enabled, you\'ll need to enter a verification code sent via Telegram each time you sign in.</p>' +
    '</div>' +
    '<button class="btn btn-primary btn-sm" onclick="WG._mfaStartSetup()">Enable MFA</button>';
};

WG._mfaReauth = function(callback) {
  /* Static template — no user input interpolated. */
  var html = '' +
    '<div style="display:flex;flex-direction:column;gap:16px;">' +
      '<p style="color:var(--text-dim);font-size:0.85rem;">Enter your password to continue.</p>' +
      '<div class="form-group">' +
        '<label class="form-label">Password</label>' +
        '<input class="form-input" id="reauthPass" type="password" placeholder="Current password" autocomplete="current-password">' +
      '</div>' +
      '<div id="reauthError" style="display:none;color:var(--critical);font-size:0.82rem;"></div>' +
    '</div>';
  WG.modal('Re-authenticate', html, [
    { label: 'Cancel', cls: 'btn-secondary', action: function() { WG.closeModal(); } },
    { label: 'Confirm', cls: 'btn-primary', action: function() {
      var pw = document.getElementById('reauthPass').value;
      if (!pw) { var e = document.getElementById('reauthError'); e.textContent = 'Password required'; e.style.display = 'block'; return; }
      WG.api('/auth/reauth/', { method: 'POST', body: JSON.stringify({ password: pw }) }).then(function(res) {
        if (res && res.status === 'ok') { WG.closeModal(); callback(); }
        else { var e = document.getElementById('reauthError'); e.textContent = (res && res.error) || 'Invalid password'; e.style.display = 'block'; }
      });
    }},
  ]);
};

WG._mfaStartSetup = function() {
  WG._mfaReauth(function() {
    WG.api('/auth/mfa/setup/', { method: 'POST' }).then(function(res) {
      if (!res || res.error) { WG.toast(res ? res.error : 'Setup failed', 'error'); return; }
      var setupToken = res.setup_token;
      /* Static template — no user input interpolated. */
      var html = '' +
        '<div style="display:flex;flex-direction:column;gap:16px;">' +
          '<p style="color:var(--text-dim);font-size:0.85rem;">A verification code has been sent to your Telegram. Enter it below to complete MFA setup.</p>' +
          '<div class="form-group">' +
            '<label class="form-label">Verification Code</label>' +
            '<input class="form-input" id="mfaSetupCode" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit code" style="text-align:center;font-family:var(--font-mono);font-size:1.1rem;letter-spacing:0.2em;">' +
          '</div>' +
          '<div id="mfaSetupError" style="display:none;color:var(--critical);font-size:0.82rem;"></div>' +
        '</div>';
      WG.modal('Confirm MFA Setup', html, [
        { label: 'Cancel', cls: 'btn-secondary', action: function() { WG.closeModal(); } },
        { label: 'Verify & Enable', cls: 'btn-primary', action: function() {
          var code = document.getElementById('mfaSetupCode').value.trim();
          if (!code) { var e = document.getElementById('mfaSetupError'); e.textContent = 'Enter the code'; e.style.display = 'block'; return; }
          WG.api('/auth/mfa/confirm/', { method: 'POST', body: JSON.stringify({ setup_token: setupToken, code: code }) }).then(function(r) {
            if (r && r.enabled) {
              WG.closeModal();
              WG._cache['mfa_status'] = { enabled: true, backup_codes_remaining: 8 };
              WG._showBackupCodes(r.backup_codes);
              WG.switchSettingsTab('security');
            } else {
              var e = document.getElementById('mfaSetupError'); e.textContent = (r && r.error) || 'Invalid code'; e.style.display = 'block';
            }
          });
        }},
      ]);
    });
  });
};

WG._showBackupCodes = function(codes) {
  if (!codes || !codes.length) return;
  var esc = WG.escHtml;
  var list = codes.map(function(c) { return '<code style="font-family:var(--font-mono);font-size:1rem;padding:4px 10px;background:var(--bg-card);border:1px solid var(--border-soft);border-radius:var(--radius-sm);">' + esc(c) + '</code>'; }).join('');
  /* Backup codes are server-generated hex (token_hex(4)), escaped via escHtml. */
  var html = '' +
    '<div style="display:flex;flex-direction:column;gap:16px;">' +
      '<p style="color:var(--critical);font-weight:600;font-size:0.85rem;">Save these backup codes now. They will not be shown again.</p>' +
      '<p style="color:var(--text-dim);font-size:0.82rem;">Each code can be used once to sign in if you lose access to your Telegram.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;padding:16px;background:var(--bg-app);border-radius:var(--radius-md);">' + list + '</div>' +
      '<button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText(\'' + codes.join('\\n') + '\');WG.toast(\'Copied\',\'info\')">Copy All</button>' +
    '</div>';
  WG.modal('Backup Codes', html, [
    { label: 'I\'ve saved these codes', cls: 'btn-primary', action: function() { WG.closeModal(); } },
  ]);
};

WG._mfaDisable = function() {
  WG._mfaReauth(function() {
    WG.api('/auth/mfa/disable/', { method: 'POST' }).then(function(res) {
      if (res && !res.error) {
        WG._cache['mfa_status'] = { enabled: false, backup_codes_remaining: 0 };
        WG.toast('MFA disabled', 'info');
        WG.switchSettingsTab('security');
      } else { WG.toast((res && res.error) || 'Failed to disable MFA', 'error'); }
    });
  });
};

WG._mfaRegenCodes = function() {
  WG._mfaReauth(function() {
    WG.api('/auth/mfa/backup-codes/', { method: 'POST' }).then(function(res) {
      if (res && res.backup_codes) {
        WG._cache['mfa_status'] = { enabled: true, backup_codes_remaining: res.backup_codes.length };
        WG._showBackupCodes(res.backup_codes);
      } else { WG.toast((res && res.error) || 'Failed to regenerate codes', 'error'); }
    });
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
  var esc = WG.escHtml;
  var user = WG.currentUser && WG.currentUser();
  var isOwner = user && user.role === 'owner';
  var ud = WG._aboutUpdateData;

  WG.api('/update-check/').then(function(data) {
    WG._aboutUpdateData = data || {};
    var el = document.getElementById('aboutUpdateStatus');
    if (el) { el.textContent = ''; el.insertAdjacentHTML('beforeend', WG._aboutUpdateStatusHtml(data, isOwner)); }
  });

  return '<div class="panel" style="max-width:700px;"><div class="panel-header"><div class="panel-title">About Wire_Ghost</div></div>' +
    '<div class="panel-body"><div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;"><div class="topbar-logo" style="width:48px;height:48px;font-size:18px;border-radius:12px;">WG</div><div><div style="font-weight:800;font-size:1.2rem;color:var(--text-bright);">Wire<span style="color:var(--accent);font-family:var(--font-mono);">_Ghost</span></div><div style="font-size:0.82rem;color:var(--text-dim);">Vulnerability Assessment Portal</div></div></div>' +
    '<div class="info-grid" style="grid-template-columns:1fr 1fr;">' +
      '<div class="info-item"><div class="info-label">Version</div><div class="info-value">' + esc(ud && ud.current ? ud.current : '2.0.0') + '</div></div>' +
      '<div class="info-item"><div class="info-label">Branch</div><div class="info-value mono">rewrite-v2</div></div>' +
      '<div class="info-item"><div class="info-label">License</div><div class="info-value">MIT</div></div>' +
      '<div class="info-item"><div class="info-label">Author</div><div class="info-value">callmedemon</div></div>' +
    '</div>' +
    '<div id="aboutUpdateStatus" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border-dim);">' +
      WG._aboutUpdateStatusHtml(ud, isOwner) +
    '</div>' +
    '<div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border-dim);font-size:0.82rem;color:var(--text-dim);line-height:1.7;">Security scanning orchestration toolkit. Coordinates Nmap, Nuclei, Dirsearch, WPScan, and more into a parallel pipeline with automated DOCX/XLSX/HTML reporting.</div></div></div>';
};

WG._aboutUpdateStatusHtml = function(data, isOwner) {
  var esc = WG.escHtml;
  if (!data) return '<div style="font-size:0.82rem;color:var(--text-dim);">Checking for updates...</div>';
  if (data.error) return '<div style="font-size:0.82rem;color:var(--text-dim);">Unable to check for updates: ' + esc(data.error) + '</div>' +
    (isOwner ? '<div style="margin-top:10px;"><button class="btn btn-secondary btn-sm" onclick="WG._forceUpdateCheck()">Retry</button></div>' : '');

  if (!data.update_available) {
    return '<div style="font-size:0.82rem;color:var(--accent);"><strong>&#10003; Up to date</strong> — ' + esc(data.current || '') + ' is the latest version.' +
      (data.checked_at ? ' <span style="color:var(--text-dim);">Last checked: ' + esc(data.checked_at.replace('T', ' ').substring(0, 19)) + ' UTC</span>' : '') +
      '</div>' +
      (isOwner ? '<div style="margin-top:10px;"><button class="btn btn-secondary btn-sm" onclick="WG._forceUpdateCheck()">Check Now</button></div>' : '');
  }

  var html = '<div style="font-size:0.82rem;border-left:3px solid var(--accent);padding:10px 14px;background:var(--accent-dim);border-radius:8px;">' +
    '<strong>&#128230; Update available:</strong> ' + esc(data.latest) +
    (data.published_at ? ' <span style="color:var(--text-dim);">(' + esc(data.published_at.split('T')[0]) + ')</span>' : '') +
    (data.latest_url ? ' &mdash; <a href="' + esc(data.latest_url) + '" target="_blank" rel="noopener" style="color:var(--accent);">Release Notes</a>' : '') +
    '</div>';

  if (isOwner) {
    html += '<div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;">' +
      '<button class="btn btn-primary btn-sm" onclick="WG._requestUpdate()">Request Update</button>' +
      '<button class="btn btn-secondary btn-sm" onclick="WG._forceUpdateCheck()">Re-check</button>' +
    '</div>' +
    '<div style="margin-top:10px;font-size:0.72rem;color:var(--text-dim);">After requesting, run on the host: <code class="mono">./scripts/wg-ctl update</code></div>';
  }
  return html;
};

WG._forceUpdateCheck = function() {
  WG._aboutUpdateData = null;
  WG.api('/update-check/', { method: 'POST' }).then(function(data) {
    WG._aboutUpdateData = data || {};
    if (WG.state.currentPage === 'settings') WG.switchSettingsTab('about');
    if (data && !data.error) WG.toast('Update check complete', 'success');
    else WG.toast((data && data.error) || 'Check failed', 'error');
  });
};

WG._requestUpdate = function() {
  if (!confirm('This will flag the system for update. You must then run ./scripts/wg-ctl update on the host. Continue?')) return;
  WG.api('/update/apply/', { method: 'POST' }).then(function(data) {
    if (data && data.status === 'flagged') {
      WG.toast('Update flagged. Run: ./scripts/wg-ctl update', 'success');
      if (WG.state.currentPage === 'settings') WG.switchSettingsTab('about');
    } else {
      WG.toast((data && data.error) || 'Failed to request update', 'error');
    }
  });
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

/* ── API Tokens ── */
WG._settingsTokens = function() {
  /* Any authenticated user can manage their own tokens — the token inherits
   * the caller's permissions, so there's no escalation vector. */
  var esc = WG.escHtml;
  var tokens = WG.getCached('api_tokens', '/auth/tokens/');
  WG.fetchData('/auth/tokens/', 'api_tokens').then(function(data) {
    if (data && WG.state.currentPage === 'settings') {
      WG._cache['api_tokens'] = data;
      WG._cacheTime['api_tokens'] = Date.now();
    }
  });
  return '<div class="panel" style="max-width:860px;">' +
    '<div class="panel-header">' +
      '<div class="panel-title">API Tokens <span class="count">' + tokens.length + '</span></div>' +
      '<button class="btn btn-primary btn-sm" onclick="WG._showCreateTokenForm()">+ New token</button>' +
    '</div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:14px;">' +
      '<div style="font-size:0.82rem;color:var(--text-dim);line-height:1.6;">' +
        'Tokens authenticate programmatic requests via <span class="mono">Authorization: Token wg_…</span>. ' +
        'They inherit your role\u2019s permissions. Each token is shown <strong>once</strong> at creation — from then on only the prefix is visible. Store it like a password.' +
      '</div>' +
      '<div id="tokenCreatePanel" style="display:none;"></div>' +
      (tokens.length
        ? '<table class="data-table"><thead><tr>' +
            '<th>Name</th><th>Prefix</th><th>Created</th><th>Last used</th><th>Status</th><th></th>' +
          '</tr></thead><tbody>' +
          tokens.map(function(t) {
            var revoked = !!t.revoked_at;
            var statusCell = revoked
              ? '<span class="status-badge failed" style="font-size:0.65rem;">Revoked</span>'
              : '<span class="status-badge completed" style="font-size:0.65rem;"><span class="dot"></span> Active</span>';
            var revokeBtn = revoked
              ? ''
              : '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG._revokeToken(\'' + esc(t.id) + '\',\'' + esc(t.name) + '\')">Revoke</button>';
            return '<tr>' +
              '<td style="font-weight:600;color:var(--text-bright);">' + esc(t.name) + '</td>' +
              '<td class="mono" style="font-size:0.75rem;">' + esc(t.prefix) + '…</td>' +
              '<td class="mono" style="font-size:0.72rem;">' + (t.created_at ? WG.fmtDate(t.created_at) : '—') + '</td>' +
              '<td class="mono" style="font-size:0.72rem;">' + (t.last_used_at ? WG.timeAgo(t.last_used_at) : '—') + '</td>' +
              '<td>' + statusCell + '</td>' +
              '<td>' + revokeBtn + '</td>' +
            '</tr>';
          }).join('') +
          '</tbody></table>'
        : '<div class="panel-empty" style="padding:20px 0;"><div class="icon">&#128273;</div>No tokens yet. Click <strong>+ New token</strong> to create one.</div>'
      ) +
    '</div></div>';
};

WG._showCreateTokenForm = function() {
  var panel = document.getElementById('tokenCreatePanel');
  if (!panel) return;
  panel.style.display = 'block';
  var html = '<div style="background:var(--bg-input);border-radius:var(--radius-md);padding:14px;display:flex;flex-direction:column;gap:10px;">' +
    '<div style="font-weight:600;color:var(--text-bright);">Create a new token</div>' +
    '<div style="display:flex;gap:8px;">' +
      '<input class="form-input" id="newTokenName" placeholder="e.g. my-laptop, ci-pipeline" maxlength="80" style="flex:1;" onkeydown="if(event.key===\'Enter\')WG._mintToken()">' +
      '<button class="btn btn-primary btn-sm" onclick="WG._mintToken()">Create</button>' +
      '<button class="btn btn-secondary btn-sm" onclick="WG._hideCreateTokenForm()">Cancel</button>' +
    '</div>' +
  '</div>';
  panel.textContent = '';
  panel.insertAdjacentHTML('beforeend', html);
  setTimeout(function() {
    var inp = document.getElementById('newTokenName');
    if (inp) inp.focus();
  }, 30);
};

WG._hideCreateTokenForm = function() {
  var panel = document.getElementById('tokenCreatePanel');
  if (panel) { panel.style.display = 'none'; panel.textContent = ''; }
};

WG._mintToken = function() {
  var inp = document.getElementById('newTokenName');
  if (!inp) return;
  var name = inp.value.trim();
  if (!name) { WG.toast('Enter a name for the token.', 'error'); return; }

  WG.api('/auth/tokens/', {
    method: 'POST',
    body: JSON.stringify({ name: name }),
  }).then(function(res) {
    if (!res || !res.token) {
      WG.toast((res && res.error) || 'Token creation failed', 'error');
      return;
    }
    WG._showNewTokenReveal(res);
    WG.invalidateCache('api_tokens');
  });
};

WG._showNewTokenReveal = function(tok) {
  var panel = document.getElementById('tokenCreatePanel');
  if (!panel) return;
  var esc = WG.escHtml;
  var html = '<div style="border:1px solid var(--accent);background:var(--accent-dim);border-radius:var(--radius-md);padding:14px;display:flex;flex-direction:column;gap:10px;">' +
    '<div style="font-weight:700;color:var(--text-bright);">Token created — copy it now</div>' +
    '<div style="font-size:0.78rem;color:var(--text-dim);">This is the only time the full token will be shown. Store it like a password.</div>' +
    '<div style="display:flex;gap:8px;">' +
      '<input id="newTokenValue" class="form-input mono" readonly value="' + esc(tok.token) + '" style="flex:1;font-size:0.82rem;" onclick="this.select()">' +
      '<button class="btn btn-primary btn-sm" onclick="WG._copyTokenToClipboard()">Copy</button>' +
      '<button class="btn btn-secondary btn-sm" onclick="WG._hideCreateTokenForm();WG.switchSettingsTab(\'tokens\')">Done</button>' +
    '</div>' +
    '<div class="mono" style="font-size:0.7rem;color:var(--text-dim);">Use: <code>curl -H "Authorization: Token ' + esc(tok.prefix) + '…"</code></div>' +
  '</div>';
  panel.textContent = '';
  panel.insertAdjacentHTML('beforeend', html);
  setTimeout(function() {
    var el = document.getElementById('newTokenValue');
    if (el) { el.focus(); el.select(); }
  }, 30);
};

WG._copyTokenToClipboard = function() {
  var el = document.getElementById('newTokenValue');
  if (!el) return;
  el.select();
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(el.value).then(
      function() { WG.toast('Token copied to clipboard', 'success'); },
      function() { WG.toast('Could not copy — select the field and press Ctrl+C.', 'error'); }
    );
  } else {
    try { document.execCommand('copy'); WG.toast('Token copied to clipboard', 'success'); }
    catch (e) { WG.toast('Could not copy — select the field and press Ctrl+C.', 'error'); }
  }
};

WG._revokeToken = function(id, name) {
  if (!window.confirm('Revoke token "' + name + '"?\n\nAny scripts or curls using this token will stop working immediately.')) return;
  WG.api('/auth/tokens/' + id + '/revoke/', { method: 'POST' }).then(function(res) {
    if (res && res.revoked_at) {
      WG.toast('Token revoked', 'info');
      WG.invalidateCache('api_tokens');
      WG.switchSettingsTab('tokens');
    } else {
      WG.toast((res && res.error) || 'Revoke failed', 'error');
    }
  });
};

/* ── Tab switcher ── */
WG.switchSettingsTab = function(tab) {
  document.querySelectorAll('#settingsTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('settingsTabContent');
  var tabs = {
    general: WG._settingsGeneral, theme: WG._settingsTheme, notifications: WG._settingsNotifications,
    tools: WG._settingsTools, sessions: WG._settingsSessions, security: WG._settingsSecurity,
    audit: WG._settingsAudit, export: WG._settingsExport, api: WG._settingsApi,
    tokens: WG._settingsTokens,
    admin: WG._settingsAdmin, support: WG._settingsSupport, about: WG._settingsAbout,
  };
  el.innerHTML = (tabs[tab] || WG._settingsGeneral)();
};
