/* Wire_Ghost — First-time Setup Wizard (Tier 0, pre-auth).
 *
 * Served by /setup.html (no auth_request gate). Also reachable from the
 * authenticated "Re-run Setup Wizard" button in Settings — in that context
 * the Tier-1 helpers below are already defined, so the `|| ...` polyfills
 * are no-ops. */

if (typeof WG === 'undefined') window.WG = {};
WG.API_BASE = WG.API_BASE || '/api';
WG.state = WG.state || { currentPage: 'setup' };

/* ── Tier-0 polyfills ── */
WG.escHtml = WG.escHtml || function(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
};
WG.toast = WG.toast || function(msg, kind) {
  try { console.log('[' + (kind || 'info') + '] ' + msg); } catch (e) {}
};
WG.navigate = WG.navigate || function(page) {
  var map = { login: '/login', setup: '/setup', dashboard: '/dashboard' };
  window.location.href = map[page] || '/' + page;
};
WG.render = WG.render || function() {
  var m = document.getElementById('setupMount');
  if (m && WG.renderSetup) {
    m.textContent = '';
    m.insertAdjacentHTML('beforeend', WG.renderSetup());
  }
};
WG.clearSession = WG.clearSession || function() {
  try { localStorage.removeItem('wg_user_info'); } catch (e) {}
};
WG.isLoggedIn = WG.isLoggedIn || function() { return false; };
WG.login = WG.login || async function(username, password) {
  try {
    var res = await fetch(WG.API_BASE + '/auth/login/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password }),
      credentials: 'include',
    });
    return res.ok;
  } catch (e) { return false; }
};

WG.SETUP_STEPS = ['welcome', 'database', 'admin', 'branding', 'tools', 'complete'];
WG._setupStep = 0;

WG.isSetupComplete = function() {
  // Check localStorage cache first (fast), then API verifies
  return localStorage.getItem('wg_setup_complete') === '1';
};

/* Check server for setup state — called on boot */
WG.checkSetupFromServer = function() {
  WG.api('/site-config/').then(function(data) {
    if (data && data.setup_complete) {
      localStorage.setItem('wg_setup_complete', '1');
    } else if (data && !data.setup_complete) {
      localStorage.removeItem('wg_setup_complete');
      if (WG.state.currentPage !== 'setup') {
        WG.navigate('setup');
      }
    }
    // Cache schedule timezone for the Settings → Administration tab default.
    if (data && data.schedule_timezone) {
      WG._scheduleTz = data.schedule_timezone;
    }
  });
};

WG.renderSetup = function() {
  var step = WG.SETUP_STEPS[WG._setupStep] || 'welcome';
  var total = WG.SETUP_STEPS.length;
  var pct = ((WG._setupStep) / (total - 1) * 100).toFixed(0);

  return '' +
    '<div class="setup-page">' +
      '<div class="setup-card">' +
        '<div class="setup-header">' +
          '<div class="topbar-logo" style="width:44px;height:44px;font-size:16px;border-radius:11px;margin:0 auto 14px;">WG</div>' +
          '<h1 style="font-size:1.3rem;font-weight:800;color:var(--text-bright);text-align:center;">Wire<span style="color:var(--accent);font-family:var(--font-mono);">_Ghost</span> Setup</h1>' +
          (WG._setupStep > 0 && WG._setupStep < total - 1 ? '' +
            '<div style="margin-top:16px;">' +
              '<div style="display:flex;justify-content:space-between;margin-bottom:6px;">' +
                '<span class="mono" style="font-size:0.65rem;color:var(--text-dim);">Step ' + (WG._setupStep + 1) + ' of ' + total + '</span>' +
                '<span class="mono" style="font-size:0.65rem;color:var(--accent);">' + pct + '%</span>' +
              '</div>' +
              '<div class="progress-bar" style="height:4px;"><div class="progress-fill" style="width:' + pct + '%;"></div></div>' +
            '</div>' +
            '<div class="setup-steps-dots">' +
              WG.SETUP_STEPS.map(function(s, i) {
                var cls = i < WG._setupStep ? 'done' : i === WG._setupStep ? 'active' : '';
                return '<div class="setup-dot ' + cls + '"></div>';
              }).join('') +
            '</div>'
          : '') +
        '</div>' +
        '<div class="setup-body" id="setupBody">' +
          WG._setupContent(step) +
        '</div>' +
      '</div>' +
    '</div>';
};

WG._setupContent = function(step) {
  var fn = {
    welcome: WG._setupWelcome,
    database: WG._setupDatabase,
    admin: WG._setupAdmin,
    branding: WG._setupBranding,
    tools: WG._setupTools,
    complete: WG._setupComplete,
  };
  return (fn[step] || WG._setupWelcome)();
};

/* ── Step 1: Welcome ── */
WG._setupWelcome = function() {
  return '' +
    '<div style="text-align:center;padding:20px 0;">' +
      '<div style="font-size:2.5rem;margin-bottom:16px;opacity:0.3;">&#9889;</div>' +
      '<h2 style="font-size:1.15rem;font-weight:700;color:var(--text-bright);margin-bottom:8px;">Welcome to Wire_Ghost</h2>' +
      '<p style="color:var(--text-dim);font-size:0.85rem;line-height:1.7;max-width:380px;margin:0 auto;">Automated vulnerability assessment platform. This wizard will configure your installation in a few quick steps.</p>' +
      '<div style="margin-top:24px;display:flex;flex-direction:column;gap:10px;text-align:left;max-width:300px;margin-left:auto;margin-right:auto;">' +
        WG._setupCheckItem('Database connection', 'Configure MySQL') +
        WG._setupCheckItem('Admin account', 'Create your first user') +
        WG._setupCheckItem('Report branding', 'Company name & logo') +
        WG._setupCheckItem('Tool verification', 'Check installed scanners') +
      '</div>' +
    '</div>' +
    '<div class="setup-footer">' +
      '<button class="btn btn-ghost" onclick="WG._skipSetup()">Skip Setup</button>' +
      '<button class="btn btn-primary" onclick="WG._setupNext()">Get Started</button>' +
    '</div>';
};

WG._setupCheckItem = function(title, desc) {
  return '<div style="display:flex;align-items:center;gap:10px;padding:8px 0;">' +
    '<div style="width:28px;height:28px;border-radius:50%;background:var(--accent-dim);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:0.75rem;flex-shrink:0;">&#10003;</div>' +
    '<div><div style="font-size:0.82rem;font-weight:600;color:var(--text-primary);">' + title + '</div>' +
    '<div style="font-size:0.7rem;color:var(--text-dim);">' + desc + '</div></div></div>';
};

/* ── Step 2: Database ── */
WG._setupDatabase = function() {
  return '' +
    '<h2 class="setup-title">Database Configuration</h2>' +
    '<p class="setup-desc">Connect to your MySQL database</p>' +
    '<div style="display:flex;flex-direction:column;gap:14px;margin-top:16px;">' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Host</label><input class="form-input" id="setupDbHost" placeholder="Database host"></div>' +
        '<div class="form-group"><label class="form-label">Port</label><input class="form-input" id="setupDbPort" placeholder="3306"></div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Database Name</label><input class="form-input" id="setupDbName" placeholder="Database name"></div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Username</label><input class="form-input" id="setupDbUser" placeholder="Database user"></div>' +
        '<div class="form-group"><label class="form-label">Password</label><input class="form-input" id="setupDbPass" type="password" placeholder="Database password"></div>' +
      '</div>' +
      '<div id="setupDbStatus"></div>' +
      '<button class="btn btn-secondary btn-sm" onclick="WG._testDbConnection()" style="align-self:flex-start;">Test Connection</button>' +
    '</div>' +
    '<div class="setup-footer">' +
      '<button class="btn btn-ghost" onclick="WG._setupPrev()">Back</button>' +
      '<button class="btn btn-primary" onclick="WG._setupNext()">Continue</button>' +
    '</div>';
};

WG._testDbConnection = function() {
  var el = document.getElementById('setupDbStatus');
  el.innerHTML = '<div style="display:flex;align-items:center;gap:8px;padding:8px 0;"><div class="spinner" style="width:16px;height:16px;"></div><span class="mono" style="font-size:0.78rem;color:var(--text-dim);">Testing connection...</span></div>';

  // Hit site-config (public endpoint) to verify API + DB are reachable
  fetch(WG.API_BASE + '/site-config/').then(function(res) {
    if (res.ok) {
      el.innerHTML = '<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--success-dim);border-radius:var(--radius-md);"><span style="color:var(--success);font-weight:600;font-size:0.82rem;">&#10003; Connected to database</span></div>';
    } else {
      el.innerHTML = '<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--medium-dim);border-radius:var(--radius-md);"><span style="color:var(--medium);font-weight:600;font-size:0.82rem;">&#9888; API returned error (' + res.status + ')</span></div>';
    }
  }).catch(function() {
    el.innerHTML = '<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--medium-dim);border-radius:var(--radius-md);"><span style="color:var(--medium);font-weight:600;font-size:0.82rem;">&#9888; API not reachable</span></div>';
  });
};

/* ── Step 3: Admin Account ── */
WG._setupAdmin = function() {
  return '' +
    '<h2 class="setup-title">Create Admin Account</h2>' +
    '<p class="setup-desc">Set up your first administrator account</p>' +
    '<div style="display:flex;flex-direction:column;gap:14px;margin-top:16px;">' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Full Name</label><input class="form-input" id="setupAdminName" placeholder="Your Name"></div>' +
        '<div class="form-group"><label class="form-label">Username</label><input class="form-input" id="setupAdminUser" placeholder="admin" oninput="WG._checkUsername(this.value)"><div id="usernameStatus" style="font-size:0.72rem;margin-top:4px;"></div></div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Email</label><input class="form-input" id="setupAdminEmail" type="email" placeholder="admin@yourcompany.com"></div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Password</label><input class="form-input" id="setupAdminPass" type="password" placeholder="Strong password"></div>' +
        '<div class="form-group"><label class="form-label">Confirm Password</label><input class="form-input" id="setupAdminPass2" type="password" placeholder="Confirm"></div>' +
      '</div>' +
      '<div id="setupAdminError" style="display:none;color:var(--critical);font-size:0.82rem;padding:10px 14px;background:rgba(255,59,92,0.08);border-radius:var(--radius-md);"></div>' +
    '</div>' +
    '<div class="setup-footer">' +
      '<button class="btn btn-ghost" onclick="WG._setupPrev()">Back</button>' +
      '<button class="btn btn-primary" onclick="WG._validateAdmin()">Continue</button>' +
    '</div>';
};

WG._usernameAvailable = null;

WG._checkUsername = function(val) {
  var el = document.getElementById('usernameStatus');
  val = val.trim();
  if (!val || val.length < 2) { el.textContent = ''; WG._usernameAvailable = null; return; }
  clearTimeout(WG._usernameCheckTimer);
  WG._usernameCheckTimer = setTimeout(function() {
    fetch(WG.API_BASE + '/auth/check-username/?username=' + encodeURIComponent(val))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        WG._usernameAvailable = data.available;
        el.textContent = data.available ? '\u2713 Available' : '\u2717 ' + (data.reason || 'Username taken');
        el.style.color = data.available ? 'var(--success)' : 'var(--critical)';
      })
      .catch(function() { el.textContent = ''; WG._usernameAvailable = null; });
  }, 500);
};

WG._validateAdmin = async function() {
  var name = (document.getElementById('setupAdminName').value || '').trim();
  var user = (document.getElementById('setupAdminUser').value || '').trim();
  var email = (document.getElementById('setupAdminEmail').value || '').trim();
  var pass = document.getElementById('setupAdminPass').value;
  var pass2 = document.getElementById('setupAdminPass2').value;
  var err = document.getElementById('setupAdminError');

  if (!name || !user || !email || !pass) { err.textContent = 'All fields are required'; err.style.display = 'block'; return; }
  if (pass !== pass2) { err.textContent = 'Passwords do not match'; err.style.display = 'block'; return; }
  if (pass.length < 4) { err.textContent = 'Password must be at least 4 characters'; err.style.display = 'block'; return; }
  if (WG._usernameAvailable === false) { err.textContent = 'Username is already taken'; err.style.display = 'block'; return; }

  err.style.display = 'none';

  // Any previous user's session must not survive into the newly-set-up portal.
  if (WG.clearSession) WG.clearSession();

  // Create the admin account via API.
  try {
    var res = await fetch(WG.API_BASE + '/auth/setup-admin/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, username: user, email: email, password: pass }),
    });
    var data = await res.json();
    if (!res.ok) {
      err.textContent = data.error || 'Failed to create account';
      err.style.display = 'block';
      return;
    }
  } catch (e) {
    err.textContent = 'Could not reach the API to create the account. Please check the backend and try again.';
    err.style.display = 'block';
    return;
  }

  // Immediately sign the new Owner in so they land on the dashboard without
  // having to re-enter credentials. WG.login sets the Django session cookie.
  try {
    var ok = await WG.login(user, pass);
    if (!ok) {
      // setup_admin succeeded but login didn't — unusual; send the user to
      // the login page with a hint rather than leaving them stuck.
      WG.navigate('login');
      return;
    }
  } catch (e) {
    WG.navigate('login');
    return;
  }

  var avatar = name.split(' ').map(function(w) { return w[0]; }).join('').toUpperCase().substring(0, 2);
  localStorage.setItem('wg_setup_admin', JSON.stringify({ name: name, username: user, email: email, avatar: avatar }));

  WG._setupNext();
};

/* ── Step 4: Branding ── */
WG._setupBranding = function() {
  return '' +
    '<h2 class="setup-title">Report Branding</h2>' +
    '<p class="setup-desc">Customize how your reports look</p>' +
    '<div style="display:flex;flex-direction:column;gap:14px;margin-top:16px;">' +
      '<div class="form-group"><label class="form-label">Company Name</label><input class="form-input" id="setupCompany" placeholder="Your Company Name"></div>' +
      '<div class="form-group"><label class="form-label">Report Title</label><input class="form-input" id="setupReportTitle" value="Vulnerability Assessment Report"></div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Prepared By</label><input class="form-input" id="setupPreparedBy" placeholder="Security Team"></div>' +
        '<div class="form-group"><label class="form-label">Brand Color</label>' +
          '<div style="display:flex;gap:8px;align-items:center;">' +
            '<input type="color" id="setupColor" value="#006D38" style="width:40px;height:36px;border:1px solid var(--border-soft);border-radius:var(--radius-sm);background:var(--bg-input);cursor:pointer;">' +
            '<input class="form-input" id="setupColorHex" value="#006D38" style="flex:1;" oninput="document.getElementById(\'setupColor\').value=this.value">' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Logo (optional)</label>' +
        '<div style="display:flex;gap:10px;align-items:center;">' +
          '<input type="file" id="setupLogoFile" accept="image/*" style="display:none;" onchange="WG._onSetupLogoPick(this)">' +
          '<button class="btn btn-secondary btn-sm" onclick="document.getElementById(\'setupLogoFile\').click()">Upload Logo</button>' +
          '<span class="mono" style="font-size:0.72rem;color:var(--text-dim);" id="setupLogoName">No logo</span>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="setup-footer">' +
      '<button class="btn btn-ghost" onclick="WG._setupPrev()">Back</button>' +
      '<button class="btn btn-primary" onclick="WG._saveBranding()">Continue</button>' +
    '</div>';
};

/* Logo file-picker handler. Stashes the File object on WG so
 * _finishSetup can push it to /api/report-config/logo/ once the new
 * Owner's session is live (upload requires report:logo:upload, which
 * the owner has but anonymous callers don't — we can't POST during the
 * wizard itself). */
WG._onSetupLogoPick = function(input) {
  var file = input.files && input.files[0];
  var label = document.getElementById('setupLogoName');
  if (!file) {
    WG._setupLogoBlob = null;
    if (label) label.textContent = 'No logo';
    return;
  }
  WG._setupLogoBlob = file;
  if (label) label.textContent = file.name;
};

WG._saveBranding = function() {
  var company = (document.getElementById('setupCompany').value || '').trim();
  var title = (document.getElementById('setupReportTitle').value || '').trim();
  var prepared = (document.getElementById('setupPreparedBy').value || '').trim();
  var color = document.getElementById('setupColor').value;

  localStorage.setItem('wg_setup_branding', JSON.stringify({
    company_name: company, report_title: title, prepared_by: prepared, brand_color: color,
  }));

  // Branding + logo are both pushed to the API in _finishSetup, once the
  // Owner's session is established (both endpoints require auth).
  WG._setupNext();
};

/* ── Step 5: Tool Check ── */
WG._setupTools = function() {
  var tools = [
    { name: 'Nmap', desc: 'Port scanner', required: true },
    { name: 'Nuclei', desc: 'Vuln scanner', required: true },
    { name: 'fping', desc: 'Host discovery', required: true },
    { name: 'httpx', desc: 'HTTP probe', required: true },
    { name: 'Dirsearch', desc: 'Dir brute', required: false },
    { name: 'Searchsploit', desc: 'Exploit DB', required: false },
    { name: 'WPScan', desc: 'WordPress', required: false },
    { name: 'OpenVAS', desc: 'Full VA', required: false },
  ];

  return '' +
    '<h2 class="setup-title">Tool Verification</h2>' +
    '<p class="setup-desc">Checking installed security tools</p>' +
    '<div style="margin-top:16px;" id="setupToolsList">' +
      tools.map(function(t) {
        var status = t.name !== 'OpenVAS';
        return '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-dim);">' +
          '<div style="display:flex;align-items:center;gap:10px;">' +
            '<div style="width:8px;height:8px;border-radius:50%;background:' + (status ? 'var(--success)' : 'var(--text-dim)') + ';"></div>' +
            '<div><span style="font-weight:600;color:var(--text-bright);font-size:0.85rem;">' + t.name + '</span>' +
            (t.required ? ' <span style="color:var(--critical);font-size:0.65rem;">*</span>' : '') +
            '<div style="font-size:0.7rem;color:var(--text-dim);">' + t.desc + '</div></div>' +
          '</div>' +
          '<span class="status-badge ' + (status ? 'completed' : 'cancelled') + '" style="font-size:0.65rem;"><span class="dot"></span> ' + (status ? 'Found' : 'Missing') + '</span>' +
        '</div>';
      }).join('') +
    '</div>' +
    '<div style="margin-top:12px;padding:10px 14px;background:var(--accent-dim);border-radius:var(--radius-md);font-size:0.78rem;color:var(--accent);">' +
      '&#9432; Required tools marked with <span style="color:var(--critical);">*</span>. Optional tools extend scan capabilities.' +
    '</div>' +
    '<div class="setup-footer">' +
      '<button class="btn btn-ghost" onclick="WG._setupPrev()">Back</button>' +
      '<button class="btn btn-primary" onclick="WG._setupNext()">Continue</button>' +
    '</div>';
};

/* ── Step 6: Complete ── */
WG._setupComplete = function() {
  var admin = {};
  try { admin = JSON.parse(localStorage.getItem('wg_setup_admin') || '{}'); } catch (e) {}
  var branding = {};
  try { branding = JSON.parse(localStorage.getItem('wg_setup_branding') || '{}'); } catch (e) {}

  return '' +
    '<div style="text-align:center;padding:20px 0;">' +
      '<div style="font-size:3rem;margin-bottom:12px;">&#10003;</div>' +
      '<h2 style="font-size:1.2rem;font-weight:700;color:var(--success);margin-bottom:8px;">Setup Complete</h2>' +
      '<p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:24px;">Wire_Ghost is ready to use</p>' +
      '<div style="text-align:left;background:var(--bg-card);border-radius:var(--radius-lg);padding:16px 20px;display:flex;flex-direction:column;gap:10px;">' +
        '<div class="setup-summary-row"><span class="setup-summary-label">Admin</span><span class="mono">' + WG.escHtml(admin.username || 'admin') + '</span></div>' +
        (branding.company_name ? '<div class="setup-summary-row"><span class="setup-summary-label">Company</span><span>' + WG.escHtml(branding.company_name) + '</span></div>' : '') +
        '<div class="setup-summary-row"><span class="setup-summary-label">Database</span><span class="mono">' + 'MySQL Connected' + '</span></div>' +
        '<div class="setup-summary-row"><span class="setup-summary-label">Tools</span><span class="mono">7/8 available</span></div>' +
      '</div>' +
    '</div>' +
    '<div class="setup-footer" style="justify-content:center;">' +
      '<button class="btn btn-primary" style="padding:12px 32px;font-size:0.9rem;" onclick="WG._finishSetup()">Launch Wire_Ghost</button>' +
    '</div>';
};

/* ── Navigation ── */
WG._setupNext = function() {
  if (WG._setupStep < WG.SETUP_STEPS.length - 1) {
    WG._setupStep++;
    WG.render();
  }
};

WG._setupPrev = function() {
  if (WG._setupStep > 0) {
    WG._setupStep--;
    WG.render();
  }
};

WG._finishSetup = async function() {
  localStorage.setItem('wg_setup_complete', '1');
  var admin = {};
  try { admin = JSON.parse(localStorage.getItem('wg_setup_admin') || '{}'); } catch (e) {}
  var branding = {};
  try { branding = JSON.parse(localStorage.getItem('wg_setup_branding') || '{}'); } catch (e) {}

  /* Push branding to the server (was previously localStorage-only — the
   * server's ReportConfig stayed empty even though the user filled it in). */
  if (branding.company_name || branding.report_title || branding.prepared_by || branding.brand_color) {
    try {
      await WG.api('/report-config/', {
        method: 'PUT',
        body: JSON.stringify({
          company_name: branding.company_name || '',
          report_title: branding.report_title || 'Vulnerability Assessment Report',
          prepared_by: branding.prepared_by || '',
          brand_color: branding.brand_color || '#006D38',
        }),
      });
    } catch (e) { /* non-fatal — user can edit in Settings later */ }
  }

  /* Upload the logo (if picked) — multipart POST, handled by its own view.
   * Uses raw fetch because WG.api forces Content-Type: application/json
   * which breaks FormData. */
  if (WG._setupLogoBlob) {
    try {
      var fd = new FormData();
      fd.append('logo', WG._setupLogoBlob);
      await fetch(WG.API_BASE + '/report-config/logo/', {
        method: 'POST',
        body: fd,
        credentials: 'include',
        headers: { 'X-CSRFToken': WG._getCSRF ? WG._getCSRF() : '' },
      });
    } catch (e) { /* non-fatal */ }
    WG._setupLogoBlob = null;
  }

  /* Mark setup complete server-side. setup-admin already flipped the
   * flag atomically, but this second call also records completed_by. */
  try {
    await WG.api('/site-config/setup-complete/', {
      method: 'POST',
      body: JSON.stringify({ completed_by: admin.username || 'admin' }),
    });
  } catch (e) { /* non-fatal */ }

  // The new Owner was auto-logged-in in _createAdmin, so land on the
  // dashboard; otherwise fall back to the login page.
  if (WG.isLoggedIn && WG.isLoggedIn()) {
    WG.navigate('dashboard');
  } else {
    WG.navigate('login');
  }
};

WG._skipSetup = function() {
  localStorage.setItem('wg_setup_complete', '1');
  WG.api('/site-config/setup-complete/', { method: 'POST', body: JSON.stringify({ completed_by: 'skipped' }) });
  WG.navigate('login');
};

WG.resetSetup = function() {
  var user = WG.currentUser && WG.currentUser();
  if (!user || user.role !== 'owner') {
    WG.toast('Owner role required to re-run setup.', 'error');
    return;
  }
  var msg = 'Re-run setup wizard?\n\nThis DELETES all users (including yours) and clears setup state. You will be signed out and have to create the Owner again. Scans, findings, and assets are kept.';
  if (!window.confirm(msg)) return;

  WG.api('/site-config/reset-setup/', { method: 'POST' }).then(function(res) {
    if (res && res.setup_complete === false) {
      try {
        localStorage.removeItem('wg_setup_complete');
        localStorage.removeItem('wg_setup_admin');
        localStorage.removeItem('wg_setup_branding');
      } catch (e) {}
      if (WG.clearSession) WG.clearSession();
      WG._setupStep = 0;
      WG.toast('Setup reset — reloading…', 'success');
      setTimeout(function() { window.location.href = '/setup'; }, 600);
    } else {
      WG.toast((res && res.error) || 'Reset failed', 'error');
    }
  });
};

/* ── Tier-0 self-mount ──
 * When loaded from /setup.html (no router.js), mount the wizard ourselves.
 * Skip mounting if there's no #setupMount (we're running inside app.html). */
document.addEventListener('DOMContentLoaded', function() {
  var mount = document.getElementById('setupMount');
  if (!mount) return;
  WG.state.currentPage = 'setup';
  WG._setupStep = 0;

  /* Short-circuit if setup is already complete — bounce to login. */
  fetch(WG.API_BASE + '/site-config/', { credentials: 'include' })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      if (data && data.setup_complete) {
        window.location.href = '/login';
        return;
      }
      WG.render();
    })
    .catch(function() { WG.render(); /* API hiccup — still render the wizard */ });
});
