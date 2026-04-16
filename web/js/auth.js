/* Wire_Ghost — Authentication (production)
   Session managed by Django session cookie only.
   localStorage used only as UI cache for user info. */

/* User info cache — NOT the session itself (cookie handles that) */
WG.getSession = function() {
  try { return JSON.parse(localStorage.getItem('wg_user_info')); }
  catch (e) { return null; }
};

WG.setSession = function(data) {
  localStorage.setItem('wg_user_info', JSON.stringify(data));
};

WG.clearSession = function() {
  localStorage.removeItem('wg_user_info');
};

WG.isLoggedIn = function() {
  return WG.getSession() !== null;
};

WG.currentUser = function() {
  return WG.getSession();
};

/* Verify session is still valid by calling /api/auth/me/ */
WG.verifySession = function() {
  return WG.api('/auth/me/').then(function(data) {
    if (data && data.id) {
      var name = data.name || data.username;
      WG.setSession({
        id: data.id, username: data.username, name: name,
        email: data.email || '', role: data.role || 'analyst',
        avatar: name.split(' ').map(function(w) { return w[0]; }).join('').toUpperCase().substring(0, 2),
      });
      return true;
    }
    WG.clearSession();
    return false;
  });
};

/* Login — POST to Django API, session cookie set by server */
WG.login = async function(username, password) {
  try {
    var res = await fetch(WG.API_BASE + '/auth/login/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password }),
      credentials: 'include',
    });
    if (res.ok) {
      var data = await res.json();
      WG.USE_MOCK = false;
      var statusEl = document.getElementById('topbarStatus');
      if (statusEl) statusEl.textContent = 'API Connected';
      var name = data.name || data.username;
      WG.setSession({
        id: data.id, username: data.username, name: name,
        email: data.email || '', role: data.role || 'analyst',
        avatar: name.split(' ').map(function(w) { return w[0]; }).join('').toUpperCase().substring(0, 2),
      });
      return true;
    }
    return false;
  } catch (e) {
    return false;
  }
};

/* Mock data fallbacks for settings tabs */
WG.MOCK_USERS = WG.MOCK_USERS || [];
WG.MOCK_SESSIONS = WG.MOCK_SESSIONS || [];
WG.MOCK_API_KEYS = WG.MOCK_API_KEYS || [];
WG.MOCK_AUDIT_LOG = WG.MOCK_AUDIT_LOG || [];

WG.logout = function() {
  fetch(WG.API_BASE + '/auth/logout/', { method: 'POST', credentials: 'include' }).catch(function() {});
  WG.clearSession();
  window.location.hash = '#login';
  WG.render();
};

/* Login page */
WG.renderLogin = function() {
  return '' +
    '<div class="login-page">' +
      '<div class="login-card">' +
        '<div class="login-header">' +
          '<div class="topbar-logo" style="width:48px;height:48px;font-size:18px;border-radius:12px;margin:0 auto 16px;">WG</div>' +
          '<h1 style="font-size:1.4rem;font-weight:800;color:var(--text-bright);text-align:center;">Wire<span style="color:var(--accent);font-family:var(--font-mono);">_Ghost</span></h1>' +
          '<p style="color:var(--text-dim);font-size:0.82rem;text-align:center;margin-top:4px;">Sign in to your account</p>' +
        '</div>' +
        '<div style="display:flex;flex-direction:column;gap:16px;margin-top:24px;">' +
          '<div class="form-group">' +
            '<label class="form-label">Username</label>' +
            '<input class="form-input" id="loginUser" type="text" placeholder="Username" autofocus onkeydown="if(event.key===\'Enter\'){document.getElementById(\'loginPass\').focus();}">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">Password</label>' +
            '<input class="form-input" id="loginPass" type="password" placeholder="Password" onkeydown="if(event.key===\'Enter\')WG.handleLogin();">' +
          '</div>' +
          '<div id="loginError" style="display:none;color:var(--critical);font-size:0.82rem;text-align:center;padding:8px;background:rgba(255,59,92,0.08);border-radius:var(--radius-md);"></div>' +
          '<button class="btn btn-primary" id="loginBtn" style="width:100%;justify-content:center;padding:11px;" onclick="WG.handleLogin()">Sign In</button>' +
        '</div>' +
        '<div style="margin-top:16px;text-align:center;">' +
          '<span style="font-size:0.72rem;color:var(--text-muted);">Wire_Ghost Vulnerability Assessment Portal</span>' +
        '</div>' +
      '</div>' +
    '</div>';
};

WG.handleLogin = async function() {
  var u = document.getElementById('loginUser').value.trim();
  var p = document.getElementById('loginPass').value;
  var err = document.getElementById('loginError');
  var btn = document.getElementById('loginBtn');

  if (!u || !p) { err.textContent = 'Username and password required'; err.style.display = 'block'; return; }

  btn.disabled = true;
  btn.textContent = 'Signing in...';
  err.style.display = 'none';

  var ok = await WG.login(u, p);
  if (ok) {
    WG.navigate('dashboard');
  } else {
    err.textContent = 'Invalid username or password';
    err.style.display = 'block';
    document.getElementById('loginPass').value = '';
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
};
