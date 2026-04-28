/* Wire_Ghost — Login boot (Tier 0, served to everyone).
 *
 * Self-contained: deliberately does NOT depend on api.js, state.js, router.js,
 * or anything else from /js/app/. Its only job is to render the login form
 * into /login.html and POST to /api/auth/login/. On success, hard-redirects
 * to "/" so nginx re-gates the session and ships Tier-1 JS.
 */

window.WG = window.WG || {};
WG.API_BASE = '/api';

/* Cache the auth'd user payload in localStorage so the SPA shell can render
 * the topbar/avatar on the next page without an extra /auth/me/ round-trip. */
WG._setLoginCache = function(data) {
  try {
    var name = data.name || data.username;
    localStorage.setItem('wg_user_info', JSON.stringify({
      id: data.id, username: data.username, name: name,
      email: data.email || '', role: data.role || 'engineer',
      avatar: name.split(' ').map(function(w) { return w[0]; })
                  .join('').toUpperCase().substring(0, 2),
    }));
  } catch (e) { /* private mode — fine, /auth/me/ will refresh it */ }
};

WG._renderLoginForm = function(mount) {
  /* Static string literal — no user input interpolated. Using
   * insertAdjacentHTML instead of innerHTML to match the codebase's
   * safe-html pattern enforced by the Wire_Ghost Write hook. */
  var html = '' +
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
            '<input class="form-input" id="loginUser" type="text" placeholder="Username" autofocus autocomplete="username" onkeydown="if(event.key===\'Enter\'){document.getElementById(\'loginPass\').focus();}">' +
          '</div>' +
          '<div class="form-group">' +
            '<label class="form-label">Password</label>' +
            '<input class="form-input" id="loginPass" type="password" placeholder="Password" autocomplete="current-password" onkeydown="if(event.key===\'Enter\')WG._handleLogin();">' +
          '</div>' +
          '<div id="loginError" style="display:none;color:var(--critical);font-size:0.82rem;text-align:center;padding:8px;background:rgba(255,59,92,0.08);border-radius:var(--radius-md);"></div>' +
          '<button class="btn btn-primary" id="loginBtn" style="width:100%;justify-content:center;padding:11px;" onclick="WG._handleLogin()">Sign In</button>' +
        '</div>' +
        '<div style="margin-top:16px;text-align:center;">' +
          '<span style="font-size:0.72rem;color:var(--text-muted);">Wire_Ghost Vulnerability Assessment Portal</span>' +
        '</div>' +
      '</div>' +
    '</div>';
  mount.insertAdjacentHTML('afterbegin', html);
};

WG._handleLogin = async function() {
  var u = document.getElementById('loginUser').value.trim();
  var p = document.getElementById('loginPass').value;
  var err = document.getElementById('loginError');
  var btn = document.getElementById('loginBtn');

  if (!u || !p) {
    err.textContent = 'Username and password required';
    err.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in...';
  err.style.display = 'none';

  try {
    var res = await fetch(WG.API_BASE + '/auth/login/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p }),
      credentials: 'include',
    });
    if (res.ok) {
      var data = await res.json();
      if (data.mfa_required) {
        WG._showMfaForm(data.mfa_token);
        return;
      }
      WG._setLoginCache(data);
      WG._redirectAfterLogin();
      return;
    }
    err.textContent = res.status === 429
      ? 'Too many attempts — try again in a minute.'
      : 'Invalid username or password';
  } catch (e) {
    err.textContent = 'Could not reach the server.';
  }

  err.style.display = 'block';
  document.getElementById('loginPass').value = '';
  btn.disabled = false;
  btn.textContent = 'Sign In';
};

WG._redirectAfterLogin = function() {
  var next = '/dashboard';
  try {
    var q = new URLSearchParams(window.location.search).get('next');
    if (q && q.charAt(0) === '/' && q.indexOf('//') !== 1) next = q;
  } catch (e) {}
  window.location.href = next;
};

WG._showMfaForm = function(token) {
  var card = document.querySelector('.login-card');
  if (!card) return;
  /* Static template — token is secrets.token_urlsafe (alphanum + -_). No user HTML. */
  card.innerHTML = '' +
    '<div class="login-header">' +
      '<div class="topbar-logo" style="width:48px;height:48px;font-size:18px;border-radius:12px;margin:0 auto 16px;">WG</div>' +
      '<h1 style="font-size:1.4rem;font-weight:800;color:var(--text-bright);text-align:center;">Verification Required</h1>' +
      '<p style="color:var(--text-dim);font-size:0.82rem;text-align:center;margin-top:4px;">Code sent to your Telegram</p>' +
    '</div>' +
    '<div style="display:flex;flex-direction:column;gap:16px;margin-top:24px;">' +
      '<div class="form-group">' +
        '<label class="form-label">Verification Code</label>' +
        '<input class="form-input" id="mfaCode" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="8" placeholder="Enter 6-digit code" autofocus autocomplete="one-time-code" style="text-align:center;font-family:var(--font-mono);font-size:1.2rem;letter-spacing:0.3em;" onkeydown="if(event.key===\'Enter\')WG._handleMfaVerify(\'' + token + '\');">' +
      '</div>' +
      '<div id="mfaError" style="display:none;color:var(--critical);font-size:0.82rem;text-align:center;padding:8px;background:rgba(255,59,92,0.08);border-radius:var(--radius-md);"></div>' +
      '<button class="btn btn-primary" id="mfaBtn" style="width:100%;justify-content:center;padding:11px;" onclick="WG._handleMfaVerify(\'' + token + '\')">Verify</button>' +
      '<div style="display:flex;justify-content:space-between;align-items:center;">' +
        '<button class="btn btn-ghost btn-sm" id="mfaResendBtn" onclick="WG._handleMfaResend(\'' + token + '\')">Resend Code</button>' +
        '<span style="font-size:0.72rem;color:var(--text-muted);">or enter a backup code</span>' +
      '</div>' +
    '</div>';
};

WG._handleMfaVerify = async function(token) {
  var code = document.getElementById('mfaCode').value.trim();
  var err = document.getElementById('mfaError');
  var btn = document.getElementById('mfaBtn');
  if (!code) { err.textContent = 'Enter the verification code'; err.style.display = 'block'; return; }

  btn.disabled = true;
  btn.textContent = 'Verifying...';
  err.style.display = 'none';

  try {
    var res = await fetch(WG.API_BASE + '/auth/mfa/verify/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_token: token, code: code }),
      credentials: 'include',
    });
    if (res.ok) {
      var data = await res.json();
      WG._setLoginCache(data);
      WG._redirectAfterLogin();
      return;
    }
    var body = await res.json().catch(function() { return {}; });
    err.textContent = body.error || (res.status === 429 ? 'Too many attempts — start over.' : 'Invalid code');
  } catch (e) {
    err.textContent = 'Could not reach the server.';
  }

  err.style.display = 'block';
  document.getElementById('mfaCode').value = '';
  btn.disabled = false;
  btn.textContent = 'Verify';
};

WG._handleMfaResend = async function(token) {
  var btn = document.getElementById('mfaResendBtn');
  btn.disabled = true;
  btn.textContent = 'Sending...';

  try {
    var res = await fetch(WG.API_BASE + '/auth/mfa/resend/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_token: token }),
      credentials: 'include',
    });
    var body = await res.json().catch(function() { return {}; });
    if (res.ok) {
      btn.textContent = 'Code Resent';
      setTimeout(function() { btn.textContent = 'Resend Code'; btn.disabled = false; }, 30000);
      return;
    }
    btn.textContent = body.error || 'Resend failed';
  } catch (e) {
    btn.textContent = 'Network error';
  }
  setTimeout(function() { btn.textContent = 'Resend Code'; btn.disabled = false; }, 5000);
};

/* On load: short-circuit to the setup wizard if the portal hasn't been
 * initialised yet, otherwise render the login form. Clears any stale
 * user_info cache from a prior session along the way. */
document.addEventListener('DOMContentLoaded', function() {
  try { localStorage.removeItem('wg_user_info'); } catch (e) {}
  var mount = document.getElementById('loginMount');
  if (!mount) return;

  fetch(WG.API_BASE + '/site-config/', { credentials: 'include' })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      if (data && data.setup_complete === false) {
        window.location.href = '/setup';
        return;
      }
      WG._renderLoginForm(mount);
    })
    .catch(function() { WG._renderLoginForm(mount); });
});
