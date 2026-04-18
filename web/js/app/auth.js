/* Wire_Ghost — Session helpers (Tier 1, authenticated only).
 *
 * This file ships only to clients that already have a valid Django session
 * cookie (nginx auth_request gates /js/app/*). The actual login flow lives
 * in /js/public/login-boot.js — this file is for an already-authenticated
 * SPA to read/refresh user info and log out.
 */

/* User info cache — NOT the session itself (the Django sessionid cookie
 * is the source of truth; localStorage just caches the last /auth/me/
 * payload so the topbar can render without a round-trip on every load). */
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

/* Refresh the cached user payload from /api/auth/me/. */
WG.verifySession = function() {
  return WG.api('/auth/me/').then(function(data) {
    if (data && data.id) {
      var name = data.name || data.username;
      WG.setSession({
        id: data.id, username: data.username, name: name,
        email: data.email || '', role: data.role || 'engineer',
        avatar: name.split(' ').map(function(w) { return w[0]; }).join('').toUpperCase().substring(0, 2),
      });
      return true;
    }
    WG.clearSession();
    return false;
  });
};

/* Logout — drop the server session, clear the cache, hard-redirect to /login
 * so nginx re-gates the shell (no stale Tier-1 JS stays resident). */
WG.logout = function() {
  fetch(WG.API_BASE + '/auth/logout/', { method: 'POST', credentials: 'include' }).catch(function() {});
  WG.clearSession();
  window.location.href = '/login';
};
