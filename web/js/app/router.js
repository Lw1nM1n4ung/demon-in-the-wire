/* Wire_Ghost — Router & initialization (History API, Tier 1).
 *
 * This file is only served to authenticated clients (nginx auth_request
 * guards /js/app/*). Login and setup live in their own Tier-0 entry
 * documents (/login, /setup) — this router only sees the SPA after sign-in.
 */

/* Pages allowed for each role. Owner has access to everything. */
WG._VIEWER_PAGES = { dashboard: 1, findings: 1, finding: 1, settings: 1 };
WG._ENGINEER_BLOCKED = { users: 1 };

WG._canVisit = function(page) {
  var user = WG.currentUser && WG.currentUser();
  var role = (user && user.role) || '';
  if (role === 'owner') return true;
  if (role === 'engineer') return !WG._ENGINEER_BLOCKED[page];
  return !!WG._VIEWER_PAGES[page];
};

WG._applySidebarRole = function() {
  var user = WG.currentUser && WG.currentUser();
  var role = (user && user.role) || '';
  document.querySelectorAll('[data-role]').forEach(function(el) {
    var req = el.getAttribute('data-role');
    var ok = (req === 'owner' && role === 'owner')
          || (req === 'engineer+' && (role === 'owner' || role === 'engineer'));
    el.style.display = ok ? '' : 'none';
  });
};

/* ── Route table: (page name) ⇄ URL path.
 *
 * Every SPA destination has a canonical path. Navigation writes the path
 * via pushState; deep-link reloads parse the pathname via _matchPath so
 * /scans/<uuid> resolves back to { page: 'scan', id: '<uuid>' } even
 * though the user never went through the SPA navigation handler. */
WG._ROUTES = [
  { page: 'dashboard',      path: '/dashboard' },
  { page: 'scans',          path: '/scans' },
  { page: 'scan',           path: '/scans/:id' },
  { page: 'findings',       path: '/findings' },
  { page: 'finding',        path: '/findings/:id' },
  { page: 'exploits',       path: '/exploits' },
  { page: 'hosts',          path: '/hosts' },
  { page: 'host',           path: '/hosts/:id' },
  { page: 'topology',       path: '/topology' },
  { page: 'new-scan',       path: '/new-scan' },
  { page: 'scan-queue',     path: '/scan-queue' },
  { page: 'scheduled',      path: '/scheduled' },
  { page: 'policies',       path: '/policies' },
  { page: 'reports',        path: '/reports' },
  { page: 'report-builder', path: '/report-builder' },
  { page: 'settings',       path: '/settings' },
  { page: 'users',          path: '/users' },
  { page: 'system',         path: '/system' },
  { page: 'ad-recon',       path: '/ad-recon' },
];

WG._routeToPath = function(page, params) {
  params = params || {};
  for (var i = 0; i < WG._ROUTES.length; i++) {
    var r = WG._ROUTES[i];
    if (r.page === page) {
      return r.path.replace(':id', params.id != null ? encodeURIComponent(params.id) : '');
    }
  }
  return '/dashboard';
};

WG._matchPath = function(pathname) {
  /* Default to dashboard at the site root. */
  if (!pathname || pathname === '/' || pathname === '/app.html') {
    return { page: 'dashboard', id: null };
  }
  for (var i = 0; i < WG._ROUTES.length; i++) {
    var r = WG._ROUTES[i];
    if (r.path.indexOf(':id') === -1) {
      if (pathname === r.path) return { page: r.page, id: null };
    } else {
      var base = r.path.split(':id')[0];
      if (pathname.indexOf(base) === 0) {
        var tail = pathname.slice(base.length).replace(/\/$/, '');
        if (tail && tail.indexOf('/') === -1) {
          return { page: r.page, id: decodeURIComponent(tail) };
        }
      }
    }
  }
  return { page: 'dashboard', id: null };
};

WG.navigate = function(page, params) {
  if (WG.closeMobileNav) WG.closeMobileNav();
  var path = WG._routeToPath(page, params);
  if (location.pathname !== path) history.pushState({}, '', path);
  WG.render();
};

WG.render = function() {
  var route = WG._matchPath(location.pathname);

  /* The nginx auth_request gate already ensured we're authenticated before
   * this file was delivered, but a cached localStorage user_info might be
   * stale (e.g. session expired server-side between page loads). If the
   * cache is missing, force a hard reload through the login flow. */
  if (!WG.isLoggedIn()) {
    window.location.href = '/login';
    return;
  }

  /* Role gate: silently redirect to dashboard if the current role isn't
   * allowed to view this page. */
  if (!WG._canVisit(route.page)) {
    WG.navigate('dashboard');
    return;
  }

  WG.state.currentPage = route.page;

  /* Update banner — check once per session, cache for 6h. */
  if (!WG._updateCheckDone) {
    WG._updateCheckDone = true;
    WG.api('/update-check/').then(function(data) {
      if (data && data.update_available) {
        WG._updateInfo = data;
        WG._showUpdateBanner(data);
      }
    });
  }

  /* Topbar: user avatar + name + email + role. */
  var user = WG.currentUser();
  if (user) {
    var avatar = document.getElementById('topbarAvatar');
    var uname = document.getElementById('topbarUserName');
    var uemail = document.getElementById('topbarUserEmail');
    var urole = document.getElementById('topbarUserRole');
    var davatar = document.getElementById('dropdownAvatar');
    if (avatar) avatar.textContent = user.avatar;
    if (davatar) davatar.textContent = user.avatar;
    if (uname) uname.textContent = user.name;
    if (uemail) uemail.textContent = user.email || '';
    if (urole) urole.textContent = user.role || '';
  }

  /* First-render-only: pull preferences from the server + flush any
   * branding the user staged during setup before their first login. */
  if (!WG._prefsLoaded && WG.loadPrefsFromServer) {
    WG._prefsLoaded = true;
    WG.loadPrefsFromServer();
    var pendingBranding = localStorage.getItem('wg_setup_branding');
    if (pendingBranding) {
      WG.api('/report-config/', { method: 'PUT', body: pendingBranding });
      localStorage.removeItem('wg_setup_branding');
    }
  }

  /* Role-based sidebar visibility. */
  WG._applySidebarRole();

  /* Active-state class on the matching sidebar item. */
  document.querySelectorAll('.sidebar-item[data-page]').forEach(function(el) {
    el.classList.toggle('active', el.dataset.page === route.page);
  });

  var pages = {
    dashboard:        WG.renderDashboard,
    scans:            WG.renderScans,
    scan:             function() { return WG.renderScanDetail(route.id); },
    findings:         WG.renderFindings,
    exploits:         WG.renderExploits,
    hosts:            WG.renderHosts,
    topology:         function() { return WG.renderTopology(route.id); },
    host:             function() { return WG.renderHostDetail(route.id); },
    finding:          function() { return WG.renderFindingDetail(route.id); },
    policies:         WG.renderPolicies,
    'new-scan':       WG.renderNewScan,
    'scan-queue':     WG.renderScanQueue,
    scheduled:        WG.renderScheduled,
    reports:          WG.renderReports,
    'report-builder': WG.renderReportBuilder,
    settings:         WG.renderSettings,
    users:            WG.renderUsers,
    system:           WG.renderSystem,
    'ad-recon':       WG.renderADRecon,
  };

  var renderFn = pages[route.page] || WG.renderDashboard;
  var main = document.getElementById('mainContent');

  /* Destroy any lingering Chart.js instances from the previous page so the
   * canvas nodes are garbage-collected with the replaced DOM. */
  if (WG._destroyCharts) WG._destroyCharts();
  if (WG._topoTeardown) WG._topoTeardown();

  main.style.animation = 'none';
  main.offsetHeight; /* force reflow */
  main.style.animation = '';
  /* renderFn output is trusted (built by us, no user input interpolated
   * without escaping in the page modules); matches the rest of the SPA. */
  main.textContent = '';
  main.insertAdjacentHTML('beforeend', renderFn());
  main.scrollTop = 0;

  /* Start the live elapsed-time ticker if any running scans are visible. */
  if (WG._startElapsedTicker) WG._startElapsedTicker();
};

/* ── Event binding ── */
function _initEvents() {
  /* Sidebar nav — intercept clicks so History API drives the route change
   * instead of a full document navigation. */
  document.querySelectorAll('.sidebar-item[data-page]').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.preventDefault();
      WG.navigate(el.dataset.page);
    });
  });

  document.querySelectorAll('.sidebar-item[data-action]').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.preventDefault();
      if (el.dataset.action === 'newScan') WG.openModal('scanModal');
      if (el.dataset.action === 'logout') WG.logout();
    });
  });

  document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) WG.closeModal(overlay.id);
    });
  });

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      if (WG.closeMobileNav) WG.closeMobileNav();
      document.querySelectorAll('.modal-overlay.active').forEach(function(m) { WG.closeModal(m.id); });
    }
    if (e.key === '/' && !e.target.matches('input,textarea,select')) {
      e.preventDefault();
      if (WG.isLoggedIn()) WG.openModal('searchModal');
    }
  });

  /* Back/forward button → re-render. */
  window.addEventListener('popstate', WG.render);
}

/* ── Update banner helpers ── */
WG._showUpdateBanner = function(data) {
  var banner = document.getElementById('updateBanner');
  if (!banner) return;
  var dismissed = null;
  try { dismissed = localStorage.getItem('wg_update_dismissed'); } catch(e) {}
  if (dismissed === data.latest) return;

  var text = document.getElementById('updateBannerText');
  var link = document.getElementById('updateBannerLink');
  if (text) text.textContent = 'Wire_Ghost ' + WG.escHtml(data.latest) + ' is available (current: ' + WG.escHtml(data.current) + ')';
  if (link && data.latest_url) { link.href = data.latest_url; link.style.display = ''; }
  else if (link) { link.style.display = 'none'; }
  banner.style.display = '';
};

WG._dismissUpdateBanner = function() {
  var banner = document.getElementById('updateBanner');
  if (banner) banner.style.display = 'none';
  if (WG._updateInfo && WG._updateInfo.latest) {
    try { localStorage.setItem('wg_update_dismissed', WG._updateInfo.latest); } catch(e) {}
  }
};

/* ── Boot ── */
(function() {
  _initEvents();

  /* Bounce back to the dashboard canonical URL if we landed on /app.html or
   * some empty path — avoids confusing users who see the internal filename. */
  if (location.pathname === '/' || location.pathname === '/app.html') {
    history.replaceState({}, '', '/dashboard');
  }

  /* Connection status ping (unauth endpoint, just checks the proxy). */
  WG.api('/auth/csrf/').then(function(data) {
    var el = document.getElementById('topbarStatus');
    if (el) el.textContent = (data && data.csrf) ? 'Connected' : 'Disconnected';
  });

  WG.render();
})();
