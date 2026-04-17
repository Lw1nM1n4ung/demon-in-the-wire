/* Wire_Ghost — Router & initialization */

/* Pages allowed for each role. Owner has access to everything. */
WG._VIEWER_PAGES = { dashboard: 1, findings: 1, finding: 1, settings: 1, login: 1, setup: 1 };
WG._ENGINEER_BLOCKED = { users: 1 };

WG._canVisit = function(page) {
  var user = WG.currentUser && WG.currentUser();
  var role = (user && user.role) || '';
  if (role === 'owner') return true;
  if (role === 'engineer') return !WG._ENGINEER_BLOCKED[page];
  // Viewer (or unknown): whitelist
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

WG.navigate = function(page, params) {
  params = params || {};
  var hash = params.id ? '#' + page + '/' + params.id : '#' + page;
  window.location.hash = hash;
};

WG.parseHash = function() {
  var hash = window.location.hash.slice(1) || 'dashboard';
  var parts = hash.split('/');
  return { page: parts[0], id: parts[1] || null };
};

WG.render = function() {
  var route = WG.parseHash();

  // Setup gate: redirect to setup wizard on first install
  if (!WG.isSetupComplete() && route.page !== 'setup') {
    window.location.hash = '#setup';
    return;
  }

  // Setup page renders without app shell
  if (route.page === 'setup') {
    document.querySelector('.app').style.display = 'none';
    var loginContainer = document.getElementById('loginContainer');
    loginContainer.style.display = 'block';
    loginContainer.innerHTML = WG.renderSetup();
    return;
  }

  // Auth gate: redirect to login if not authenticated
  if (!WG.isLoggedIn() && route.page !== 'login') {
    window.location.hash = '#login';
    return;
  }

  // If logged in but on login page, redirect to dashboard
  if (WG.isLoggedIn() && route.page === 'login') {
    window.location.hash = '#dashboard';
    return;
  }

  // Role-based page gate: silently redirect to dashboard if role can't visit this page.
  if (WG.isLoggedIn() && !WG._canVisit(route.page)) {
    window.location.hash = '#dashboard';
    return;
  }

  WG.state.currentPage = route.page;

  // Login page renders without app shell
  if (route.page === 'login') {
    document.querySelector('.app').style.display = 'none';
    var loginContainer = document.getElementById('loginContainer');
    loginContainer.style.display = 'block';
    loginContainer.innerHTML = WG.renderLogin();
    // Bind enter key on login inputs
    setTimeout(function() {
      var passField = document.getElementById('loginPass');
      var userField = document.getElementById('loginUser');
      if (passField) passField.addEventListener('keydown', function(e) { if (e.key === 'Enter') WG.handleLogin(); });
      if (userField) userField.addEventListener('keydown', function(e) { if (e.key === 'Enter') document.getElementById('loginPass').focus(); });
    }, 50);
    return;
  }

  // Show app shell, hide login
  document.querySelector('.app').style.display = '';
  document.getElementById('loginContainer').style.display = 'none';

  // Load preferences from server on first render after login
  if (!WG._prefsLoaded && WG.loadPrefsFromServer) {
    WG._prefsLoaded = true;
    WG.loadPrefsFromServer();

    // Push any pending setup branding to API (saved during setup before login)
    var pendingBranding = localStorage.getItem('wg_setup_branding');
    if (pendingBranding) {
      WG.api('/report-config/', { method: 'PUT', body: pendingBranding });
      localStorage.removeItem('wg_setup_branding');
    }
  }

  // Update topbar with current user
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

  // Apply role-based sidebar visibility (hide nav items the user isn't allowed to see).
  WG._applySidebarRole();

  // Update sidebar active state
  document.querySelectorAll('.sidebar-item[data-page]').forEach(function(el) {
    el.classList.toggle('active', el.dataset.page === route.page);
  });

  var pages = {
    dashboard: WG.renderDashboard,
    scans: WG.renderScans,
    scan: function() { return WG.renderScanDetail(route.id); },
    findings: WG.renderFindings,
    hosts: WG.renderHosts,
    topology: function() { return WG.renderTopology(route.id); },
    host: function() { return WG.renderHostDetail(route.id); },
    finding: function() { return WG.renderFindingDetail(route.id); },
    policies: WG.renderPolicies,
    'new-scan': WG.renderNewScan,
    'scan-queue': WG.renderScanQueue,
    scheduled: WG.renderScheduled,
    reports: WG.renderReports,
    'report-builder': WG.renderReportBuilder,
    settings: WG.renderSettings,
    users: WG.renderUsers,
  };

  var renderFn = pages[route.page] || WG.renderDashboard;
  var main = document.getElementById('mainContent');

  // Destroy any lingering Chart.js instances from the previous page so the
  // canvas nodes are garbage-collected with the replaced DOM.
  if (WG._destroyCharts) WG._destroyCharts();

  // Smooth page transition
  main.style.animation = 'none';
  main.offsetHeight; // force reflow
  main.style.animation = '';
  main.innerHTML = renderFn();
  main.scrollTop = 0;
};

/* ── Event binding ── */
function _initEvents() {
  // Sidebar nav
  document.querySelectorAll('.sidebar-item[data-page]').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.preventDefault();
      WG.navigate(el.dataset.page);
    });
  });

  // Sidebar actions
  document.querySelectorAll('.sidebar-item[data-action]').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.preventDefault();
      if (el.dataset.action === 'newScan') WG.openModal('scanModal');
      if (el.dataset.action === 'logout') WG.logout();
    });
  });

  // Modal backdrop close
  document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) WG.closeModal(overlay.id);
    });
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.active').forEach(function(m) { WG.closeModal(m.id); });
    }
    if (e.key === '/' && !e.target.matches('input,textarea,select')) {
      e.preventDefault();
      if (WG.isLoggedIn()) WG.openModal('searchModal');
    }
  });

  // Hash change
  window.addEventListener('hashchange', WG.render);
}

/* ── Boot ── */
(function() {
  _initEvents();

  // Check API connectivity (use unauthenticated endpoint)
  WG.api('/auth/csrf/').then(function(data) {
    var el = document.getElementById('topbarStatus');
    if (el) el.textContent = (data && data.csrf) ? 'Connected' : 'Disconnected';
  });

  // Check setup state from server
  if (WG.checkSetupFromServer) WG.checkSetupFromServer();

  // Initial render
  WG.render();
})();
