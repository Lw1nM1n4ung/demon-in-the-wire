/* Wire_Ghost — Router & initialization */

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
    if (data && data.csrf) {
      WG.USE_MOCK = false;
      if (el) el.textContent = 'API Connected';
    } else {
      if (el) el.textContent = 'Demo Mode';
    }
  });

  // Check setup state from server
  if (WG.checkSetupFromServer) WG.checkSetupFromServer();

  // Initial render
  WG.render();
})();
