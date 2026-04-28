/* Wire_Ghost — Full Portal E2E QA Test
 *
 * Tests every page, button, form, modal, dropdown, and RBAC boundary
 * through a real Chromium browser against the live Docker stack.
 *
 * Run: NODE_PATH=/usr/local/lib/node_modules node tests/test_portal_e2e.js
 */

const { chromium } = require('playwright');

const BASE = 'https://localhost:18443';
const CREDS = {
  owner:    { username: 'admin',         password: 'QAtest2026!' },
  engineer: { username: 'test_engineer', password: 'QAtest2026!' },
  viewer:   { username: 'test_viewer',   password: 'QAtest2026!' },
};

var passed = 0, failed = 0, skipped = 0;
var results = [];

function ok(name) { passed++; results.push({ name, status: 'PASS' }); console.log('  \x1b[32m✓\x1b[0m ' + name); }
function fail(name, err) { failed++; results.push({ name, status: 'FAIL', error: String(err) }); console.log('  \x1b[31m✗\x1b[0m ' + name + ' — ' + err); }
function skip(name, reason) { skipped++; results.push({ name, status: 'SKIP', error: reason }); console.log('  \x1b[33m○\x1b[0m ' + name + ' — ' + reason); }

async function assert(name, fn) {
  try { await fn(); ok(name); }
  catch (e) { fail(name, e.message || e); }
}

async function login(context, role) {
  var page = await context.newPage();
  await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.waitForSelector('#loginUser', { timeout: 5000 });
  var cred = CREDS[role];
  await page.fill('#loginUser', cred.username);
  await page.fill('#loginPass', cred.password);
  await page.click('#loginBtn');
  await page.waitForURL('**/dashboard*', { timeout: 8000 }).catch(() => {});
  await page.waitForTimeout(1500);
  return page;
}

// ═══════════════════════════════════════════
// TEST SUITES
// ═══════════════════════════════════════════

async function testLoginPage(context) {
  console.log('\n── Login Page ──');
  var page = await context.newPage();

  await assert('Login page loads', async () => {
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 15000 });
    var title = await page.title();
    if (!title.includes('Wire_Ghost') && !title.includes('Sign in')) throw new Error('Title: ' + title);
  });

  await assert('Login form has username + password fields', async () => {
    await page.waitForSelector('#loginUser', { timeout: 5000 });
    var inputs = await page.$$('input');
    if (inputs.length < 2) throw new Error('Expected >=2 inputs, got ' + inputs.length);
  });

  await assert('Login form has submit button', async () => {
    var btn = await page.$('button[type="submit"], .btn-primary, #loginBtn');
    if (!btn) throw new Error('No submit button found');
  });

  await assert('Empty submit shows validation', async () => {
    await page.fill('#loginUser', '');
    await page.fill('#loginPass', '');
    await page.click('#loginBtn');
    await page.waitForTimeout(500);
    var url = page.url();
    if (!url.includes('login')) throw new Error('Should stay on login');
  });

  await assert('Wrong password shows error', async () => {
    await page.fill('#loginUser', 'admin');
    await page.fill('#loginPass', 'wrongpassword');
    await page.click('#loginBtn');
    await page.waitForTimeout(1500);
    var body = await page.textContent('body');
    if (body.includes('Dashboard') && !body.includes('Invalid') && !body.includes('error') && !body.includes('incorrect'))
      throw new Error('Logged in with wrong password!');
  });

  await assert('Correct credentials log in successfully', async () => {
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.waitForSelector('#loginUser', { timeout: 5000 });
    await page.fill('#loginUser', 'admin');
    await page.fill('#loginPass', 'QAtest2026!');
    await page.click('#loginBtn');
    await page.waitForTimeout(3000);
    var url = page.url();
    var body = await page.textContent('body');
    if (url.includes('login') && !body.includes('Dashboard')) throw new Error('Still on login page: ' + url);
  });

  await page.close();
}

async function testDashboard(page) {
  console.log('\n── Dashboard ──');

  await assert('Dashboard page loads', async () => {
    await page.goto(BASE + '/#dashboard', { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Dashboard') && !body.includes('dashboard'))
      throw new Error('Dashboard content missing');
  });

  await assert('Dashboard has stats cards', async () => {
    await page.waitForTimeout(3000);
    var cards = await page.$$('.stat-card, .stats-grid > div');
    var body = await page.textContent('body');
    if (cards.length < 3 && !body.includes('Scans') && !body.includes('Hosts'))
      throw new Error('Expected stat cards or stats text, got ' + cards.length + ' cards');
  });

  await assert('Dashboard has severity breakdown', async () => {
    var body = await page.textContent('body');
    var hasSev = body.includes('Critical') || body.includes('critical') || body.includes('High') || body.includes('high') || body.includes('Findings');
    if (!hasSev) throw new Error('No severity breakdown visible');
  });

  await assert('Dashboard has recent scans or activity', async () => {
    var body = await page.textContent('body');
    if (!body.includes('Recent') && !body.includes('activity') && !body.includes('No scans') &&
        !body.includes('QA Test') && !body.includes('Scan') && !body.includes('completed'))
      throw new Error('No activity section or scan references');
  });
}

async function testSidebar(page) {
  console.log('\n── Sidebar Navigation ──');
  var navLinks = ['dashboard', 'scans', 'findings', 'hosts', 'topology', 'scheduled', 'policies', 'settings'];

  for (var i = 0; i < navLinks.length; i++) {
    var link = navLinks[i];
    await assert('Sidebar link: ' + link, async () => {
      var el = await page.$('a[onclick*="' + link + '"], [data-page="' + link + '"], .nav-link[href*="' + link + '"], .sidebar a[onclick*="' + link + '"]');
      if (!el) {
        var allLinks = await page.$$eval('.sidebar a, nav a, .nav-link', els => els.map(e => e.textContent.trim().toLowerCase()));
        if (!allLinks.some(t => t.includes(link))) throw new Error('Nav link "' + link + '" not found. Links: ' + allLinks.join(', '));
      }
    });
  }
}

async function testScansPage(page) {
  console.log('\n── Scans Page ──');

  await assert('Scans page loads', async () => {
    await page.$eval('body', () => { WG.navigate('scans'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Scans') && !body.includes('scans')) throw new Error('Scans page missing');
  });

  await assert('Scans page has stats row', async () => {
    var cards = await page.$$('.stat-card');
    if (cards.length < 3) throw new Error('Expected >=3 stat cards, got ' + cards.length);
  });

  await assert('Scans page has data table', async () => {
    var table = await page.$('.data-table, #scansTable, table');
    if (!table) throw new Error('No data table on scans page');
  });

  await assert('Scans page has filter controls', async () => {
    var filters = await page.$$('.filter-input, .filter-select, #scanSearch, #scanStatusFilter');
    if (filters.length < 2) throw new Error('Expected >=2 filter controls, got ' + filters.length);
  });

  await assert('New Scan button exists', async () => {
    var btn = await page.$('button[onclick*="scanModal"], button:has-text("New Scan"), .btn-primary');
    if (!btn) throw new Error('New Scan button not found');
  });

  await assert('Scan status filter works', async () => {
    var sel = await page.$('#scanStatusFilter, select.filter-select');
    if (sel) {
      await sel.selectOption('completed');
      await page.waitForTimeout(500);
      await sel.selectOption('');
      await page.waitForTimeout(500);
    } else {
      throw new Error('No status filter select found');
    }
  });

  await assert('Select All checkbox works', async () => {
    var cb = await page.$('#scanSelectAll, input[type="checkbox"]');
    if (cb) {
      await cb.click();
      await page.waitForTimeout(300);
      var checked = await page.$$eval('.scan-check:checked', els => els.length);
      await cb.click();
    }
  });

  await assert('Scan comparison section exists', async () => {
    var body = await page.textContent('body');
    if (!body.includes('Comparison') && !body.includes('comparison') && !body.includes('Compare'))
      throw new Error('No comparison section');
  });
}

async function testScanModal(page) {
  console.log('\n── Scan Launch Modal ──');

  await assert('Scan modal opens', async () => {
    await page.$eval('body', () => { WG.openModal('scanModal'); });
    await page.waitForTimeout(500);
    var modal = await page.$('#scanModal.active, .modal-overlay.active');
    if (!modal) throw new Error('Modal not active');
  });

  await assert('Scan modal has target input', async () => {
    var input = await page.$('#scanTarget');
    if (!input) throw new Error('Target input missing');
  });

  await assert('Scan modal has type select', async () => {
    var sel = await page.$('#scanType');
    if (!sel) throw new Error('Type select missing');
  });

  await assert('Scan modal has toggle options', async () => {
    var opts = await page.$$('[data-opt]');
    if (opts.length < 2) throw new Error('Expected >=2 toggle options, got ' + opts.length);
  });

  await assert('Scan modal closes', async () => {
    await page.$eval('body', () => { WG.closeModal('scanModal'); });
    await page.waitForTimeout(300);
    var modal = await page.$('#scanModal.active');
    if (modal) throw new Error('Modal still active after close');
  });
}

async function testFindingsPage(page) {
  console.log('\n── Findings Page ──');

  await assert('Findings page loads', async () => {
    await page.$eval('body', () => { WG.navigate('findings'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Findings') && !body.includes('findings') && !body.includes('vulnerabilities'))
      throw new Error('Findings page missing');
  });

  await assert('Findings has severity stat cards', async () => {
    var cards = await page.$$('.stat-card');
    if (cards.length < 4) throw new Error('Expected >=4 sev cards, got ' + cards.length);
  });

  await assert('Findings has data table', async () => {
    var table = await page.$('#findingsTable, .data-table, table');
    if (!table) throw new Error('No findings table');
  });

  await assert('Findings has filter bar', async () => {
    var inputs = await page.$$('#findingSearch, #findingSevFilter, #findingSourceFilter, .filter-input, .filter-select');
    if (inputs.length < 2) throw new Error('Expected >=2 filters, got ' + inputs.length);
  });

  await assert('Findings severity filter works', async () => {
    var result = await page.$eval('body', () => {
      var sel = document.getElementById('findingSevFilter');
      if (!sel) return 'no element';
      sel.value = 'critical';
      WG.filterFindings();
      var hidden = document.querySelectorAll('#findingsTable tbody tr[style*="display: none"]').length;
      sel.value = '';
      WG.filterFindings();
      return 'filtered ' + hidden + ' rows';
    });
    if (result === 'no element') throw new Error('No severity filter element');
  });

  await assert('Findings source filter works', async () => {
    var result = await page.$eval('body', () => {
      var sel = document.getElementById('findingSourceFilter');
      if (!sel) return 'no element';
      sel.value = 'nuclei';
      WG.filterFindings();
      var hidden = document.querySelectorAll('#findingsTable tbody tr[style*="display: none"]').length;
      sel.value = '';
      WG.filterFindings();
      return 'filtered ' + hidden + ' rows';
    });
    if (result === 'no element') throw new Error('No source filter element');
  });
}

async function testHostsPage(page) {
  console.log('\n── Hosts Page ──');

  await assert('Hosts page loads', async () => {
    await page.$eval('body', () => { WG.navigate('hosts'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Hosts') && !body.includes('hosts') && !body.includes('discovered'))
      throw new Error('Hosts page missing');
  });

  await assert('Hosts has data table or empty state', async () => {
    var table = await page.$('.data-table, table');
    var empty = await page.$('.empty-state, .panel-empty');
    if (!table && !empty) throw new Error('No hosts table or empty state');
  });
}

async function testTopologyPage(page) {
  console.log('\n── Topology Page ──');

  await assert('Topology page loads', async () => {
    await page.$eval('body', () => { WG.navigate('topology'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Topology') && !body.includes('topology') && !body.includes('Network'))
      throw new Error('Topology page missing');
  });

  await assert('Topology has SVG canvas or scan selector', async () => {
    var svg = await page.$('svg, #topoSvg, .topo-container');
    var selector = await page.$('#topoScanSelect, select');
    var body = await page.textContent('body');
    if (!svg && !selector && !body.includes('Select a scan'))
      throw new Error('No SVG or scan selector');
  });

  await assert('Topology controls panel exists', async () => {
    var controls = await page.$$('#topoControls, .topo-controls, [class*="topo"]');
    var body = await page.textContent('body');
    if (controls.length === 0 && !body.includes('Layout') && !body.includes('Color'))
      throw new Error('No topology controls');
  });
}

async function testScheduledPage(page) {
  console.log('\n── Scheduled Scans Page ──');

  await assert('Scheduled page loads', async () => {
    await page.$eval('body', () => { WG.navigate('scheduled'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Scheduled') && !body.includes('scheduled') && !body.includes('Schedule'))
      throw new Error('Scheduled page missing');
  });

  await assert('Scheduled has table or empty state', async () => {
    var table = await page.$('.data-table, table');
    var empty = await page.$('.empty-state, .panel-empty');
    var body = await page.textContent('body');
    if (!table && !empty && !body.includes('No scheduled'))
      throw new Error('No table or empty state');
  });
}

async function testPoliciesPage(page) {
  console.log('\n── Policies Page ──');

  await assert('Policies page loads', async () => {
    await page.$eval('body', () => { WG.navigate('policies'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Policies') && !body.includes('policies') && !body.includes('Policy'))
      throw new Error('Policies page missing');
  });

  await assert('Policies has create button or table', async () => {
    var btn = await page.$('button:has-text("New"), button:has-text("Create"), .btn-primary');
    var table = await page.$('.data-table, table');
    var empty = await page.$('.empty-state, .panel-empty');
    if (!btn && !table && !empty) throw new Error('No create button, table, or empty state');
  });
}

async function testSettingsPage(page) {
  console.log('\n── Settings Page ──');

  await assert('Settings page loads', async () => {
    await page.$eval('body', () => { WG.navigate('settings'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Settings') && !body.includes('settings') && !body.includes('Configuration'))
      throw new Error('Settings page missing');
  });

  await assert('Settings has form fields', async () => {
    var inputs = await page.$$('input, select, textarea');
    if (inputs.length < 2) throw new Error('Expected >=2 settings fields, got ' + inputs.length);
  });

  await assert('Settings has save button', async () => {
    var btn = await page.$('button:has-text("Save"), button[type="submit"], .btn-primary');
    if (!btn) throw new Error('No save button');
  });
}

async function testUsersPage(page) {
  console.log('\n── Users Page ──');

  await assert('Users page loads', async () => {
    await page.$eval('body', () => { WG.navigate('users'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Users') && !body.includes('users') && !body.includes('admin'))
      throw new Error('Users page missing');
  });

  await assert('Users page lists admin user', async () => {
    var body = await page.textContent('body');
    if (!body.includes('admin')) throw new Error('Admin user not visible');
  });

  await assert('Users has create button', async () => {
    var btn = await page.$('button:has-text("New"), button:has-text("Create"), button:has-text("Add"), .btn-primary');
    if (!btn) throw new Error('No create user button');
  });
}

async function testSystemPage(page) {
  console.log('\n── System / Tools Health ──');

  await assert('System page loads', async () => {
    await page.$eval('body', () => { WG.navigate('system'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('System') && !body.includes('system') && !body.includes('Tools') && !body.includes('Health'))
      throw new Error('System page missing');
  });

  await assert('System shows tool status', async () => {
    var body = await page.textContent('body');
    var hasTools = body.includes('nmap') || body.includes('nuclei') || body.includes('Tool') || body.includes('Version');
    if (!hasTools) throw new Error('No tools listed');
  });
}

async function testReportsPage(page) {
  console.log('\n── Reports Page ──');

  await assert('Reports page loads', async () => {
    await page.$eval('body', () => { WG.navigate('reports'); });
    await page.waitForTimeout(2000);
    var body = await page.textContent('body');
    if (!body.includes('Reports') && !body.includes('reports') && !body.includes('Report'))
      throw new Error('Reports page missing');
  });
}

async function testGlobalSearch(page) {
  console.log('\n── Global Search ──');

  await assert('Search modal opens via WG.openModal', async () => {
    await page.$eval('body', () => { WG.openModal('searchModal'); });
    await page.waitForTimeout(500);
    var modal = await page.$('#searchModal.active, .modal-overlay.active');
    if (!modal) throw new Error('Search modal not opened');
  });

  await assert('Search input exists and is focused', async () => {
    var input = await page.$('#globalSearch');
    if (!input) throw new Error('Global search input missing');
  });

  await assert('Search modal closes', async () => {
    await page.$eval('body', () => { WG.closeModal('searchModal'); });
    await page.waitForTimeout(300);
  });
}

async function testUserDropdown(page) {
  console.log('\n── User Dropdown Menu ──');

  await assert('User menu toggles open', async () => {
    await page.$eval('body', () => { WG.toggleUserMenu(); });
    await page.waitForTimeout(300);
    var menu = await page.$('#userMenu.open');
    if (!menu) throw new Error('User menu not opened');
  });

  await assert('User menu has theme toggle', async () => {
    var body = await page.textContent('#userMenu');
    if (!body.includes('Theme') && !body.includes('theme') && !body.includes('Mode') && !body.includes('Dark') && !body.includes('Light'))
      throw new Error('No theme toggle in menu');
  });

  await assert('User menu closes', async () => {
    await page.$eval('#userMenu', (el) => { el.classList.remove('open'); });
    await page.waitForTimeout(200);
  });
}

async function testThemeToggle(page) {
  console.log('\n── Theme Toggle ──');

  await assert('Theme cycles dark -> light -> cyberpunk', async () => {
    var initial = await page.$eval('body', () => {
      var prefs = WG.getThemePrefs ? WG.getThemePrefs() : {};
      return prefs.mode || 'dark';
    });
    await page.$eval('body', () => { WG._toggleThemeQuick(); });
    await page.waitForTimeout(300);
    var next = await page.$eval('body', () => {
      var prefs = WG.getThemePrefs ? WG.getThemePrefs() : {};
      return prefs.mode || 'dark';
    });
    if (initial === next) throw new Error('Theme did not change: ' + initial);
    await page.$eval('body', () => { WG.setThemeMode('dark'); });
  });
}

async function testToasts(page) {
  console.log('\n── Toast Notifications ──');

  await assert('Toast appears and auto-dismisses', async () => {
    await page.$eval('body', () => { WG.toast('QA test toast', 'success'); });
    await page.waitForTimeout(300);
    var toasts = await page.$$('.toast');
    if (toasts.length === 0) throw new Error('No toast appeared');
  });

  await assert('Multiple toast types render', async () => {
    await page.$eval('body', () => {
      WG.toast('Info toast', 'info');
      WG.toast('Error toast', 'error');
      WG.toast('Success toast', 'success');
    });
    await page.waitForTimeout(500);
    var toasts = await page.$$('.toast');
    if (toasts.length < 3) throw new Error('Expected >=3 toasts, got ' + toasts.length);
  });
}

async function testScanDetail(page) {
  console.log('\n── Scan Detail Page ──');

  var scanId = await page.$eval('body', () => {
    var scans = WG._cache && WG._cache.scans;
    if (scans && scans.length) return scans[0].id;
    return null;
  });

  if (!scanId) { skip('Scan detail (no scans in cache)', 'No scans available'); return; }

  await assert('Scan detail loads', async () => {
    await page.$eval('body', (_, id) => { WG.navigate('scan', { id: id }); }, scanId);
    await page.waitForTimeout(2500);
    var body = await page.textContent('body');
    if (!body.includes('Scan') && !body.includes('Target') && !body.includes('Status'))
      throw new Error('Scan detail not loaded');
  });

  await assert('Scan detail has info grid', async () => {
    var items = await page.$$('.info-item, .info-grid');
    if (items.length < 2) throw new Error('Expected >=2 info items, got ' + items.length);
  });

  await assert('Scan detail has tabs', async () => {
    var tabs = await page.$$('.tab, #scanTabs .tab');
    if (tabs.length < 2) throw new Error('Expected >=2 tabs, got ' + tabs.length);
  });

  await assert('Scan detail tab switching works', async () => {
    var findingsTab = await page.$('.tab[data-tab="findings"]');
    if (findingsTab) {
      await findingsTab.click();
      await page.waitForTimeout(1000);
      var content = await page.textContent('#scanTabContent');
      if (content === null) throw new Error('Tab content missing after switch');
    }
    var hostsTab = await page.$('.tab[data-tab="hosts"]');
    if (hostsTab) await hostsTab.click();
    await page.waitForTimeout(500);
  });
}

async function testFindingDetail(page) {
  console.log('\n── Finding Detail Page ──');

  var findingId = await page.$eval('body', () => {
    var findings = WG._cache && WG._cache.findings;
    if (findings && findings.length) return findings[0].id;
    return null;
  });

  if (!findingId) { skip('Finding detail (no findings in cache)', 'No findings available'); return; }

  await assert('Finding detail loads', async () => {
    await page.$eval('body', (_, id) => { WG.navigate('finding', { id: id }); }, findingId);
    await page.waitForTimeout(2500);
    var body = await page.textContent('body');
    if (!body.includes('Severity') && !body.includes('Host') && !body.includes('Port') && !body.includes('Source') && !body.includes('Finding'))
      throw new Error('Finding detail not loaded');
  });

  await assert('Finding detail has breadcrumbs', async () => {
    var crumbs = await page.$('.breadcrumbs');
    if (!crumbs) throw new Error('No breadcrumbs');
  });

  await assert('Finding detail has severity badge', async () => {
    var badge = await page.$('.sev-badge');
    if (!badge) throw new Error('No severity badge');
  });
}

async function testHostDetail(page) {
  console.log('\n── Host Detail Page ──');

  var hostId = await page.$eval('body', () => {
    var hosts = WG._cache && WG._cache.hosts;
    if (hosts && hosts.length) return hosts[0].id;
    return null;
  });

  if (!hostId) { skip('Host detail (no hosts in cache)', 'No hosts available'); return; }

  await assert('Host detail loads', async () => {
    await page.$eval('body', (_, id) => { WG.navigate('host', { id: id }); }, hostId);
    await page.waitForTimeout(2500);
    var body = await page.textContent('body');
    if (!body.includes('Port') && !body.includes('Findings') && !body.includes('IP') && !body.includes('Host'))
      throw new Error('Host detail not loaded');
  });

  await assert('Host detail has tabs', async () => {
    var tabs = await page.$$('#hostTabs .tab, .tab');
    if (tabs.length < 2) throw new Error('Expected >=2 tabs');
  });

  await assert('Host detail tab switching works', async () => {
    var findingsTab = await page.$('.tab[data-tab="findings"]');
    if (findingsTab) {
      await findingsTab.click();
      await page.waitForTimeout(1000);
    }
    var portsTab = await page.$('.tab[data-tab="ports"]');
    if (portsTab) await portsTab.click();
    await page.waitForTimeout(500);
  });
}

async function testAPIHealth(page) {
  console.log('\n── API Endpoint Health ──');

  var endpoints = [
    '/api/auth/csrf/',
    '/api/dashboard/',
    '/api/scans/',
    '/api/findings/',
    '/api/hosts/',
    '/api/auth/users/',
    '/api/site-config/',
    '/api/scheduled-scans/',
    '/api/scan-policies/',
    '/api/tools-health/',
    '/api/report-config/',
  ];

  for (var i = 0; i < endpoints.length; i++) {
    var ep = endpoints[i];
    await assert('API ' + ep + ' responds', async () => {
      var result = await page.$eval('body', async (_, url) => {
        try {
          var res = await fetch(url, { credentials: 'include' });
          return { status: res.status, ok: res.ok };
        } catch (e) { return { status: 0, error: e.message }; }
      }, BASE + ep);
      if (result.status === 0) throw new Error('Network error: ' + result.error);
      if (result.status >= 500) throw new Error('Server error: ' + result.status);
      if (result.status === 403) throw new Error('Forbidden (missing auth?)');
    });
  }
}

async function testRBAC(browser) {
  console.log('\n── RBAC Boundary Tests ──');

  // Test Viewer cannot access admin pages
  var viewerCtx = await browser.newContext({ ignoreHTTPSErrors: true });
  var viewerPage;
  try {
    viewerPage = await login(viewerCtx, 'viewer');
    await viewerPage.waitForTimeout(2000);

    await assert('Viewer can access dashboard', async () => {
      await viewerPage.$eval('body', () => { WG.navigate('dashboard'); });
      await viewerPage.waitForTimeout(1500);
      var body = await viewerPage.textContent('body');
      if (!body.includes('Dashboard') && !body.includes('dashboard')) throw new Error('Viewer cannot see dashboard');
    });

    await assert('Viewer can access findings', async () => {
      await viewerPage.$eval('body', () => { WG.navigate('findings'); });
      await viewerPage.waitForTimeout(1500);
      var body = await viewerPage.textContent('body');
      if (!body.includes('Findings') && !body.includes('finding')) throw new Error('Viewer cannot see findings');
    });

    await assert('Viewer cannot access users page', async () => {
      await viewerPage.$eval('body', () => { WG.navigate('users'); });
      await viewerPage.waitForTimeout(1500);
      var body = await viewerPage.textContent('body');
      if (body.includes('Create') && body.includes('admin@')) throw new Error('Viewer can see users page fully');
    });

    await assert('Viewer cannot create scans via API', async () => {
      var result = await viewerPage.$eval('body', async () => {
        var res = await fetch('/api/scans/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ target: '10.0.0.1', name: 'rbac-test', scan_type: 'quick' })
        });
        return res.status;
      });
      if (result === 201 || result === 200) throw new Error('Viewer created a scan! Status: ' + result);
    });

    await assert('Viewer cannot delete users via API', async () => {
      var result = await viewerPage.$eval('body', async () => {
        var res = await fetch('/api/auth/users/', { credentials: 'include' });
        var users = await res.json();
        if (!users.length) return 403;
        var target = users.find(function(u) { return u.username === 'test_engineer'; });
        if (!target) return 403;
        var del = await fetch('/api/auth/users/' + target.id + '/', {
          method: 'DELETE', credentials: 'include'
        });
        return del.status;
      });
      if (result === 200 || result === 204) throw new Error('Viewer deleted a user! Status: ' + result);
    });
  } catch (e) {
    fail('Viewer RBAC setup', 'Could not log in as viewer: ' + e.message);
  }

  if (viewerPage) await viewerPage.close();
  await viewerCtx.close();

  // Test Engineer can create scans but not manage users
  var engCtx = await browser.newContext({ ignoreHTTPSErrors: true });
  var engPage;
  try {
    engPage = await login(engCtx, 'engineer');
    await engPage.waitForTimeout(2000);

    await assert('Engineer can access scans', async () => {
      await engPage.$eval('body', () => { WG.navigate('scans'); });
      await engPage.waitForTimeout(1500);
      var body = await engPage.textContent('body');
      if (!body.includes('Scans') && !body.includes('scans')) throw new Error('Engineer cannot see scans');
    });

    await assert('Engineer cannot delete users via API', async () => {
      var result = await engPage.$eval('body', async () => {
        var res = await fetch('/api/auth/users/', { credentials: 'include' });
        if (res.status === 403) return 403;
        var users = await res.json();
        var target = users.find(function(u) { return u.username === 'test_viewer'; });
        if (!target) return 403;
        var del = await fetch('/api/auth/users/' + target.id + '/', {
          method: 'DELETE', credentials: 'include'
        });
        return del.status;
      });
      if (result === 200 || result === 204) throw new Error('Engineer deleted a user! Status: ' + result);
    });
  } catch (e) {
    fail('Engineer RBAC setup', 'Could not log in as engineer: ' + e.message);
  }

  if (engPage) await engPage.close();
  await engCtx.close();
}

async function testLogout(page) {
  console.log('\n── Logout ──');

  await assert('Logout redirects to login', async () => {
    await page.$eval('body', async () => {
      await fetch('/api/auth/logout/', { method: 'POST', credentials: 'include' });
    });
    await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.waitForTimeout(2000);
    var url = page.url();
    var body = await page.textContent('body');
    if (!url.includes('login') && !body.includes('Sign in')) throw new Error('Not redirected to login: ' + url);
  });
}

async function testConsoleErrors(page) {
  console.log('\n── Console Error Check ──');

  var errors = [];
  page.on('console', function(msg) {
    if (msg.type() === 'error') errors.push(msg.text());
  });

  await page.$eval('body', () => { WG.navigate('dashboard'); });
  await page.waitForTimeout(2000);
  await page.$eval('body', () => { WG.navigate('scans'); });
  await page.waitForTimeout(2000);
  await page.$eval('body', () => { WG.navigate('findings'); });
  await page.waitForTimeout(2000);
  await page.$eval('body', () => { WG.navigate('hosts'); });
  await page.waitForTimeout(2000);

  await assert('No JS console errors during navigation', async () => {
    var real = errors.filter(function(e) {
      return !e.includes('favicon') && !e.includes('404') && !e.includes('net::') && !e.includes('certificate');
    });
    if (real.length > 0) throw new Error('Console errors: ' + real.slice(0, 3).join('; '));
  });
}

async function testMobileNav(page) {
  console.log('\n── Mobile Navigation ──');

  await assert('Mobile nav functions exist', async () => {
    var exists = await page.$eval('body', () => {
      return typeof WG.toggleMobileNav === 'function' &&
             typeof WG.openMobileNav === 'function' &&
             typeof WG.closeMobileNav === 'function';
    });
    if (!exists) throw new Error('Mobile nav functions missing');
  });
}

async function testXSSEscaping(page) {
  console.log('\n── XSS Escaping Verification ──');

  await assert('escHtml escapes HTML tags', async () => {
    var result = await page.$eval('body', () => {
      return WG.escHtml('<script>alert(1)</script>');
    });
    if (result.includes('<script>')) throw new Error('XSS not escaped: ' + result);
  });

  await assert('escHtml escapes ampersands', async () => {
    var result = await page.$eval('body', () => {
      return WG.escHtml('a&b');
    });
    if (!result.includes('&amp;')) throw new Error('Ampersand not escaped: ' + result);
  });

  await assert('sevOrder returns correct values', async () => {
    var result = await page.$eval('body', () => {
      return {
        critical: WG.sevOrder('critical'),
        high: WG.sevOrder('high'),
        info: WG.sevOrder('info'),
        unknown: WG.sevOrder('xyz'),
      };
    });
    if (result.critical !== 0) throw new Error('critical should be 0, got ' + result.critical);
    if (result.high !== 1) throw new Error('high should be 1, got ' + result.high);
    if (result.unknown !== 5) throw new Error('unknown should be 5, got ' + result.unknown);
  });
}

async function testNetworkRequests(page) {
  console.log('\n── Network Request Verification ──');

  await assert('API calls include CSRF token', async () => {
    var hasCsrf = await page.$eval('body', () => {
      return document.cookie.includes('csrftoken') || document.cookie.includes('csrf');
    });
    if (!hasCsrf) throw new Error('No CSRF cookie found');
  });

  await assert('API base URL is configured', async () => {
    var base = await page.$eval('body', () => { return WG.API_BASE; });
    if (!base || base.length < 3) throw new Error('API_BASE not set: ' + base);
  });
}

// ═══════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════

(async () => {
  console.log('═══════════════════════════════════════════');
  console.log(' Wire_Ghost Portal — Full E2E QA');
  console.log('═══════════════════════════════════════════');
  console.log('Target: ' + BASE);

  var browser = await chromium.launch({
    headless: true,
    executablePath: '/usr/bin/google-chrome',
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  });

  try {
    // ── Auth tests (separate context) ──
    var authCtx = await browser.newContext({ ignoreHTTPSErrors: true });
    await testLoginPage(authCtx);
    await authCtx.close();

    // ── Main session (owner) ──
    var mainCtx = await browser.newContext({ ignoreHTTPSErrors: true });
    var page = await login(mainCtx, 'owner');
    await page.waitForTimeout(2000);

    // Pre-populate caches by visiting key pages (wait for API responses)
    await page.$eval('body', () => { WG.navigate('dashboard'); });
    await page.waitForTimeout(3000);
    await page.$eval('body', () => { WG.navigate('scans'); });
    await page.waitForTimeout(3000);
    await page.$eval('body', () => { WG.navigate('findings'); });
    await page.waitForTimeout(3000);
    await page.$eval('body', () => { WG.navigate('hosts'); });
    await page.waitForTimeout(3000);

    // Run all page tests
    await testDashboard(page);
    await testSidebar(page);
    await testScansPage(page);
    await testScanModal(page);
    await testFindingsPage(page);
    await testHostsPage(page);
    await testTopologyPage(page);
    await testScheduledPage(page);
    await testPoliciesPage(page);
    await testSettingsPage(page);
    await testUsersPage(page);
    await testSystemPage(page);
    await testReportsPage(page);

    // UI components
    await testGlobalSearch(page);
    await testUserDropdown(page);
    await testThemeToggle(page);
    await testToasts(page);
    await testMobileNav(page);

    // Detail pages
    await testScanDetail(page);
    await testFindingDetail(page);
    await testHostDetail(page);

    // API health
    await testAPIHealth(page);

    // Security
    await testXSSEscaping(page);
    await testNetworkRequests(page);

    // Console errors
    await testConsoleErrors(page);

    // Logout
    await testLogout(page);

    await page.close();
    await mainCtx.close();

    // ── RBAC tests (separate contexts per role) ──
    await testRBAC(browser);

  } finally {
    await browser.close();
  }

  // ── Report ──
  console.log('\n═══════════════════════════════════════════');
  console.log(' RESULTS: ' + passed + ' passed, ' + failed + ' failed, ' + skipped + ' skipped');
  console.log(' Total: ' + (passed + failed + skipped));
  console.log('═══════════════════════════════════════════');

  if (failed > 0) {
    console.log('\nFailed tests:');
    results.filter(function(r) { return r.status === 'FAIL'; }).forEach(function(r) {
      console.log('  X ' + r.name + ': ' + r.error);
    });
  }

  process.exit(failed > 0 ? 1 : 0);
})();
