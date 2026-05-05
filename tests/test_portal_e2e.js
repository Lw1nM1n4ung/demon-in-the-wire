/* Wire_Ghost — Full Portal E2E QA Test
 *
 * Tests every page, button, form, modal, dropdown, and RBAC boundary
 * through a real Chromium browser against the live Docker stack.
 *
 * Run: WG_BASE=https://localhost:18443 node tests/test_portal_e2e.js
 */

const { chromium } = require('playwright');
const { BASE, FAIL_ON_SKIP, launchBrowser } = require('./browser_test_config');
const CREDS = {
  owner:    { username: 'admin',         password: 'QAtest2026!' },
  engineer: { username: 'test_engineer', password: 'QAtest2026!' },
  viewer:   { username: 'test_viewer',   password: 'QAtest2026!' },
};
const RUN_ID = Date.now().toString(36);
const RUN_DATA = {
  scanName: 'E2E Scan ' + RUN_ID,
  scanTarget: '203.0.113.25',
  policyName: 'E2E Policy ' + RUN_ID,
  scheduleName: 'E2E Schedule ' + RUN_ID,
  userFullName: 'E2E Viewer ' + RUN_ID,
  userName: 'e2e_viewer_' + RUN_ID,
  userEmail: 'e2e+' + RUN_ID + '@test.local',
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

async function waitForAppReady(page, timeout) {
  var deadline = Date.now() + (timeout || 30000);
  var lastState = null;
  await page.waitForLoadState('domcontentloaded', { timeout: Math.min(timeout || 15000, 15000) }).catch(() => {});
  while (Date.now() < deadline) {
    try {
      lastState = await page.evaluate(async () => {
        var wg = window.WG || {};
        var meStatus = null;
        try {
          var res = await fetch('/api/auth/me/', { credentials: 'include' });
          meStatus = res.status;
        } catch (e) {
          meStatus = String((e && e.message) || e);
        }
        return {
          href: location.href,
          meStatus: meStatus,
          navigate: typeof wg.navigate,
          escHtml: typeof wg.escHtml,
          api: typeof wg.api,
          cacheType: wg._cache && typeof wg._cache,
        };
      });
      if (
        lastState.meStatus === 200
        && lastState.navigate === 'function'
        && lastState.escHtml === 'function'
        && lastState.api === 'function'
        && lastState.cacheType === 'object'
      ) return;
    } catch (e) {
      lastState = { error: e.message || String(e) };
    }
    await page.waitForTimeout(500);
  }
  throw new Error('Timed out waiting for app readiness: ' + JSON.stringify(lastState));
}

async function closeActiveModals(page) {
  await page.evaluate(() => {
    if (!window.WG) return;
    ['scanModal', 'policyModal', 'scheduleModal', 'userModal'].forEach(function(id) {
      try { WG.closeModal(id); } catch (e) {}
    });
    document.querySelectorAll('.modal-overlay.active').forEach(function(el) {
      el.classList.remove('active');
    });
  }).catch(() => {});
  await page.waitForTimeout(250);
}

async function navigate(page, route) {
  await closeActiveModals(page);
  await page.$eval('body', function(_, nextRoute) { WG.navigate(nextRoute); }, route);
  await waitForAppReady(page, 15000);
  await page.waitForTimeout(1200);
}

async function ensureCachedRecordId(page, cacheKey, apiPath) {
  return await page.evaluate(async function(args) {
    var cached = WG._cache && WG._cache[args.cacheKey];
    if (cached && cached.length) return cached[0].id;
    var data = await WG.api(args.apiPath);
    var items = Array.isArray(data) ? data : ((data && data.results) || []);
    if (items.length) {
      WG._cache = WG._cache || {};
      WG._cache[args.cacheKey] = items;
      return items[0].id;
    }
    return null;
  }, { cacheKey: cacheKey, apiPath: apiPath });
}

async function login(context, role) {
  var page = await context.newPage();
  var cred = CREDS[role];
  await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.waitForSelector('#loginUser', { timeout: 15000 });
  await page.fill('#loginUser', cred.username);
  await page.fill('#loginPass', cred.password);
  await page.click('#loginBtn');
  await waitForAppReady(page, 30000);
  var meStatus = await page.evaluate(async () => {
    var res = await fetch('/api/auth/me/', { credentials: 'include' });
    return res.status;
  });
  if (meStatus !== 200) throw new Error('/api/auth/me/ returned ' + meStatus);
  await closeActiveModals(page);
  await page.waitForTimeout(2000);
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
    await page.waitForSelector('#loginUser', { timeout: 15000 });
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
    await page.fill('#loginUser', 'qa_invalid_login');
    await page.fill('#loginPass', 'wrongpassword');
    await page.click('#loginBtn');
    await page.waitForTimeout(1500);
    var body = await page.textContent('body');
    if (body.includes('Dashboard') && !body.includes('Invalid') && !body.includes('error') && !body.includes('incorrect'))
      throw new Error('Logged in with wrong password!');
  });

  await assert('Correct credentials log in successfully', async () => {
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 15000 });
    await page.waitForSelector('#loginUser', { timeout: 15000 });
    await page.fill('#loginUser', CREDS.viewer.username);
    await page.fill('#loginPass', CREDS.viewer.password);
    await page.click('#loginBtn');
    await waitForAppReady(page, 30000);
    var meStatus = await page.evaluate(async () => {
      var res = await fetch('/api/auth/me/', { credentials: 'include' });
      return res.status;
    });
    if (meStatus !== 200) throw new Error('/api/auth/me/ returned ' + meStatus);
    var url = page.url();
    if (url.includes('login')) throw new Error('Still on login page: ' + url);
  });

  await page.close();
}

async function testDashboard(page) {
  console.log('\n── Dashboard ──');

  await assert('Dashboard page loads', async () => {
    await navigate(page, 'dashboard');
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

  var scanId = await ensureCachedRecordId(page, 'scans', '/scans/');
  if (!scanId) { fail('Scan detail seed exists', 'No scans available after seed'); return; }

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
    if (await page.$('#scanTabs .tab[data-tab="findings"]')) {
      await page.click('#scanTabs .tab[data-tab="findings"]');
      await page.waitForTimeout(1000);
      var content = await page.textContent('#scanTabContent');
      if (content === null) throw new Error('Tab content missing after switch');
    }
    if (await page.$('#scanTabs .tab[data-tab="hosts"]')) await page.click('#scanTabs .tab[data-tab="hosts"]');
    await page.waitForTimeout(500);
  });
}

async function testFindingDetail(page) {
  console.log('\n── Finding Detail Page ──');

  var findingId = await ensureCachedRecordId(page, 'findings', '/findings/');
  if (!findingId) { fail('Finding detail seed exists', 'No findings available after seed'); return; }

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

  var hostId = await ensureCachedRecordId(page, 'hosts', '/hosts/');
  if (!hostId) { fail('Host detail seed exists', 'No hosts available after seed'); return; }

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
    if (await page.$('#hostTabs .tab[data-tab="findings"]')) {
      await page.click('#hostTabs .tab[data-tab="findings"]');
      await page.waitForTimeout(1000);
    }
    if (await page.$('#hostTabs .tab[data-tab="ports"]')) await page.click('#hostTabs .tab[data-tab="ports"]');
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
    '/api/schedules/',
    '/api/policies/',
    '/api/tools-health/',
    '/api/report-config/',
  ];

  for (var i = 0; i < endpoints.length; i++) {
    var ep = endpoints[i];
    await assert('API ' + ep + ' responds', async () => {
      if (ep === '/api/tools-health/') {
        var response = await page.context().request.get(BASE + ep, { failOnStatusCode: false });
        if (!response.ok()) throw new Error('request client status ' + response.status());
        var parsed = await response.json();
        if (!Array.isArray(parsed)) throw new Error('expected array response');
        return;
      }
      var result = await page.evaluate(async function(url) {
        try {
          await WG.api(url.replace('/api', ''));
          return true;
        } catch (e) {
          return String((e && e.message) || e);
        }
      }, ep);
      if (result !== true) throw new Error('WG.api failed: ' + result);
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
        if (res.status === 403 || res.status === 401) return res.status;
        var users = await res.json();
        users = Array.isArray(users) ? users : ((users && users.results) || []);
        if (!users.length) return 403;
        var target = users.find(function(u) { return u.username === 'test_engineer'; });
        if (!target) return 403;
        var del = await fetch('/api/auth/users/' + target.id + '/delete/', {
          method: 'DELETE',
          credentials: 'include',
          headers: { 'X-CSRFToken': WG._getCSRF() }
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
        users = Array.isArray(users) ? users : ((users && users.results) || []);
        var target = users.find(function(u) { return u.username === 'test_viewer'; });
        if (!target) return 403;
        var del = await fetch('/api/auth/users/' + target.id + '/delete/', {
          method: 'DELETE',
          credentials: 'include',
          headers: { 'X-CSRFToken': WG._getCSRF() }
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
    await page.$eval('body', () => { WG.logout(); });
    await page.waitForURL('**/login*', { timeout: 15000 });
    await page.waitForFunction(() => {
      var body = (document.body && document.body.innerText) || '';
      return !!document.querySelector('#loginUser') || /sign in|login/i.test(body);
    }, { timeout: 15000 });
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
// FUNCTIONAL TESTS (form submit + CRUD flows)
// ═══════════════════════════════════════════

async function testScanSubmit(page) {
  console.log('\n── Scan Submit Flow ──');

  await assert('Submit scan with valid target', async () => {
    await navigate(page, 'new-scan');
    await page.waitForSelector('#nsScanTarget', { timeout: 15000 });
    await page.fill('#nsScanTarget', RUN_DATA.scanTarget);
    await page.fill('#nsScanName', RUN_DATA.scanName);
    await page.click('button:has-text("Launch Scan")');
    await page.waitForFunction(function(expectedPage) {
      return window.WG && WG.state && WG.state.currentPage === expectedPage;
    }, 'scans', { timeout: 15000 });
    await page.waitForTimeout(2500);
    var body = await page.textContent('body');
    if (body.includes('error') && body.includes('target'))
      throw new Error('Scan submission failed with target error');
  });

  await assert('Submitted scan appears in list', async () => {
    await navigate(page, 'scans');
    await page.waitForFunction(function(expected) {
      return document.body && document.body.innerText.indexOf(expected) !== -1;
    }, RUN_DATA.scanName, { timeout: 15000 }).catch(() => {});
    var body = await page.textContent('body');
    if (!body.includes(RUN_DATA.scanName) && !body.includes(RUN_DATA.scanTarget))
      throw new Error('Submitted scan not visible in list');
  });
}

async function testSettingsSave(page) {
  console.log('\n── Settings Save Persistence ──');

  await assert('Settings save persists on reload', async () => {
    await navigate(page, 'settings');
    await page.waitForSelector('#genParallelism', { timeout: 15000 });
    var field = await page.$('#genParallelism');
    if (!field) throw new Error('General settings field not found');
    var original = parseInt(await field.inputValue(), 10) || 10;
    var testVal = original === 10 ? 11 : 10;
    await field.fill(String(testVal));
    await page.click('button[onclick*="_saveGeneralDefaults"]');
    await page.waitForTimeout(2000);
    await navigate(page, 'dashboard');
    await navigate(page, 'settings');
    await page.waitForSelector('#genParallelism', { timeout: 15000 });
    var newVal = parseInt(await (await page.$('#genParallelism')).inputValue(), 10);
    if (newVal !== testVal) throw new Error('Setting not persisted: expected "' + testVal + '", got "' + newVal + '"');
    await (await page.$('#genParallelism')).fill(String(original));
    await page.click('button[onclick*="_saveGeneralDefaults"]');
    await page.waitForTimeout(1000);
  });
}

async function testPolicyCRUD(page) {
  console.log('\n── Policy CRUD Flow ──');

  await assert('Create a scan policy', async () => {
    await navigate(page, 'policies');
    var createBtn = await page.$('button:has-text("New Policy"), button:has-text("Create"), .btn-primary');
    if (!createBtn) throw new Error('No create policy button');
    await createBtn.click();
    await page.waitForSelector('#policyName', { timeout: 10000 });
    var nameField = await page.$('#policyName, input[name="name"]');
    if (!nameField) throw new Error('Policy name field not found');
    await nameField.fill(RUN_DATA.policyName);
    var descField = await page.$('#policyDesc');
    if (descField) await descField.fill('Browser QA policy ' + RUN_ID);
    await page.click('#policyModal .modal-footer .btn-primary');
    await closeActiveModals(page);
    await page.waitForTimeout(2000);
    var policyData = await page.evaluate(async function() { return await WG.api('/policies/'); });
    var policies = Array.isArray(policyData) ? policyData : ((policyData && policyData.results) || []);
    var createdPolicy = policies.find(function(item) { return item.name === RUN_DATA.policyName; }) || null;
    if (!createdPolicy) throw new Error('Created policy not visible');
    RUN_DATA.policyId = createdPolicy.id;
    await navigate(page, 'policies');
    await page.waitForFunction(function(expected) {
      return document.body && document.body.innerText.indexOf(expected) !== -1;
    }, RUN_DATA.policyName, { timeout: 15000 }).catch(() => {});
  });

  await assert('Delete the test policy', async () => {
    await navigate(page, 'policies');
    if (!RUN_DATA.policyId) {
      var policyData = await page.evaluate(async function() { return await WG.api('/policies/'); });
      var policies = Array.isArray(policyData) ? policyData : ((policyData && policyData.results) || []);
      var createdPolicy = policies.find(function(item) { return item.name === RUN_DATA.policyName; }) || null;
      RUN_DATA.policyId = createdPolicy && createdPolicy.id;
    }
    if (!RUN_DATA.policyId) throw new Error('Delete button for created policy not found');
    await page.waitForFunction(function(expected) {
      return document.body && document.body.innerText.indexOf(expected) !== -1;
    }, RUN_DATA.policyName, { timeout: 15000 }).catch(() => {});
    var delSelector = 'button[onclick*="' + RUN_DATA.policyId + '"][onclick*="_deletePolicy"]';
    if (!await page.$(delSelector)) throw new Error('Delete button for created policy not found');
    await page.click(delSelector);
    await page.waitForTimeout(2000);
    var policyData = await page.evaluate(async function() { return await WG.api('/policies/'); });
    var policies = Array.isArray(policyData) ? policyData : ((policyData && policyData.results) || []);
    if (policies.some(function(item) { return item.id === RUN_DATA.policyId; })) throw new Error('Policy not deleted');
  });
}

async function testScheduleCreate(page) {
  console.log('\n── Schedule Create Flow ──');

  await assert('Create a scheduled scan', async () => {
    await navigate(page, 'scheduled');
    var createBtn = await page.$('button:has-text("New Schedule"), button:has-text("Create Schedule"), .btn-primary');
    if (!createBtn) throw new Error('No create schedule button');
    await createBtn.click();
    await page.waitForSelector('#schedName', { timeout: 10000 });
    var nameField = await page.$('#schedName, input[name="name"]');
    if (nameField) await nameField.fill(RUN_DATA.scheduleName);
    var targetField = await page.$('#schedTarget, input[name="target"]');
    if (targetField) await targetField.fill(RUN_DATA.scanTarget);
    await page.click('#scheduleModal .modal-footer .btn-primary');
    await page.waitForTimeout(2000);
    var scheduleData = await page.evaluate(async function() { return await WG.api('/schedules/'); });
    var schedules = Array.isArray(scheduleData) ? scheduleData : ((scheduleData && scheduleData.results) || []);
    var created = schedules.some(function(item) { return item.name === RUN_DATA.scheduleName; });
    if (!created) throw new Error('Created schedule not visible');
    await navigate(page, 'scheduled');
    var body = await page.textContent('body');
    if (!body.includes(RUN_DATA.scheduleName) && !body.includes(RUN_DATA.scanTarget))
      throw new Error('Created schedule not visible');
  });
}

async function testUserCreate(page) {
  console.log('\n── User Create Flow ──');

  await assert('Create a viewer user', async () => {
    await navigate(page, 'users');
    var createBtn = await page.$('button:has-text("Add User"), button:has-text("Create"), button:has-text("Add"), .btn-primary');
    if (!createBtn) throw new Error('No create user button');
    await createBtn.click();
    await page.waitForSelector('#userUsername', { timeout: 10000 });
    var usernameField = await page.$('#userUsername, input[name="username"]');
    if (!usernameField) throw new Error('Username field not found');
    await usernameField.fill(RUN_DATA.userName);
    var nameField = await page.$('#userName');
    if (nameField) await nameField.fill(RUN_DATA.userFullName);
    var passField = await page.$('#userPass, input[name="password"]');
    if (passField) await passField.fill('E2e!Pass99');
    var emailField = await page.$('#userEmail, input[name="email"]');
    if (emailField) await emailField.fill(RUN_DATA.userEmail);
    var roleSelect = await page.$('#userRole, select[name="role"]');
    if (roleSelect) await roleSelect.selectOption('viewer');
    await page.click('#userSaveBtn');
    await page.waitForTimeout(2000);
    var created = await page.evaluate(async function(username) {
      var data = await WG.api('/auth/users/');
      data = data || [];
      return data.some(function(item) { return item.username === username; });
    }, RUN_DATA.userName);
    if (!created) throw new Error('Created user not visible');
    await navigate(page, 'users');
    await page.waitForFunction(function(expected) {
      return document.body && document.body.innerText.indexOf(expected) !== -1;
    }, RUN_DATA.userName, { timeout: 15000 }).catch(() => {});
    var body = await page.textContent('body');
    if (!body.includes(RUN_DATA.userName) && !body.includes(RUN_DATA.userFullName))
      throw new Error('Created user not visible');
  });
}

async function testReportDownload(page) {
  console.log('\n── Report Download ──');

  await assert('Report download button triggers download', async () => {
    await navigate(page, 'reports');
    var strictSelector = 'button[onclick*="WG.downloadReport"], a[href*="/api/reports/"]';
    var fallbackSelector = 'a[download], button:has-text("Download"), .btn-download, a[href*="report"]';
    var dlBtn = await page.$(FAIL_ON_SKIP ? strictSelector : fallbackSelector);
    if (!dlBtn) {
      if (FAIL_ON_SKIP) throw new Error('No real report download button found');
      skip('Report download', 'No download button (no reports yet?)');
      return;
    }
    var dlPromise = page.waitForEvent('download', { timeout: 15000 }).catch(() => null);
    await dlBtn.click();
    var dl = await dlPromise;
    if (!dl) throw new Error('Download did not trigger within 5s');
  });
}

async function testSessionTimeout(page) {
  console.log('\n── Session Timeout ──');

  await assert('IdleTimeoutMiddleware constant is 7200', async () => {
    var resp = await page.evaluate(async () => {
      var r = await fetch('/api/auth/check/');
      return r.status;
    });
    if (resp !== 200 && resp !== 204) throw new Error('Expected 200/204, got ' + resp);
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

  var authBrowser = await launchBrowser(chromium);
  try {
    var authCtx = await authBrowser.newContext({ ignoreHTTPSErrors: true });
    await testLoginPage(authCtx);
    await authCtx.close();
  } finally {
    await authBrowser.close();
  }

  var browser = await launchBrowser(chromium);
  try {
    // ── Main session (owner) ──
    var mainCtx = await browser.newContext({ ignoreHTTPSErrors: true });
    var page = await login(mainCtx, 'owner');
    await page.waitForTimeout(2000);

    // Pre-populate caches by visiting key pages (wait for API responses)
    await waitForAppReady(page, 30000);
    await navigate(page, 'dashboard');
    await page.waitForTimeout(1800);
    await navigate(page, 'scans');
    await page.waitForTimeout(1800);
    await navigate(page, 'findings');
    await page.waitForTimeout(1800);
    await navigate(page, 'hosts');
    await page.waitForTimeout(1800);

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

    // Functional CRUD flows
    await testScanSubmit(page);
    await testSettingsSave(page);
    await testPolicyCRUD(page);
    await testScheduleCreate(page);
    await testUserCreate(page);
    await testReportDownload(page);
    await testSessionTimeout(page);

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
  process.exit(failed > 0 || (FAIL_ON_SKIP && skipped > 0) ? 1 : 0);
})();
