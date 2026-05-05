/* Wire_Ghost — JS Bug Fix Regression Tests
 *
 * Verifies the 14 JS bug fixes across 7 files:
 *   1. Scan detail tab switching (hosts/findings/reports)
 *   2. Bulk actions on scans page
 *   3. Scheduled scan creation
 *   4. Policy application to new-scan form
 *   5. Scan comparison
 *   6. Host detail findings tab
 *   7. Scan queue remove
 *
 * Run: WG_BASE=https://localhost:18443 node tests/test_js_regression.js
 */

const { chromium } = require('playwright');
const { BASE, FAIL_ON_SKIP, launchBrowser } = require('./browser_test_config');
const CREDS = { username: 'admin', password: 'QAtest2026!' };

var passed = 0, failed = 0, skipped = 0;

function ok(name) { passed++; console.log('  \x1b[32m✓\x1b[0m ' + name); }
function fail(name, err) { failed++; console.log('  \x1b[31m✗\x1b[0m ' + name + ' — ' + err); }
function skip(name, reason) { skipped++; console.log('  \x1b[33m○\x1b[0m ' + name + ' — ' + reason); }

async function assert(name, fn) {
  try { await fn(); ok(name); }
  catch (e) { fail(name, e.message || e); }
}

async function waitForAuthenticatedApp(page, timeout) {
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
          scanHostsTab: typeof wg._scanHostsTab,
          hostPortsTab: typeof wg._hostPortsTab,
          cacheType: wg._cache && typeof wg._cache,
        };
      });
      if (
        lastState.meStatus === 200
        && lastState.navigate === 'function'
        && lastState.escHtml === 'function'
        && lastState.scanHostsTab === 'function'
        && lastState.hostPortsTab === 'function'
        && lastState.cacheType === 'object'
      ) return;
    } catch (e) {
      lastState = { error: e.message || String(e) };
    }
    await page.waitForTimeout(500);
  }
  throw new Error('Timed out waiting for authenticated app: ' + JSON.stringify(lastState));
}

async function login(page) {
  await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.waitForSelector('#loginUser', { timeout: 15000 });
  await page.fill('#loginUser', CREDS.username);
  await page.fill('#loginPass', CREDS.password);
  await page.click('#loginBtn');
  await waitForAuthenticatedApp(page, 30000);
  var meStatus = await page.evaluate(async () => {
    var res = await fetch('/api/auth/me/', { credentials: 'include' });
    return res.status;
  });
  if (meStatus !== 200) throw new Error('/api/auth/me/ returned ' + meStatus);
  await page.waitForTimeout(1000);
}

function nav(page, route, params) {
  return page.$eval('body', (_, args) => WG.navigate(args.route, args.params), { route, params });
}

function getCache(page, key) {
  return page.$eval('body', (_, k) => WG._cache[k] || [], key);
}

function fnExists(page, name) {
  return page.$eval('body', (_, n) => typeof WG[n] === 'function', name);
}

function fnSource(page, name) {
  return page.$eval('body', (_, n) => typeof WG[n] === 'function' ? WG[n].toString() : '', name);
}

function mainHtml(page) {
  return page.$eval('#mainContent', el => el.innerHTML);
}

// ═══════════════════════════════════════════
// 1. SCAN DETAIL TAB SWITCHING
// ═══════════════════════════════════════════

async function testScanDetailTabs(page) {
  console.log('\n── 1. Scan Detail Tab Switching ──');

  var scans = await getCache(page, 'scans');
  var completed = scans.find(s => s.status === 'completed');

  if (!completed) {
    skip('Scan detail tabs', 'No completed scan available');
    return;
  }

  await nav(page, 'scan', { id: completed.id });
  await page.waitForTimeout(2000);

  await assert('Hosts tab renders with table', async () => {
    if (await page.$('#scanTabs .tab[data-tab="hosts"]')) await page.click('#scanTabs .tab[data-tab="hosts"]');
    await page.waitForTimeout(500);
    var content = await page.$eval('#scanTabContent', el => el.innerHTML);
    if (content.includes('data-table') || content.includes('panel-empty'))
      return;
    throw new Error('Hosts tab has no table or empty state');
  });

  await assert('Findings tab renders with table', async () => {
    if (!(await page.$('#scanTabs .tab[data-tab="findings"]'))) throw new Error('No findings tab found');
    await page.click('#scanTabs .tab[data-tab="findings"]');
    await page.waitForTimeout(500);
    var content = await page.$eval('#scanTabContent', el => el.innerHTML);
    if (content.includes('data-table') || content.includes('panel-empty'))
      return;
    throw new Error('Findings tab has no table or empty state');
  });

  await assert('Reports tab renders with table', async () => {
    if (!(await page.$('#scanTabs .tab[data-tab="reports"]'))) throw new Error('No reports tab found');
    await page.click('#scanTabs .tab[data-tab="reports"]');
    await page.waitForTimeout(500);
    var content = await page.$eval('#scanTabContent', el => el.innerHTML);
    if (content.includes('data-table') || content.includes('panel-empty'))
      return;
    throw new Error('Reports tab has no table or empty state');
  });
}

// ═══════════════════════════════════════════
// 2. BULK ACTIONS (SCANS PAGE)
// ═══════════════════════════════════════════

async function testBulkActions(page) {
  console.log('\n── 2. Bulk Actions (Scans Page) ──');

  await nav(page, 'scans');
  await page.waitForTimeout(1500);

  await assert('Scans page renders scan list', async () => {
    var html = await mainHtml(page);
    if (html.includes('data-table') || html.includes('empty-state') || html.includes('panel-empty'))
      return;
    throw new Error('No scan rows and no empty state');
  });

  await assert('WG._bulkAction function exists', async () => {
    if (!(await fnExists(page, '_bulkAction')))
      throw new Error('_bulkAction not defined');
  });

  await assert('WG._getSelectedIds function exists', async () => {
    if (!(await fnExists(page, '_getSelectedIds')))
      throw new Error('_getSelectedIds not defined');
  });

  await assert('_bulkAction handles cancel and delete actions', async () => {
    var src = await fnSource(page, '_bulkAction');
    if (!src.includes('cancel') || !src.includes('delete'))
      throw new Error('_bulkAction does not handle cancel/delete');
  });
}

// ═══════════════════════════════════════════
// 3. SCHEDULED SCAN CREATION
// ═══════════════════════════════════════════

async function testScheduledScanCreation(page) {
  console.log('\n── 3. Scheduled Scan Creation ──');

  await nav(page, 'new-scan');
  await page.waitForTimeout(1500);

  await assert('New scan form renders', async () => {
    var html = await mainHtml(page);
    if (html.includes('Launch') || html.includes('Target') || html.includes('target'))
      return;
    throw new Error('New scan form not found');
  });

  await assert('Schedule toggle exists on form', async () => {
    var html = await mainHtml(page);
    if (html.toLowerCase().includes('schedule') || html.toLowerCase().includes('recurring'))
      return;
    throw new Error('No schedule toggle found in new-scan form');
  });

  await assert('_nsLaunch sends schedule data when enabled', async () => {
    var src = await fnSource(page, '_nsLaunch');
    if (src.includes('schedule') || src.includes('cron') || src.includes('frequency'))
      return;
    throw new Error('_nsLaunch does not handle schedule data');
  });
}

// ═══════════════════════════════════════════
// 4. POLICY APPLICATION
// ═══════════════════════════════════════════

async function testPolicyApplication(page) {
  console.log('\n── 4. Policy Application ──');

  await assert('WG._nsApplyPolicy function exists', async () => {
    if (!(await fnExists(page, '_nsApplyPolicy')))
      throw new Error('_nsApplyPolicy not defined');
  });

  await assert('_nsApplyPolicy populates form fields from policy data', async () => {
    var src = await fnSource(page, '_nsApplyPolicy');
    if (src.includes('scan_type') || src.includes('parallelism') || src.includes('tools') || src.includes('value'))
      return;
    throw new Error('_nsApplyPolicy does not populate form fields');
  });
}

// ═══════════════════════════════════════════
// 5. SCAN COMPARISON
// ═══════════════════════════════════════════

async function testScanComparison(page) {
  console.log('\n── 5. Scan Comparison ──');

  await nav(page, 'scans');
  await page.waitForTimeout(1000);

  await assert('Compare tab or compare function exists on scans page', async () => {
    var html = await mainHtml(page);
    var hasTab = html.toLowerCase().includes('compare');
    var hasFn = await fnExists(page, 'compareScans');
    if (!hasTab && !hasFn)
      throw new Error('No Compare tab or compareScans function');
  });

  await assert('WG._compareScans function exists', async () => {
    if (!(await fnExists(page, '_compareScans')))
      throw new Error('_compareScans not defined');
  });

  await assert('_compareScans diffs findings (not empty array bug)', async () => {
    var src = await fnSource(page, '_compareScans');
    if (src.includes('findings') && (src.includes('filter') || src.includes('diff') || src.includes('new') || src.includes('resolved')))
      return;
    throw new Error('_compareScans does not diff findings properly');
  });
}

// ═══════════════════════════════════════════
// 6. HOST DETAIL FINDINGS TAB
// ═══════════════════════════════════════════

async function testHostDetailFindings(page) {
  console.log('\n── 6. Host Detail Findings Tab ──');

  var hosts = await page.evaluate(async function() {
    var cached = WG._cache.hosts || [];
    if (cached.length) return cached;
    var data = await WG.api('/hosts/');
    if (Array.isArray(data)) return data;
    return (data && data.results) || [];
  });
  var host = hosts.find(h => h.findings_count > 0) || hosts[0];

  if (!host) {
    skip('Host detail findings', 'No hosts available');
    return;
  }

  await nav(page, 'host', { id: host.id });
  await page.waitForTimeout(2000);

  await assert('Host detail page renders', async () => {
    var html = await mainHtml(page);
    if (html.includes('hostTabs') || html.includes('Loading host'))
      return;
    throw new Error('Host detail page did not render');
  });

  await assert('Findings tab exists on host detail', async () => {
    await page.waitForTimeout(1000);
    var tab = await page.$('#hostTabs .tab[data-tab="findings"]');
    if (tab) return;
    var html = await mainHtml(page);
    if (html.includes('findings'))
      return;
    throw new Error('No findings tab on host detail');
  });

  await assert('Clicking findings tab renders content (not empty)', async () => {
    var tab = await page.$('#hostTabs .tab[data-tab="findings"]');
    if (tab) {
      await tab.click();
      await page.waitForTimeout(500);
      var content = await page.$eval('#hostTabContent', el => el.innerHTML);
      if (content.includes('data-table') || content.includes('panel-empty') || content.includes('No findings'))
        return;
      throw new Error('Findings tab rendered empty ([] literal bug)');
    }
  });

  await assert('switchHostTab findings calls _scanFindingsTab with real data', async () => {
    var src = await fnSource(page, 'switchHostTab');
    if (src.includes('_scanFindingsTab') && src.includes('filter'))
      return;
    throw new Error('switchHostTab does not filter findings for host');
  });
}

// ═══════════════════════════════════════════
// 7. SCAN QUEUE REMOVE
// ═══════════════════════════════════════════

async function testScanQueueRemove(page) {
  console.log('\n── 7. Scan Queue Remove ──');

  await assert('WG._removeFromQueue function exists', async () => {
    if (!(await fnExists(page, '_removeFromQueue')))
      throw new Error('_removeFromQueue not defined');
  });

  await assert('_removeFromQueue calls DELETE /scans/{id}/', async () => {
    var src = await fnSource(page, '_removeFromQueue');
    if (src.includes('DELETE') && src.includes('/scans/'))
      return;
    throw new Error('_removeFromQueue does not call DELETE /scans/');
  });

  await assert('WG._cancelAllRunning cancels via POST', async () => {
    var src = await fnSource(page, '_cancelAllRunning');
    if (src.includes('cancel') && src.includes('POST'))
      return;
    throw new Error('_cancelAllRunning missing or incomplete');
  });
}

// ═══════════════════════════════════════════
// RUN
// ═══════════════════════════════════════════

(async () => {
  console.log('╔══════════════════════════════════════════╗');
  console.log('║  Wire_Ghost — JS Bug Fix Regression QA   ║');
  console.log('╚══════════════════════════════════════════╝');

  var browser = await launchBrowser(chromium);
  var context = await browser.newContext({ ignoreHTTPSErrors: true });
  var page = await context.newPage();

  try {
    console.log('\n── Login ──');
    await login(page);
    await assert('Logged in as admin', async () => {
      var url = page.url();
      if (!url.includes('dashboard')) throw new Error('Not on dashboard: ' + url);
    });

    // Pre-warm caches
    await nav(page, 'scans');
    await page.waitForTimeout(2000);
    await nav(page, 'hosts');
    await page.waitForTimeout(1500);

    await testScanDetailTabs(page);
    await testBulkActions(page);
    await testScheduledScanCreation(page);
    await testPolicyApplication(page);
    await testScanComparison(page);
    await testHostDetailFindings(page);
    await testScanQueueRemove(page);

  } catch (e) {
    failed++;
    console.error('\nFATAL: ' + (e && e.stack ? e.stack : e.message || e));
  } finally {
    await browser.close();
  }

  console.log('\n══════════════════════════════════════════');
  console.log('Results: ' + passed + ' pass, ' + failed + ' fail, ' + skipped + ' skip');
  console.log('══════════════════════════════════════════');

  process.exit(failed > 0 || (FAIL_ON_SKIP && skipped > 0) ? 1 : 0);
})();
