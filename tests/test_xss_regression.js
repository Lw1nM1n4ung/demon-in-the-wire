/* Wire_Ghost — XSS Regression Tests
 *
 * Verifies that the 12-point XSS hardening (commit 6ffa339) remains intact.
 * Tests that hostile user-controlled strings are escaped via WG.escHtml()
 * rather than rendered as raw HTML.
 *
 * Run: WG_BASE=https://localhost:18443 node tests/test_xss_regression.js
 */

const { chromium } = require('playwright');
const { BASE, launchBrowser } = require('./browser_test_config');
const CREDS = { username: 'admin', password: 'QAtest2026!' };

var passed = 0, failed = 0;

function ok(name) { passed++; console.log('  \x1b[32m✓\x1b[0m ' + name); }
function fail(name, err) { failed++; console.log('  \x1b[31m✗\x1b[0m ' + name + ' — ' + err); }

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
          renderFindings: typeof wg.renderFindings,
          scanHostsTab: typeof wg._scanHostsTab,
          hostPortsTab: typeof wg._hostPortsTab,
          renderFindingDetail: typeof wg.renderFindingDetail,
          cacheType: wg._cache && typeof wg._cache,
        };
      });
      if (
        lastState.meStatus === 200
        && lastState.navigate === 'function'
        && lastState.escHtml === 'function'
        && lastState.renderFindings === 'function'
        && lastState.scanHostsTab === 'function'
        && lastState.hostPortsTab === 'function'
        && lastState.renderFindingDetail === 'function'
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

function browserEval(page, fn) {
  return page.$eval('body', fn);
}

// ═══════════════════════════════════════════
// 1. escHtml UTILITY
// ═══════════════════════════════════════════

async function testEscHtml(page) {
  console.log('\n── 1. escHtml Utility ──');

  await assert('escHtml escapes angle brackets', async () => {
    var result = await browserEval(page, () => WG.escHtml('<script>alert(1)</script>'));
    if (result.includes('<script>'))
      throw new Error('Angle brackets not escaped: ' + result);
    if (!result.includes('&lt;script&gt;'))
      throw new Error('Expected HTML entities: ' + result);
  });

  await assert('escHtml escapes double quotes', async () => {
    var result = await browserEval(page, () => WG.escHtml('" onload="alert(1)'));
    if (result.includes('"') && !result.includes('&quot;'))
      throw new Error('Quotes not escaped: ' + result);
  });

  await assert('escHtml handles null/undefined', async () => {
    var r1 = await browserEval(page, () => WG.escHtml(null));
    var r2 = await browserEval(page, () => WG.escHtml(undefined));
    var r3 = await browserEval(page, () => WG.escHtml(''));
    if (r1 !== '' || r2 !== '' || r3 !== '')
      throw new Error('Falsy input not returning empty string');
  });

  await assert('escHtml escapes ampersands', async () => {
    var result = await browserEval(page, () => WG.escHtml('a&b<c'));
    if (!result.includes('&amp;'))
      throw new Error('Ampersand not escaped: ' + result);
  });
}

// ═══════════════════════════════════════════
// 2. RENDERING FUNCTIONS USE escHtml
// ═══════════════════════════════════════════

async function testRenderersUseEscHtml(page) {
  console.log('\n── 2. Renderers Use escHtml ──');

  await assert('renderFindings escapes finding titles', async () => {
    var html = await browserEval(page, () => {
      var hostile = {
        id: 'xss-test-1', title: '<img src=x onerror=alert(1)>',
        severity: 'high', source: 'nuclei', host: '10.0.0.1',
        host_ip: '10.0.0.1', port: '80',
      };
      WG._cache.findings = [hostile];
      return WG.renderFindings();
    });
    if (html.includes('<img src=x'))
      throw new Error('Finding title not escaped — raw <img> tag in output');
  });

  await assert('_scanHostsTab escapes hostnames', async () => {
    var html = await browserEval(page, () => {
      var hostile = {
        id: 'xss-host', ip: '10.0.0.1',
        hostname: '<script>alert("xss")</script>',
        open_ports_count: 1, findings_count: 0,
      };
      return WG._scanHostsTab([hostile]);
    });
    if (html.includes('<script>alert'))
      throw new Error('Hostname not escaped — raw <script> tag in output');
  });

  await assert('_hostPortsTab escapes service names', async () => {
    var html = await browserEval(page, () => {
      var hostile = {
        number: 80, protocol: 'tcp', state: 'open',
        service_name: '<marquee>evil</marquee>',
        service_product: 'safe', service_version: '1.0',
      };
      return WG._hostPortsTab([hostile]);
    });
    if (html.includes('<marquee>'))
      throw new Error('Service name not escaped — raw <marquee> tag in output');
  });

  await assert('renderFindingDetail escapes raw nuclei output', async () => {
    var fn = await browserEval(page, () => typeof WG.renderFindingDetail);
    if (fn !== 'function') return;
    var html = await browserEval(page, () => {
      var hostile = {
        id: 'xss-raw', title: 'Test', severity: 'info',
        source: 'nuclei', host: '10.0.0.1', host_ip: '10.0.0.1',
        port: '80', raw_output: '<svg onload=alert(document.cookie)>',
        description: 'test', request: '', response: '',
        curl_command: '',
      };
      WG._cache['finding_xss-raw'] = hostile;
      return WG.renderFindingDetail('xss-raw');
    });
    if (html.includes('<svg onload'))
      throw new Error('Raw nuclei output not escaped — XSS via SVG tag');
  });

  await assert('renderFindingDetail escapes curl command', async () => {
    var fn = await browserEval(page, () => typeof WG.renderFindingDetail);
    if (fn !== 'function') return;
    var html = await browserEval(page, () => {
      var hostile = {
        id: 'xss-curl', title: 'Test', severity: 'info',
        source: 'nuclei', host: '10.0.0.1', host_ip: '10.0.0.1',
        port: '80', curl_command: '<script>alert(1)</script>',
        description: 'test', request: '', response: '',
      };
      WG._cache['finding_xss-curl'] = hostile;
      return WG.renderFindingDetail('xss-curl');
    });
    if (html.includes('<script>alert(1)</script>'))
      throw new Error('Curl command not escaped — raw script tag');
  });
}

// ═══════════════════════════════════════════
// 3. SEARCH INPUT REFLECTION
// ═══════════════════════════════════════════

async function testSearchReflection(page) {
  console.log('\n── 3. Search Input Reflection ──');

  await assert('Search input value is not reflected as raw HTML', async () => {
    var searchInput = await page.$('#globalSearch, #searchInput, [data-search]');
    if (!searchInput) return;
    if (!(await searchInput.isVisible())) return;

    await searchInput.fill('<img src=x onerror=alert(1)>');
    await page.waitForTimeout(500);

    var body = await page.$eval('body', el => el.innerHTML);
    if (body.includes('<img src=x onerror'))
      throw new Error('Search query reflected as raw HTML — XSS');
  });
}

// ═══════════════════════════════════════════
// 4. CSV EXPORT (FORMULA INJECTION)
// ═══════════════════════════════════════════

async function testCsvExport(page) {
  console.log('\n── 4. CSV Export Safety ──');

  await assert('escHtml neutralizes formula injection characters', async () => {
    var result = await browserEval(page, () => WG.escHtml('=cmd|"/C calc"|A0'));
    if (result.startsWith('='))
      throw new Error('Formula injection character not neutralized: ' + result);
  });
}

// ═══════════════════════════════════════════
// RUN
// ═══════════════════════════════════════════

(async () => {
  console.log('╔══════════════════════════════════════════╗');
  console.log('║  Wire_Ghost — XSS Regression Tests       ║');
  console.log('╚══════════════════════════════════════════╝');

  var browser = await launchBrowser(chromium);
  var context = await browser.newContext({ ignoreHTTPSErrors: true });
  var page = await context.newPage();

  try {
    console.log('\n── Login ──');
    await login(page);
    await assert('Logged in', async () => {
      if (!page.url().includes('dashboard')) throw new Error('Not on dashboard');
    });

    await testEscHtml(page);
    await testRenderersUseEscHtml(page);
    await testSearchReflection(page);
    await testCsvExport(page);

  } catch (e) {
    failed++;
    console.error('\nFATAL: ' + (e && e.stack ? e.stack : e.message || e));
  } finally {
    await browser.close();
  }

  console.log('\n══════════════════════════════════════════');
  console.log('Results: ' + passed + ' pass, ' + failed + ' fail');
  console.log('══════════════════════════════════════════');

  process.exit(failed > 0 ? 1 : 0);
})();
