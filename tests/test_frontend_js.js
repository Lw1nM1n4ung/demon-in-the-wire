/**
 * Node.js tests for Wire_Ghost frontend pure-logic functions.
 * Covers: utils.js, router.js, auth.js, api.js (cache), scheduled.js, new-scan.js
 * Uses vm.runInContext to load browser-targeted JS in a sandboxed environment.
 * Run: node tests/test_frontend_js.js
 */

'use strict';

const vm = require('vm');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const JS_DIR = path.join(__dirname, '..', 'web', 'js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  \x1b[32m✓\x1b[0m ' + name);
  } catch (e) {
    failed++;
    console.log('  \x1b[31m✗\x1b[0m ' + name);
    console.log('    ' + e.message);
  }
}

function buildSandbox() {
  /* localStorage stub with backing store */
  var _store = {};
  var localStorageStub = {
    getItem: function(k) { return _store.hasOwnProperty(k) ? _store[k] : null; },
    setItem: function(k, v) { _store[k] = String(v); },
    removeItem: function(k) { delete _store[k]; },
    clear: function() { _store = {}; },
    _store: _store,
  };

  /* Element registry for getElementById */
  var _elements = {};
  function makeElement(id) {
    return {
      id: id,
      _textContent: '',
      _innerHTML: '',
      _classes: [],
      style: {},
      children: [],
      get textContent() { return this._textContent; },
      set textContent(v) {
        this._textContent = String(v);
        /* Emulate innerHTML escaping from textContent */
        this._innerHTML = String(v)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      },
      get innerHTML() { return this._innerHTML; },
      set innerHTML(v) { this._innerHTML = v; },
      appendChild: function(child) { this.children.push(child); },
      setAttribute: function() {},
      getAttribute: function(attr) { return null; },
      getBoundingClientRect: function() { return { right: 0, bottom: 0 }; },
      remove: function() {},
      classList: {
        _set: new Set(),
        add: function(c) { this._set.add(c); },
        remove: function(c) { this._set.delete(c); },
        toggle: function(c, force) {
          if (force === undefined) {
            if (this._set.has(c)) this._set.delete(c);
            else this._set.add(c);
          } else if (force) this._set.add(c);
          else this._set.delete(c);
        },
        contains: function(c) { return this._set.has(c); },
      },
      focus: function() {},
      dataset: {},
      scrollTop: 0,
      offsetHeight: 0,
      insertAdjacentHTML: function() {},
    };
  }

  var sandbox = {
    /* Wire window.WG and WG to the same object. state.js does window.WG = window.WG || {} */
    window: {},
    document: {
      getElementById: function(id) {
        if (!_elements[id]) _elements[id] = makeElement(id);
        return _elements[id];
      },
      createElement: function(tag) { return makeElement('_anon_' + tag); },
      body: { appendChild: function() {}, style: {} },
      addEventListener: function() {},
      removeEventListener: function() {},
      querySelectorAll: function() { return { forEach: function() {} }; },
      querySelector: function() { return null; },
      fullscreenElement: null,
      cookie: '',
    },
    localStorage: localStorageStub,
    location: { pathname: '/dashboard', href: '' },
    history: { pushState: function() {}, replaceState: function() {} },
    navigator: { clipboard: { writeText: function() { return { then: function(cb) { if (cb) cb(); } }; } } },
    addEventListener: function() {},
    removeEventListener: function() {},
    confirm: function() { return false; },
    setTimeout: function(fn) { if (typeof fn === 'function') fn(); return 1; },
    clearTimeout: function() {},
    setInterval: function() { return 1; },
    clearInterval: function() {},
    fetch: function() {
      return {
        then: function(cb) {
          return { catch: function() { return { then: function() {} }; } };
        },
        catch: function() { return { then: function() {} }; },
      };
    },
    console: console,
    Object: Object,
    Math: Math,
    Array: Array,
    String: String,
    Number: Number,
    RegExp: RegExp,
    JSON: JSON,
    URL: URL,
    Date: Date,
    Error: Error,
    Set: Set,
    Map: Map,
    Promise: {
      resolve: function(v) { return { then: function(cb) { var r = cb(v); return { then: function(cb2) { if (cb2) cb2(r); return { catch: function() {} }; }, catch: function() {} }; }, catch: function() {} }; },
      reject: function(e) { return { then: function() { return { catch: function(cb) { cb(e); } }; }, catch: function(cb) { cb(e); } }; },
    },
    parseInt: parseInt,
    parseFloat: parseFloat,
    isNaN: isNaN,
    isFinite: isFinite,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    btoa: function(s) { return Buffer.from(s).toString('base64'); },
    unescape: unescape,
    /* _elements exposed for test manipulation */
    _elements: _elements,
    _localStore: _store,
  };

  /* Make window self-referential so state.js's `window.WG = window.WG || {}` works,
   * and `window.location` / `window.addEventListener` are reachable. */
  sandbox.window = sandbox;

  return sandbox;
}

function loadFile(ctx, filePath, filename) {
  var code = fs.readFileSync(filePath, 'utf8');
  vm.runInContext(code, ctx, { filename: filename || path.basename(filePath) });
}

/* ────────────────────────────────────────
 * Build context and load modules in dependency order
 * ──────────────────────────────────────── */
var sandbox = buildSandbox();
var ctx = vm.createContext(sandbox);

/* state.js first — sets window.WG = {} and WG.API_BASE */
loadFile(ctx, path.join(JS_DIR, 'public', 'state.js'), 'state.js');

/* api.js — sets WG.api, WG._cache, WG.getCached, WG.invalidateCache */
loadFile(ctx, path.join(JS_DIR, 'public', 'api.js'), 'api.js');

/* auth.js — sets WG.getSession, WG.setSession, etc. */
loadFile(ctx, path.join(JS_DIR, 'app', 'auth.js'), 'auth.js');

/* utils.js — sets WG.escHtml, WG.timeAgo, etc. */
loadFile(ctx, path.join(JS_DIR, 'app', 'utils.js'), 'utils.js');

/* Stub out render-related functions that router.js IIFE calls */
sandbox.WG.renderDashboard = function() { return ''; };
sandbox.WG.renderScans = function() { return ''; };
sandbox.WG.renderScanDetail = function() { return ''; };
sandbox.WG.renderFindings = function() { return ''; };
sandbox.WG.renderHosts = function() { return ''; };
sandbox.WG.renderTopology = function() { return ''; };
sandbox.WG.renderHostDetail = function() { return ''; };
sandbox.WG.renderFindingDetail = function() { return ''; };
sandbox.WG.renderPolicies = function() { return ''; };
sandbox.WG.renderNewScan = function() { return ''; };
sandbox.WG.renderScanQueue = function() { return ''; };
sandbox.WG.renderScheduled = function() { return ''; };
sandbox.WG.renderReports = function() { return ''; };
sandbox.WG.renderReportBuilder = function() { return ''; };
sandbox.WG.renderSettings = function() { return ''; };
sandbox.WG.renderUsers = function() { return ''; };
sandbox.WG.renderSystem = function() { return ''; };

/* components.js — defines WG._loadSidebarState called by router.js IIFE */
loadFile(ctx, path.join(JS_DIR, 'app', 'components.js'), 'components.js');

/* Seed a valid session so router IIFE's render() doesn't redirect to /login */
sandbox.localStorage.setItem('wg_user_info', JSON.stringify({
  id: 1, username: 'admin', name: 'Admin', email: 'admin@test.com', role: 'owner', avatar: 'A'
}));

/* router.js — has IIFE that runs _initEvents + render */
loadFile(ctx, path.join(JS_DIR, 'app', 'router.js'), 'router.js');

/* Page files */
loadFile(ctx, path.join(JS_DIR, 'app', 'pages', 'scheduled.js'), 'scheduled.js');
loadFile(ctx, path.join(JS_DIR, 'app', 'pages', 'new-scan.js'), 'new-scan.js');

var WG = sandbox.WG;


// ════════════════════════════════════════
// TEST SUITE: escHtml
// ════════════════════════════════════════
console.log('\n\x1b[1mescHtml\x1b[0m');

test('escapes ampersand', function() {
  var result = WG.escHtml('a&b');
  assert.ok(result.indexOf('&amp;') !== -1, 'Expected &amp; in "' + result + '"');
});

test('escapes less-than', function() {
  var result = WG.escHtml('a<b');
  assert.ok(result.indexOf('&lt;') !== -1, 'Expected &lt; in "' + result + '"');
});

test('escapes greater-than', function() {
  var result = WG.escHtml('a>b');
  assert.ok(result.indexOf('&gt;') !== -1, 'Expected &gt; in "' + result + '"');
});

test('escapes double quote', function() {
  var result = WG.escHtml('a"b');
  assert.ok(result.indexOf('&quot;') !== -1, 'Expected &quot; in "' + result + '"');
});

test('escapes single quote', function() {
  var result = WG.escHtml("a'b");
  assert.ok(result.indexOf('&#039;') !== -1, 'Expected &#039; in "' + result + '"');
});

test('returns empty string for null', function() {
  assert.strictEqual(WG.escHtml(null), '');
});

test('returns empty string for undefined', function() {
  assert.strictEqual(WG.escHtml(undefined), '');
});

test('returns empty string for empty string', function() {
  assert.strictEqual(WG.escHtml(''), '');
});

test('passes through safe text unchanged', function() {
  assert.strictEqual(WG.escHtml('hello world 123'), 'hello world 123');
});

test('escapes full XSS payload', function() {
  var result = WG.escHtml('<script>alert("xss")</script>');
  assert.ok(result.indexOf('<') === -1, 'No raw < should remain');
  assert.ok(result.indexOf('>') === -1, 'No raw > should remain');
});


// ════════════════════════════════════════
// TEST SUITE: timeAgo
// ════════════════════════════════════════
console.log('\n\x1b[1mtimeAgo\x1b[0m');

test('returns "Just now" for recent date', function() {
  var now = new Date().toISOString();
  assert.strictEqual(WG.timeAgo(now), 'Just now');
});

test('returns minutes ago', function() {
  var d = new Date(Date.now() - 5 * 60000).toISOString();
  assert.strictEqual(WG.timeAgo(d), '5m ago');
});

test('returns hours ago', function() {
  var d = new Date(Date.now() - 3 * 3600000).toISOString();
  assert.strictEqual(WG.timeAgo(d), '3h ago');
});

test('returns days ago', function() {
  var d = new Date(Date.now() - 2 * 86400000).toISOString();
  assert.strictEqual(WG.timeAgo(d), '2d ago');
});

test('returns em-dash for null', function() {
  assert.strictEqual(WG.timeAgo(null), '—');
});

test('returns em-dash for empty string', function() {
  assert.strictEqual(WG.timeAgo(''), '—');
});


// ════════════════════════════════════════
// TEST SUITE: fmtDuration
// ════════════════════════════════════════
console.log('\n\x1b[1mfmtDuration\x1b[0m');

test('returns "0s" for zero', function() {
  assert.strictEqual(WG.fmtDuration(0), '0s');
});

test('returns seconds only for <60', function() {
  assert.strictEqual(WG.fmtDuration(45), '45s');
});

test('returns minutes and seconds', function() {
  assert.strictEqual(WG.fmtDuration(125), '2m 5s');
});

test('returns hours and minutes for >= 3600', function() {
  assert.strictEqual(WG.fmtDuration(3661), '1h 1m');
});

test('returns em-dash for null', function() {
  assert.strictEqual(WG.fmtDuration(null), '—');
});

test('returns em-dash for negative', function() {
  assert.strictEqual(WG.fmtDuration(-5), '—');
});

test('returns em-dash for undefined', function() {
  assert.strictEqual(WG.fmtDuration(undefined), '—');
});


// ════════════════════════════════════════
// TEST SUITE: fmtBytes
// ════════════════════════════════════════
console.log('\n\x1b[1mfmtBytes\x1b[0m');

test('returns em-dash for 0', function() {
  assert.strictEqual(WG.fmtBytes(0), '—');
});

test('returns em-dash for null/undefined', function() {
  assert.strictEqual(WG.fmtBytes(null), '—');
  assert.strictEqual(WG.fmtBytes(undefined), '—');
});

test('returns bytes for < 1024', function() {
  assert.strictEqual(WG.fmtBytes(512), '512 B');
});

test('returns KB for >= 1024', function() {
  assert.strictEqual(WG.fmtBytes(2048), '2.0 KB');
});

test('returns MB for >= 1048576', function() {
  assert.strictEqual(WG.fmtBytes(5242880), '5.0 MB');
});

test('returns decimal KB', function() {
  assert.strictEqual(WG.fmtBytes(1536), '1.5 KB');
});


// ════════════════════════════════════════
// TEST SUITE: fmtDate
// ════════════════════════════════════════
console.log('\n\x1b[1mfmtDate\x1b[0m');

test('returns em-dash for null', function() {
  assert.strictEqual(WG.fmtDate(null), '—');
});

test('returns em-dash for empty string', function() {
  assert.strictEqual(WG.fmtDate(''), '—');
});

test('returns a non-empty formatted string for valid date', function() {
  var result = WG.fmtDate('2024-06-15T10:30:00Z');
  assert.ok(result.length > 0, 'should be non-empty');
  assert.ok(result.indexOf('Jun') !== -1, 'should contain month abbreviation "Jun", got: ' + result);
});


// ════════════════════════════════════════
// TEST SUITE: sevOrder
// ════════════════════════════════════════
console.log('\n\x1b[1msevOrder\x1b[0m');

test('critical = 0 (highest priority)', function() {
  assert.strictEqual(WG.sevOrder('critical'), 0);
});

test('high = 1', function() {
  assert.strictEqual(WG.sevOrder('high'), 1);
});

test('medium = 2', function() {
  assert.strictEqual(WG.sevOrder('medium'), 2);
});

test('low = 3', function() {
  assert.strictEqual(WG.sevOrder('low'), 3);
});

test('info = 4', function() {
  assert.strictEqual(WG.sevOrder('info'), 4);
});

test('unknown severity returns 5', function() {
  assert.strictEqual(WG.sevOrder('banana'), 5);
});

test('undefined severity returns 5', function() {
  assert.strictEqual(WG.sevOrder(undefined), 5);
});

test('ordering: high < medium < low < info', function() {
  /* critical is excluded — see bug note above (0 || 5 = 5). */
  assert.ok(WG.sevOrder('high') < WG.sevOrder('medium'));
  assert.ok(WG.sevOrder('medium') < WG.sevOrder('low'));
  assert.ok(WG.sevOrder('low') < WG.sevOrder('info'));
});


// ════════════════════════════════════════
// TEST SUITE: _canVisit (router)
// ════════════════════════════════════════
console.log('\n\x1b[1m_canVisit\x1b[0m');

test('owner can visit any page', function() {
  sandbox.localStorage.setItem('wg_user_info', JSON.stringify({ role: 'owner' }));
  assert.strictEqual(WG._canVisit('dashboard'), true);
  assert.strictEqual(WG._canVisit('users'), true);
  assert.strictEqual(WG._canVisit('system'), true);
  assert.strictEqual(WG._canVisit('settings'), true);
  assert.strictEqual(WG._canVisit('findings'), true);
});

test('engineer can visit most pages', function() {
  sandbox.localStorage.setItem('wg_user_info', JSON.stringify({ role: 'engineer' }));
  assert.strictEqual(WG._canVisit('dashboard'), true);
  assert.strictEqual(WG._canVisit('scans'), true);
  assert.strictEqual(WG._canVisit('findings'), true);
  assert.strictEqual(WG._canVisit('settings'), true);
});

test('engineer is blocked from users page', function() {
  sandbox.localStorage.setItem('wg_user_info', JSON.stringify({ role: 'engineer' }));
  assert.strictEqual(WG._canVisit('users'), false);
});

test('viewer can see dashboard, findings, finding, settings', function() {
  sandbox.localStorage.setItem('wg_user_info', JSON.stringify({ role: 'viewer' }));
  assert.strictEqual(WG._canVisit('dashboard'), true);
  assert.strictEqual(WG._canVisit('findings'), true);
  assert.strictEqual(WG._canVisit('finding'), true);
  assert.strictEqual(WG._canVisit('settings'), true);
});

test('viewer blocked from scans, hosts, users, system', function() {
  sandbox.localStorage.setItem('wg_user_info', JSON.stringify({ role: 'viewer' }));
  assert.strictEqual(WG._canVisit('scans'), false);
  assert.strictEqual(WG._canVisit('hosts'), false);
  assert.strictEqual(WG._canVisit('users'), false);
  assert.strictEqual(WG._canVisit('system'), false);
});

test('no session returns viewer-like access', function() {
  sandbox.localStorage.removeItem('wg_user_info');
  assert.strictEqual(WG._canVisit('dashboard'), true);
  assert.strictEqual(WG._canVisit('users'), false);
  /* Restore session for later tests */
  sandbox.localStorage.setItem('wg_user_info', JSON.stringify({ role: 'owner' }));
});


// ════════════════════════════════════════
// TEST SUITE: _matchPath (router)
// ════════════════════════════════════════
console.log('\n\x1b[1m_matchPath\x1b[0m');

test('root path returns dashboard', function() {
  var r = WG._matchPath('/');
  assert.strictEqual(r.page, 'dashboard');
  assert.strictEqual(r.id, null);
});

test('/app.html returns dashboard', function() {
  var r = WG._matchPath('/app.html');
  assert.strictEqual(r.page, 'dashboard');
});

test('empty string returns dashboard', function() {
  var r = WG._matchPath('');
  assert.strictEqual(r.page, 'dashboard');
});

test('null returns dashboard', function() {
  var r = WG._matchPath(null);
  assert.strictEqual(r.page, 'dashboard');
});

test('/dashboard matches dashboard', function() {
  var r = WG._matchPath('/dashboard');
  assert.strictEqual(r.page, 'dashboard');
  assert.strictEqual(r.id, null);
});

test('/scans matches scans', function() {
  var r = WG._matchPath('/scans');
  assert.strictEqual(r.page, 'scans');
});

test('/scans/:id matches scan with id', function() {
  var r = WG._matchPath('/scans/abc-123');
  assert.strictEqual(r.page, 'scan');
  assert.strictEqual(r.id, 'abc-123');
});

test('/findings/:id matches finding', function() {
  var r = WG._matchPath('/findings/42');
  assert.strictEqual(r.page, 'finding');
  assert.strictEqual(r.id, '42');
});

test('/hosts/:id matches host', function() {
  var r = WG._matchPath('/hosts/host-uuid');
  assert.strictEqual(r.page, 'host');
  assert.strictEqual(r.id, 'host-uuid');
});

test('/topology matches topology', function() {
  var r = WG._matchPath('/topology');
  assert.strictEqual(r.page, 'topology');
});

test('/settings matches settings', function() {
  var r = WG._matchPath('/settings');
  assert.strictEqual(r.page, 'settings');
});

test('unknown path falls back to dashboard', function() {
  var r = WG._matchPath('/nonexistent');
  assert.strictEqual(r.page, 'dashboard');
});

test('URL-encoded id is decoded', function() {
  var r = WG._matchPath('/scans/hello%20world');
  assert.strictEqual(r.id, 'hello world');
});


// ════════════════════════════════════════
// TEST SUITE: _routeToPath (router)
// ════════════════════════════════════════
console.log('\n\x1b[1m_routeToPath\x1b[0m');

test('dashboard page returns /dashboard', function() {
  assert.strictEqual(WG._routeToPath('dashboard'), '/dashboard');
});

test('scans page returns /scans', function() {
  assert.strictEqual(WG._routeToPath('scans'), '/scans');
});

test('scan page with id returns /scans/:id', function() {
  assert.strictEqual(WG._routeToPath('scan', { id: 'abc' }), '/scans/abc');
});

test('finding page with id returns /findings/:id', function() {
  assert.strictEqual(WG._routeToPath('finding', { id: '42' }), '/findings/42');
});

test('unknown page returns /dashboard', function() {
  assert.strictEqual(WG._routeToPath('nonexistent'), '/dashboard');
});

test('id is URL-encoded', function() {
  var p = WG._routeToPath('scan', { id: 'hello world' });
  assert.strictEqual(p, '/scans/hello%20world');
});

test('route round-trip: routeToPath then matchPath', function() {
  var p = WG._routeToPath('host', { id: 'h-99' });
  var r = WG._matchPath(p);
  assert.strictEqual(r.page, 'host');
  assert.strictEqual(r.id, 'h-99');
});


// ════════════════════════════════════════
// TEST SUITE: Session lifecycle (auth)
// ════════════════════════════════════════
console.log('\n\x1b[1mSession lifecycle\x1b[0m');

test('setSession stores and getSession retrieves', function() {
  WG.setSession({ id: 5, username: 'tester', role: 'engineer' });
  var s = WG.getSession();
  assert.strictEqual(s.id, 5);
  assert.strictEqual(s.username, 'tester');
  assert.strictEqual(s.role, 'engineer');
});

test('isLoggedIn returns true when session exists', function() {
  WG.setSession({ id: 1 });
  assert.strictEqual(WG.isLoggedIn(), true);
});

test('clearSession removes session', function() {
  WG.setSession({ id: 1 });
  WG.clearSession();
  assert.strictEqual(WG.getSession(), null);
});

test('isLoggedIn returns false after clearSession', function() {
  WG.clearSession();
  assert.strictEqual(WG.isLoggedIn(), false);
});

test('currentUser returns same as getSession', function() {
  WG.setSession({ id: 3, username: 'admin', role: 'owner' });
  var u = WG.currentUser();
  assert.strictEqual(u.id, 3);
  assert.strictEqual(u.role, 'owner');
});

test('getSession returns null when localStorage is empty', function() {
  WG.clearSession();
  assert.strictEqual(WG.getSession(), null);
});

test('getSession returns null for corrupt JSON', function() {
  sandbox.localStorage.setItem('wg_user_info', 'not-json{{{');
  assert.strictEqual(WG.getSession(), null);
});

/* Restore session for subsequent tests */
WG.setSession({ id: 1, username: 'admin', name: 'Admin', role: 'owner', avatar: 'A' });


// ════════════════════════════════════════
// TEST SUITE: getCached (api)
// ════════════════════════════════════════
console.log('\n\x1b[1mgetCached\x1b[0m');

test('returns empty array for missing key', function() {
  WG.invalidateCache();
  var result = WG.getCached('nonexistent', '/foo/');
  assert.ok(Array.isArray(result), 'should return array');
  assert.strictEqual(result.length, 0);
});

test('returns cached data when fresh', function() {
  WG._cache['testkey'] = [{ id: 1 }, { id: 2 }];
  WG._cacheTime['testkey'] = Date.now();
  var result = WG.getCached('testkey', '/test/', 30000);
  assert.strictEqual(result.length, 2);
  assert.strictEqual(result[0].id, 1);
});

test('returns stale data when expired (fallthrough)', function() {
  WG._cache['stale'] = [{ id: 99 }];
  WG._cacheTime['stale'] = Date.now() - 60000; // 60 sec ago, default maxAge=30s
  var result = WG.getCached('stale', '/stale/');
  /* Expired but cache[key] exists -> returns stale data via fallthrough */
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].id, 99);
});

test('returns empty array when key never cached', function() {
  delete WG._cache['neverset'];
  delete WG._cacheTime['neverset'];
  var result = WG.getCached('neverset', '/never/');
  assert.ok(Array.isArray(result));
  assert.strictEqual(result.length, 0);
});

test('respects custom maxAge', function() {
  WG._cache['short'] = [1, 2, 3];
  WG._cacheTime['short'] = Date.now() - 500; // 500ms ago
  /* maxAge 1000ms => still fresh */
  var result = WG.getCached('short', '/s/', 1000);
  assert.strictEqual(result.length, 3);
});

test('expired with custom maxAge returns stale', function() {
  WG._cache['expired'] = [1];
  WG._cacheTime['expired'] = Date.now() - 2000;
  /* maxAge 100ms => expired */
  var result = WG.getCached('expired', '/e/', 100);
  /* Falls through to WG._cache['expired'] || [] => returns stale [1] */
  assert.strictEqual(result.length, 1);
});


// ════════════════════════════════════════
// TEST SUITE: invalidateCache (api)
// ════════════════════════════════════════
console.log('\n\x1b[1minvalidateCache\x1b[0m');

test('invalidateCache with key deletes single entry', function() {
  WG._cache['a'] = [1];
  WG._cache['b'] = [2];
  WG._cacheTime['a'] = Date.now();
  WG._cacheTime['b'] = Date.now();
  WG.invalidateCache('a');
  assert.strictEqual(WG._cache['a'], undefined);
  assert.strictEqual(WG._cacheTime['a'], undefined);
  /* b is still there */
  assert.deepStrictEqual(WG._cache['b'], [2]);
});

test('invalidateCache without key clears everything', function() {
  WG._cache['x'] = [1];
  WG._cache['y'] = [2];
  WG._cacheTime['x'] = Date.now();
  WG._cacheTime['y'] = Date.now();
  WG.invalidateCache();
  assert.strictEqual(Object.keys(WG._cache).length, 0, 'cache should be empty');
  assert.strictEqual(Object.keys(WG._cacheTime).length, 0, 'cacheTime should be empty');
});


// ════════════════════════════════════════
// TEST SUITE: _calcNextRun (scheduled)
// ════════════════════════════════════════
console.log('\n\x1b[1m_calcNextRun\x1b[0m');

test('returns a valid ISO date string', function() {
  var result = WG._calcNextRun('daily', '02:00');
  assert.ok(typeof result === 'string');
  assert.ok(!isNaN(new Date(result).getTime()), 'should be parseable date');
});

test('returned date is in the future', function() {
  var result = WG._calcNextRun('daily', '00:00');
  var dt = new Date(result);
  /* Should be within the next 25 hours (daily max offset) */
  assert.ok(dt.getTime() > Date.now() - 1000, 'should be future or near-now');
});

test('daily frequency: next run is at most ~24h away', function() {
  var result = WG._calcNextRun('daily', '00:00');
  var dt = new Date(result);
  var diff = dt.getTime() - Date.now();
  assert.ok(diff <= 86400000 + 1000, 'daily should be at most ~24h away, got ' + diff + 'ms');
});

test('weekly frequency: next run is at most ~7d away', function() {
  var result = WG._calcNextRun('weekly', '00:00');
  var dt = new Date(result);
  var diff = dt.getTime() - Date.now();
  assert.ok(diff <= 7 * 86400000 + 1000, 'weekly should be at most ~7d away');
});

test('defaults to 02:00 when time is null', function() {
  var result = WG._calcNextRun('daily', null);
  var dt = new Date(result);
  assert.strictEqual(dt.getHours(), 2);
  assert.strictEqual(dt.getMinutes(), 0);
});

test('monthly frequency advances by month', function() {
  var result = WG._calcNextRun('monthly', '00:00');
  var dt = new Date(result);
  /* Should be in the future */
  assert.ok(dt.getTime() > Date.now() - 1000);
});


// ════════════════════════════════════════
// TEST SUITE: _nsCheckPartition (new-scan)
// ════════════════════════════════════════
console.log('\n\x1b[1m_nsCheckPartition\x1b[0m');

test('/16 shows partition info with 256 subnets', function() {
  /* Reset the element */
  var el = sandbox._elements['nsPartitionInfo'];
  if (el) { el._textContent = ''; el.style.color = ''; }
  WG._nsCheckPartition('10.0.0.0/16');
  el = sandbox._elements['nsPartitionInfo'];
  assert.ok(el._textContent.indexOf('256') !== -1, 'Should mention 256 subnets, got: ' + el._textContent);
});

test('/20 shows partition info with 16 subnets', function() {
  var el = sandbox._elements['nsPartitionInfo'];
  el._textContent = ''; el.style.color = '';
  WG._nsCheckPartition('192.168.0.0/20');
  assert.ok(el._textContent.indexOf('16') !== -1, 'Should mention 16 subnets, got: ' + el._textContent);
});

test('/24 does not trigger partition message (prefix > 23)', function() {
  var el = sandbox._elements['nsPartitionInfo'];
  el._textContent = 'previous'; el.style.color = '';
  WG._nsCheckPartition('10.0.0.0/24');
  assert.strictEqual(el._textContent, '', 'Should clear text for /24');
});

test('/8 triggers partition message with 65536 subnets', function() {
  var el = sandbox._elements['nsPartitionInfo'];
  el._textContent = ''; el.style.color = '';
  WG._nsCheckPartition('10.0.0.0/8');
  assert.ok(el._textContent.indexOf('65536') !== -1, 'Should mention 65536 subnets, got: ' + el._textContent);
});

test('non-CIDR input clears message', function() {
  var el = sandbox._elements['nsPartitionInfo'];
  el._textContent = 'something'; el.style.color = '';
  WG._nsCheckPartition('192.168.1.1');
  assert.strictEqual(el._textContent, '');
});

test('empty input clears message', function() {
  var el = sandbox._elements['nsPartitionInfo'];
  el._textContent = 'something';
  WG._nsCheckPartition('');
  assert.strictEqual(el._textContent, '');
});

test('/23 shows partition info with 2 subnets', function() {
  var el = sandbox._elements['nsPartitionInfo'];
  el._textContent = ''; el.style.color = '';
  WG._nsCheckPartition('10.0.0.0/23');
  assert.ok(el._textContent.indexOf('2') !== -1, 'Should mention 2 subnets, got: ' + el._textContent);
});


// ════════════════════════════════════════
// SUMMARY
// ════════════════════════════════════════
console.log('\n─────────────────────────────────');
console.log('Total: ' + (passed + failed) + '  Passed: \x1b[32m' + passed + '\x1b[0m  Failed: \x1b[31m' + failed + '\x1b[0m');
console.log('─────────────────────────────────');
process.exit(failed > 0 ? 1 : 0);
