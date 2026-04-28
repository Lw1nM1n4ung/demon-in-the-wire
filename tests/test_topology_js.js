/**
 * Node.js tests for topology module pure-logic functions.
 * Uses vm.runInContext to load browser-targeted JS in a sandboxed environment.
 * Run: node tests/test_topology_js.js
 */

'use strict';

const vm = require('vm');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const TOPO_DIR = path.join(__dirname, '..', 'web', 'js', 'app', 'pages', 'topology');

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
  var stubSelection = {
    selectAll: function() { return stubSelection; },
    select: function() { return stubSelection; },
    data: function() { return stubSelection; },
    enter: function() { return stubSelection; },
    append: function() { return stubSelection; },
    attr: function() { return stubSelection; },
    style: function() { return stubSelection; },
    merge: function() { return stubSelection; },
    exit: function() { return stubSelection; },
    remove: function() { return stubSelection; },
    empty: function() { return false; },
    classed: function() { return stubSelection; },
    transition: function() { return stubSelection; },
    duration: function() { return stubSelection; },
    ease: function() { return stubSelection; },
    on: function() { return stubSelection; },
    filter: function() { return stubSelection; },
    call: function() { return stubSelection; },
    text: function() { return stubSelection; },
    insert: function() { return stubSelection; },
    node: function() { return null; },
  };

  var sandbox = {
    WG: {
      _topo: {},
      escHtml: function(s) { return String(s); },
      navigate: function() {},
      toast: function() {},
      api: function() { return { then: function() {} }; },
    },
    d3: {
      select: function() { return stubSelection; },
      selectAll: function() { return stubSelection; },
      forceSimulation: function() {
        return {
          nodes: function() { return this; },
          force: function() { return this; },
          alpha: function() { return this; },
          alphaTarget: function() { return this; },
          alphaDecay: function() { return this; },
          restart: function() { return this; },
          stop: function() {},
          on: function() { return this; },
          initialize: function() { return this; },
        };
      },
      forceLink: function() {
        return { id: function() { return this; }, distance: function() { return this; }, strength: function() { return this; } };
      },
      forceManyBody: function() { return { strength: function() { return this; } }; },
      forceCenter: function() { return {}; },
      forceCollide: function() {
        return { radius: function() { return this; }, initialize: function() {} };
      },
      zoom: function() { return { scaleExtent: function() { return this; }, on: function() { return this; } }; },
      drag: function() { return { on: function() { return this; } }; },
      tree: function() { return { size: function() { return function() { return { descendants: function() { return []; } }; }; } }; },
      cluster: function() { return { size: function() { return function() { return { descendants: function() { return []; } }; }; } }; },
      easeCubicOut: function(t) { return t; },
      easeCubicInOut: function(t) { return t; },
      line: function() {
        var gen = function(pts) { return 'M0,0'; };
        gen.curve = function() { return gen; };
        return gen;
      },
      curveCardinalClosed: { tension: function() { return {}; } },
      zoomIdentity: { translate: function() { return { scale: function() { return { translate: function() { return {}; } }; } }; } },
    },
    document: {
      getElementById: function() { return null; },
      createElement: function(tag) {
        return { style: {}, cssText: '', textContent: '', appendChild: function() {}, setAttribute: function() {}, getBoundingClientRect: function() { return { right: 0, bottom: 0 }; } };
      },
      body: { appendChild: function() {} },
      addEventListener: function() {},
      removeEventListener: function() {},
      querySelectorAll: function() { return []; },
      fullscreenElement: null,
    },
    window: { innerWidth: 1200, innerHeight: 800 },
    navigator: { clipboard: { writeText: function() { return { then: function(cb) { cb(); } }; } } },
    confirm: function() { return false; },
    setTimeout: function(fn, ms) { fn(); return 1; },
    clearTimeout: function() {},
    setInterval: function() { return 1; },
    clearInterval: function() {},
    console: console,
    Object: Object,
    Math: Math,
    Array: Array,
    String: String,
    JSON: JSON,
    URL: URL,
    Blob: function() {},
    Image: function() { return { onload: null }; },
    XMLSerializer: function() { return { serializeToString: function() { return '<svg/>'; } }; },
    btoa: function(s) { return Buffer.from(s).toString('base64'); },
    unescape: unescape,
    encodeURIComponent: encodeURIComponent,
    parseInt: parseInt,
    parseFloat: parseFloat,
    isNaN: isNaN,
  };

  return sandbox;
}

function loadModules(ctx) {
  var order = ['heatmap', 'search', 'ports', 'edges', 'cluster', 'layouts', 'minimap', 'contextmenu', 'export', 'live', 'core'];
  order.forEach(function(mod) {
    var code = fs.readFileSync(path.join(TOPO_DIR, mod + '.js'), 'utf8');
    vm.runInContext(code, ctx, { filename: mod + '.js' });
  });
}

// ────────────────────────────────────────
// Build context and load modules
// ────────────────────────────────────────
var sandbox = buildSandbox();
var ctx = vm.createContext(sandbox);
loadModules(ctx);
var WG = sandbox.WG;

// ════════════════════════════════════════
// TEST SUITE: Risk Score
// ════════════════════════════════════════
console.log('\n\x1b[1mRisk Score\x1b[0m');

test('zero for no findings', function() {
  assert.strictEqual(WG._topoRiskScore({}), 0);
});

test('critical contributes 10 per count', function() {
  assert.strictEqual(WG._topoRiskScore({ critical_count: 3 }), 30);
});

test('high contributes 5 per count', function() {
  assert.strictEqual(WG._topoRiskScore({ high_count: 4 }), 20);
});

test('medium contributes 2 per count', function() {
  assert.strictEqual(WG._topoRiskScore({ medium_count: 7 }), 14);
});

test('low contributes 1 per count', function() {
  assert.strictEqual(WG._topoRiskScore({ low_count: 5 }), 5);
});

test('combined formula', function() {
  assert.strictEqual(WG._topoRiskScore({
    critical_count: 2, high_count: 3, medium_count: 1, low_count: 4
  }), 2*10 + 3*5 + 1*2 + 4);  // 41
});

test('capped at 100', function() {
  assert.strictEqual(WG._topoRiskScore({ critical_count: 20 }), 100);
});

test('handles undefined fields gracefully', function() {
  assert.strictEqual(WG._topoRiskScore({ critical_count: 1, high_count: undefined }), 10);
});

// ════════════════════════════════════════
// TEST SUITE: Search Index
// ════════════════════════════════════════
console.log('\n\x1b[1mSearch Index\x1b[0m');

test('builds index from nodes', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoBuildSearchIndex({
    nodes: [
      { id: '1', ip: '192.168.1.1', hostname: 'web01', primary_service: 'web', ports_count: 3, cves: ['CVE-2023-1234'], ports: [{ number: 80, service_name: 'http' }, { number: 443, service_name: 'https' }] },
      { id: '2', ip: '10.0.0.5', hostname: '', primary_service: 'ssh', ports_count: 1, cves: [], ports: [{ number: 22, service_name: 'ssh' }] },
    ]
  });
  assert.strictEqual(WG._topo.state.searchIndex.length, 2);
});

test('tokens include ip', function() {
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('192.168.1.1') !== -1);
});

test('tokens include hostname', function() {
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('web01') !== -1);
});

test('tokens include cves', function() {
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('cve-2023-1234') !== -1);
});

test('tokens include port numbers', function() {
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('80') !== -1);
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('443') !== -1);
});

test('tokens include service names', function() {
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('http') !== -1);
});

test('tokens are lowercased', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoBuildSearchIndex({
    nodes: [{ id: '1', ip: '1.2.3.4', hostname: 'MyHost', primary_service: 'Web', ports_count: 0, cves: [], ports: [] }]
  });
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('myhost') !== -1);
  assert.ok(WG._topo.state.searchIndex[0].tokens.indexOf('web') !== -1);
});

test('empty nodes produce empty index', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoBuildSearchIndex({ nodes: [] });
  assert.strictEqual(WG._topo.state.searchIndex.length, 0);
});

// ════════════════════════════════════════
// TEST SUITE: Auto-Clustering
// ════════════════════════════════════════
console.log('\n\x1b[1mAuto-Clustering\x1b[0m');

test('returns nodes unchanged below threshold', function() {
  var nodes = [];
  for (var i = 0; i < 10; i++) nodes.push({ type: 'host', subnet: '10.0.0.0/24', id: 'h' + i });
  var result = WG._topoAutoCluster(nodes, 50);
  assert.strictEqual(result.length, 10);
});

test('clusters subnets with >5 hosts when above threshold', function() {
  var nodes = [];
  for (var i = 0; i < 60; i++) {
    nodes.push({
      type: 'host', subnet: '10.0.' + Math.floor(i / 10) + '.0/24',
      id: 'h' + i, worst_severity: 'low',
      critical_count: 0, high_count: 0, medium_count: 0, low_count: 1
    });
  }
  var result = WG._topoAutoCluster(nodes, 50);
  var clusters = result.filter(function(n) { return n.type === 'cluster'; });
  assert.ok(clusters.length > 0, 'should have at least one cluster');
  clusters.forEach(function(c) {
    assert.ok(c.host_count > 5, 'cluster host_count should be > 5, got ' + c.host_count);
    assert.ok(c.id.indexOf('cluster_') === 0, 'cluster id should start with cluster_');
  });
});

test('preserves small subnets as individual hosts', function() {
  var nodes = [];
  for (var i = 0; i < 55; i++) {
    var subnet = i < 50 ? '10.0.0.0/24' : '10.0.1.0/24';
    nodes.push({
      type: 'host', subnet: subnet, id: 'h' + i,
      worst_severity: 'clean', critical_count: 0, high_count: 0, medium_count: 0, low_count: 0
    });
  }
  var result = WG._topoAutoCluster(nodes, 50);
  var smallSubnetHosts = result.filter(function(n) { return n.type === 'host' && n.subnet === '10.0.1.0/24'; });
  assert.strictEqual(smallSubnetHosts.length, 5, 'small subnet hosts should pass through');
});

test('cluster node has correct properties', function() {
  var nodes = [];
  for (var i = 0; i < 55; i++) {
    nodes.push({
      type: 'host', subnet: '10.0.0.0/24', id: 'h' + i,
      worst_severity: i === 0 ? 'critical' : 'low',
      critical_count: i === 0 ? 1 : 0, high_count: 0, medium_count: 0, low_count: 1
    });
  }
  var result = WG._topoAutoCluster(nodes, 50);
  var cluster = result.find(function(n) { return n.type === 'cluster'; });
  assert.ok(cluster, 'should have a cluster');
  assert.strictEqual(cluster.subnet, '10.0.0.0/24');
  assert.strictEqual(cluster.host_count, 55);
  assert.strictEqual(cluster.worst_severity, 'critical');
  assert.ok(cluster.r > 20, 'radius should be > 20');
  assert.ok(cluster.label.indexOf('55') !== -1, 'label should contain count');
});

// ════════════════════════════════════════
// TEST SUITE: getBounds
// ════════════════════════════════════════
console.log('\n\x1b[1mgetBounds\x1b[0m');

test('returns null for empty or no-position nodes', function() {
  assert.strictEqual(WG._topoGetBounds([]), null);
  assert.strictEqual(WG._topoGetBounds([{ id: 1 }]), null);
});

test('computes correct bounds', function() {
  var nodes = [
    { x: 10, y: 20 },
    { x: 100, y: 5 },
    { x: 50, y: 200 },
  ];
  var b = WG._topoGetBounds(nodes);
  assert.strictEqual(b.minX, 10);
  assert.strictEqual(b.maxX, 100);
  assert.strictEqual(b.minY, 5);
  assert.strictEqual(b.maxY, 200);
});

test('single node returns same min/max', function() {
  var b = WG._topoGetBounds([{ x: 42, y: 77 }]);
  assert.strictEqual(b.minX, 42);
  assert.strictEqual(b.maxX, 42);
  assert.strictEqual(b.minY, 77);
  assert.strictEqual(b.maxY, 77);
});

// ════════════════════════════════════════
// TEST SUITE: Node Color
// ════════════════════════════════════════
console.log('\n\x1b[1mNode Color (service map)\x1b[0m');

test('service colors map is populated', function() {
  assert.ok(WG._topoServiceColors.web, 'web color exists');
  assert.ok(WG._topoServiceColors.database, 'database color exists');
  assert.ok(WG._topoServiceColors.ssh, 'ssh color exists');
});

test('severity colors map is populated', function() {
  assert.ok(WG._topoSeverityColors.critical, 'critical color exists');
  assert.ok(WG._topoSeverityColors.high, 'high color exists');
  assert.ok(WG._topoSeverityColors.clean, 'clean color exists');
});

test('service labels map is populated', function() {
  assert.strictEqual(WG._topoServiceLabels.web, 'Web Server');
  assert.strictEqual(WG._topoServiceLabels.database, 'Database');
});

// ════════════════════════════════════════
// TEST SUITE: Fresh State
// ════════════════════════════════════════
console.log('\n\x1b[1mFresh State\x1b[0m');

test('_freshState returns a new object each call', function() {
  var a = WG._topo._freshState();
  var b = WG._topo._freshState();
  assert.notStrictEqual(a, b);
  assert.notStrictEqual(a.sel, b.sel);
});

test('_freshState has expected keys', function() {
  var s = WG._topo._freshState();
  assert.strictEqual(s.colorMode, 'service');
  assert.strictEqual(s.sizeMode, 'ports');
  assert.strictEqual(s.layoutMode, 'force');
  assert.strictEqual(s.simulation, null);
  assert.strictEqual(s.fullscreen, false);
  assert.strictEqual(s.nodes.length, 0);
  assert.strictEqual(s.links.length, 0);
  assert.strictEqual(s.expandedHosts.length, 0);
});

test('backward compat alias WG._topoState works', function() {
  var state = WG._topo.state;
  assert.strictEqual(WG._topoState, state);
});

// ════════════════════════════════════════
// TEST SUITE: Size Mode
// ════════════════════════════════════════
console.log('\n\x1b[1mSize Mode\x1b[0m');

test('risk size mode computes correct radius', function() {
  var node = { type: 'host', critical_count: 4, high_count: 0, medium_count: 0, low_count: 0 };
  var score = WG._topoRiskScore(node);
  assert.strictEqual(score, 40);
  var expectedR = Math.max(8, Math.sqrt(40) * 3);
  assert.ok(Math.abs(expectedR - 18.97) < 0.1, 'radius ~18.97, got ' + expectedR);
});

test('ports size mode uses ports_count', function() {
  var r = Math.max(8, Math.sqrt(16) * 5);
  assert.strictEqual(r, 20);
});

test('minimum radius is 8', function() {
  assert.strictEqual(Math.max(8, Math.sqrt(0) * 5), 8);
  assert.strictEqual(Math.max(8, Math.sqrt(0) * 3), 8);
});

// ════════════════════════════════════════
// TEST SUITE: Port Expansion
// ════════════════════════════════════════
console.log('\n\x1b[1mPort Expansion\x1b[0m');

test('expand adds port nodes to state', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoRebindGraph = function() {};
  var host = {
    id: 'host_1', type: 'host', dbId: '1', r: 10, x: 100, y: 100,
    ports: [{ number: 80, protocol: 'tcp', service_name: 'http' }, { number: 443, protocol: 'tcp', service_name: 'https' }]
  };
  WG._topo.state.nodes.push(host);
  WG._topoExpandHost(host);
  var portNodes = WG._topo.state.nodes.filter(function(n) { return n.type === 'port'; });
  assert.strictEqual(portNodes.length, 2);
  assert.strictEqual(portNodes[0].portNumber, 80);
  assert.strictEqual(portNodes[1].portNumber, 443);
  assert.ok(WG._topo.state.expandedHosts.indexOf('host_1') !== -1);
});

test('collapse removes port nodes', function() {
  WG._topoCollapseHost('host_1');
  var portNodes = WG._topo.state.nodes.filter(function(n) { return n.type === 'port'; });
  assert.strictEqual(portNodes.length, 0);
  assert.strictEqual(WG._topo.state.expandedHosts.indexOf('host_1'), -1);
});

test('LRU cap at 3 hosts', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoRebindGraph = function() {};
  for (var i = 1; i <= 4; i++) {
    var h = {
      id: 'host_' + i, type: 'host', dbId: String(i), r: 10, x: i * 50, y: 100,
      ports: [{ number: 80 + i, protocol: 'tcp', service_name: 'http' }]
    };
    WG._topo.state.nodes.push(h);
    WG._topoExpandHost(h);
  }
  assert.ok(WG._topo.state.expandedHosts.length <= 3, 'max 3 expanded, got ' + WG._topo.state.expandedHosts.length);
  assert.strictEqual(WG._topo.state.expandedHosts.indexOf('host_1'), -1, 'oldest host should be collapsed');
});

test('toggle collapses already expanded host', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoRebindGraph = function() {};
  var h = {
    id: 'host_1', type: 'host', dbId: '1', r: 10, x: 100, y: 100,
    ports: [{ number: 22, protocol: 'tcp', service_name: 'ssh' }]
  };
  WG._topo.state.nodes.push(h);
  WG._topoExpandHost(h);
  assert.ok(WG._topo.state.expandedHosts.indexOf('host_1') !== -1);
  WG._topoExpandHost(h);
  assert.strictEqual(WG._topo.state.expandedHosts.indexOf('host_1'), -1, 'should be collapsed after toggle');
});

// ════════════════════════════════════════
// TEST SUITE: Edge Toggle
// ════════════════════════════════════════
console.log('\n\x1b[1mEdge Toggle\x1b[0m');

test('toggleEdges updates state', function() {
  WG._topo.state = WG._topo._freshState();
  WG._topoToggleEdges(true);
  assert.strictEqual(WG._topo.state.edgesVisible, true);
  WG._topoToggleEdges(false);
  assert.strictEqual(WG._topo.state.edgesVisible, false);
});

// ════════════════════════════════════════
// TEST SUITE: Teardown
// ════════════════════════════════════════
console.log('\n\x1b[1mTeardown\x1b[0m');

test('teardown resets state', function() {
  WG._topo.state.fullscreen = false;
  WG._topo.state.nodes = [{ id: 'a' }];
  WG._topo.state.pollHandle = 123;
  WG._topoTeardown();
  assert.strictEqual(WG._topo.state.nodes.length, 0);
  assert.strictEqual(WG._topo.state.pollHandle, null);
  assert.strictEqual(WG._topo.state.simulation, null);
});

// ════════════════════════════════════════
// SUMMARY
// ════════════════════════════════════════
console.log('\n─────────────────────────────────');
console.log('Total: ' + (passed + failed) + '  Passed: \x1b[32m' + passed + '\x1b[0m  Failed: \x1b[31m' + failed + '\x1b[0m');
console.log('─────────────────────────────────');
process.exit(failed > 0 ? 1 : 0);
