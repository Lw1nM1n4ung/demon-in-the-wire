WG._topo = WG._topo || {};

/* ═══════════════ SERVICE COLORS & CONFIG ═══════════════ */

WG._topoServiceColors = {
  web: '#3b82f6', database: '#f59e0b', ssh: '#34d399', mail: '#a78bfa',
  dns: '#f97316', file: '#ec4899', network: '#6b7280', other: '#4b5563'
};

WG._topoSeverityColors = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308',
  low: '#3b82f6', info: '#6b7280', clean: '#22c55e'
};

WG._topoServiceLabels = {
  web: 'Web Server', database: 'Database', ssh: 'SSH', mail: 'Mail',
  dns: 'DNS', file: 'File/SMB', network: 'Network', other: 'Other'
};

/* ═══════════════ STATE ═══════════════ */

WG._topo._freshState = function() {
  return {
    colorMode: 'service', sizeMode: 'ports', layoutMode: 'force',
    simulation: null, svg: null, zoom: null, currentTransform: null,
    data: null, nodes: [], links: [],
    filters: {}, edgesVisible: false,
    expandedHosts: [],
    searchIndex: [], pollHandle: null, fullscreen: false,
    sel: { node: null, label: null, link: null, hull: null, halo: null, edge: null, minimap: null }
  };
};

WG._topo.state = WG._topo._freshState();

Object.defineProperty(WG, '_topoState', {
  get: function() { return WG._topo.state; }, configurable: true
});

/* ═══════════════ TEARDOWN ═══════════════ */

WG._topoTeardown = function() {
  var s = WG._topo.state;
  if (s.simulation) { s.simulation.stop(); s.simulation = null; }
  if (s.pollHandle) { clearInterval(s.pollHandle); s.pollHandle = null; }
  if (WG._topo._searchTimer) { clearTimeout(WG._topo._searchTimer); WG._topo._searchTimer = null; }
  if (s.fullscreen) WG._topoExitFullscreen();
  WG._topoContextDismiss();
  WG._topo.state = WG._topo._freshState();
};

/* ═══════════════ PAGE RENDER ═══════════════ */

WG.renderTopology = function(scanId) {
  var scans = WG.getCached('scans', '/scans/');
  var esc = WG.escHtml;
  var completedScans = scans.filter(function(s) { return s.status === 'completed'; });

  WG.fetchData('/scans/').then(function(data) {
    if (!Array.isArray(data) || !data.length) return;
    WG._cache['scans'] = data; WG._cacheTime['scans'] = Date.now();
    var sel = document.getElementById('topoScanSelect');
    if (!sel) return;
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    var placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Select a scan...';
    sel.appendChild(placeholder);
    var allScans = data.filter(function(s) { return s.status === 'completed' || s.status === 'running'; });
    allScans.forEach(function(s) {
      var o = document.createElement('option');
      o.value = s.id;
      o.textContent = s.name + ' (' + s.target + ')' + (s.status === 'running' ? ' [LIVE]' : '');
      if (scanId && s.id === scanId) o.selected = true;
      sel.appendChild(o);
    });
    if (scanId && sel.value === scanId) WG._topoLoadScan(scanId);
  });

  var scanOpts = completedScans.map(function(s) {
    var sel = (scanId && s.id === scanId) ? ' selected' : '';
    return '<option value="' + s.id + '"' + sel + '>' + esc(s.name) + ' (' + esc(s.target) + ')</option>';
  }).join('');

  /* All values interpolated below come from WG.escHtml() or are
     static string literals — consistent with the rest of the SPA. */
  var html = '' +
    '<div class="page-header"><div class="page-header-left"><h1>Network Topology</h1><p>Interactive network architecture map</p></div>' +
    '<div class="page-header-actions" style="display:flex;gap:8px;align-items:center;">' +
      '<select class="form-select" id="topoScanSelect" onchange="WG._topoLoadScan(this.value)" style="width:260px;">' +
        '<option value="">Select a scan...</option>' + scanOpts +
      '</select>' +

      '<div class="btn-group" style="display:flex;gap:2px;">' +
        '<button class="btn btn-secondary btn-sm topo-layout-btn active" data-layout="force" onclick="WG._topoSetLayout(\'force\')">Force</button>' +
        '<button class="btn btn-secondary btn-sm topo-layout-btn" data-layout="hierarchical" onclick="WG._topoSetLayout(\'hierarchical\')">Tree</button>' +
        '<button class="btn btn-secondary btn-sm topo-layout-btn" data-layout="radial" onclick="WG._topoSetLayout(\'radial\')">Radial</button>' +
        '<button class="btn btn-secondary btn-sm topo-layout-btn" data-layout="grid" onclick="WG._topoSetLayout(\'grid\')">Grid</button>' +
      '</div>' +

      '<button class="btn btn-secondary btn-sm" onclick="WG._topoToggleFullscreen()">Fullscreen</button>' +

      '<div style="position:relative;"><button class="btn btn-secondary btn-sm" onclick="WG._topoToggleExport()">Export</button>' +
        '<div id="topoExportMenu" style="display:none;position:absolute;right:0;top:100%;margin-top:4px;background:var(--bg-card);border:1px solid var(--border-dim);border-radius:var(--radius-md);padding:4px;z-index:100;min-width:120px;">' +
          '<button class="btn btn-ghost btn-sm" style="width:100%;justify-content:flex-start;" onclick="WG._topoExportSVG()">Download SVG</button>' +
          '<button class="btn btn-ghost btn-sm" style="width:100%;justify-content:flex-start;" onclick="WG._topoExportPNG()">Download PNG</button>' +
        '</div></div>' +
    '</div></div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:16px;" id="topoStats">' +
      '<div class="stat-card"><div class="stat-label">Hosts</div><div class="stat-value" id="topoStatHosts">-</div></div>' +
      '<div class="stat-card"><div class="stat-label">Subnets</div><div class="stat-value" id="topoStatSubnets">-</div></div>' +
      '<div class="stat-card"><div class="stat-label">Critical</div><div class="stat-value" style="color:var(--critical);" id="topoStatCritical">-</div></div>' +
      '<div class="stat-card"><div class="stat-label">High</div><div class="stat-value" style="color:var(--high);" id="topoStatHigh">-</div></div>' +
      '<div class="stat-card"><div class="stat-label">Services</div><div class="stat-value" id="topoStatServices">-</div></div>' +
    '</div>' +

    '<div style="display:grid;grid-template-columns:220px 1fr;gap:16px;">' +
      '<div>' +

        '<div class="panel" style="margin-bottom:12px;"><div class="panel-header"><div class="panel-title">Search</div></div>' +
          '<div class="panel-body">' +
            '<input type="text" class="form-input" id="topoSearch" placeholder="IP, port, CVE, service..." ' +
            'oninput="WG._topoSearch(this.value)" style="width:100%;font-size:0.78rem;">' +
          '</div></div>' +

        '<div class="panel" style="margin-bottom:12px;"><div class="panel-header"><div class="panel-title">Color By</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:6px;">' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.82rem;color:var(--text-bright);">' +
              '<input type="radio" name="topoColor" value="service" checked onchange="WG._topoSetColorMode(\'service\')"> Service Type</label>' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.82rem;color:var(--text-bright);">' +
              '<input type="radio" name="topoColor" value="severity" onchange="WG._topoSetColorMode(\'severity\')"> Severity</label>' +
          '</div></div>' +

        '<div class="panel" style="margin-bottom:12px;"><div class="panel-header"><div class="panel-title">Size By</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:6px;">' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.82rem;color:var(--text-bright);">' +
              '<input type="radio" name="topoSize" value="ports" checked onchange="WG._topoSetSizeMode(\'ports\')"> Ports</label>' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.82rem;color:var(--text-bright);">' +
              '<input type="radio" name="topoSize" value="risk" onchange="WG._topoSetSizeMode(\'risk\')"> Risk Score</label>' +
          '</div></div>' +

        '<div class="panel" style="margin-bottom:12px;"><div class="panel-header"><div class="panel-title">Show Services</div></div>' +
          '<div class="panel-body" id="topoServiceFilters" style="display:flex;flex-direction:column;gap:5px;">' +
            Object.keys(WG._topoServiceColors).map(function(svc) {
              return '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.78rem;color:var(--text-bright);">' +
                '<input type="checkbox" checked data-svc="' + svc + '" onchange="WG._topoToggleFilter(\'' + svc + '\',this.checked)">' +
                '<span style="width:10px;height:10px;border-radius:50%;background:' + WG._topoServiceColors[svc] + ';flex-shrink:0;"></span> ' +
                esc(WG._topoServiceLabels[svc]) + '</label>';
            }).join('') +
          '</div></div>' +

        '<div class="panel" style="margin-bottom:12px;"><div class="panel-header"><div class="panel-title">Options</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:6px;">' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.78rem;color:var(--text-bright);">' +
              '<input type="checkbox" onchange="WG._topoToggleEdges(this.checked)"> Show relationships</label>' +
          '</div></div>' +

        '<div class="panel"><div class="panel-header"><div class="panel-title">Legend</div></div>' +
          '<div class="panel-body" id="topoLegend"></div></div>' +
      '</div>' +

      '<div class="panel" style="padding:0;overflow:hidden;position:relative;min-height:500px;" id="topoGraphPanel">' +
        '<div id="topoContainer" style="width:100%;height:600px;background:var(--bg-main);"></div>' +
        '<div id="topoEmpty" style="display:flex;align-items:center;justify-content:center;height:100%;position:absolute;top:0;left:0;right:0;bottom:0;color:var(--text-dim);font-size:0.9rem;">' +
          'Select a completed scan to visualize' +
        '</div>' +
      '</div>' +
    '</div>' +

    '<div class="panel" id="topoDetail" style="margin-top:16px;">' +
      '<div class="panel-header"><div class="panel-title" id="topoDetailTitle">Host Details</div>' +
        '<button class="btn btn-ghost btn-sm" onclick="document.getElementById(\'topoDetail\').classList.remove(\'open\')">Close</button></div>' +
      '<div class="panel-body" id="topoDetailBody"></div>' +
    '</div>' +

    '<div id="topoTooltip" style="opacity:0;visibility:hidden;position:fixed;pointer-events:none;z-index:1000;background:var(--bg-card);border:1px solid var(--border-dim);border-radius:var(--radius-md);padding:10px 14px;font-size:0.78rem;box-shadow:var(--shadow-lg);max-width:280px;transition:opacity 0.15s ease,visibility 0.15s ease;"></div>';

  if (scanId) {
    setTimeout(function() { WG._topoLoadScan(scanId); }, 80);
  }
  setTimeout(WG._topoUpdateLegend, 50);

  return html;
};

/* ═══════════════ DATA LOADING ═══════════════ */

WG._topoLoadScan = function(scanId) {
  if (!scanId) return;
  scanId = String(scanId);
  var empty = document.getElementById('topoEmpty');
  if (empty) empty.textContent = 'Loading topology...';

  WG.api('/scans/' + scanId + '/topology/').then(function(data) {
    if (data && data.nodes) {
      WG._topoRenderGraph(data);
      if (data.scan_status === 'running') {
        WG._topoStartPolling(scanId);
      }
    } else {
      if (empty) empty.textContent = 'No topology data available for this scan';
    }
  });
};

/* ═══════════════ D3 GRAPH RENDERING ═══════════════ */

WG._topoRenderGraph = function(data) {
  var s = WG._topo.state;
  if (s.simulation) { s.simulation.stop(); s.simulation = null; }
  if (s.pollHandle) { clearInterval(s.pollHandle); s.pollHandle = null; }
  s.data = data;

  var el = function(id) { return document.getElementById(id); };
  if (el('topoStatHosts')) el('topoStatHosts').textContent = data.nodes.length;
  if (el('topoStatSubnets')) el('topoStatSubnets').textContent = data.subnets.length;
  var critCount = data.nodes.reduce(function(sum, n) { return sum + (n.critical_count || 0); }, 0);
  var highCount = data.nodes.reduce(function(sum, n) { return sum + (n.high_count || 0); }, 0);
  if (el('topoStatCritical')) el('topoStatCritical').textContent = critCount;
  if (el('topoStatHigh')) el('topoStatHigh').textContent = highCount;
  var svcs = {};
  data.nodes.forEach(function(n) { svcs[n.primary_service] = true; });
  if (el('topoStatServices')) el('topoStatServices').textContent = Object.keys(svcs).length;

  var empty = document.getElementById('topoEmpty');
  if (empty) empty.style.display = 'none';

  var container = document.getElementById('topoContainer');
  if (!container) return;
  container.textContent = '';

  var width = container.clientWidth || 800;
  var height = container.clientHeight || 600;

  var nodes = [];
  var links = [];
  var subnetMap = {};

  data.subnets.forEach(function(sub) {
    var hubId = 'subnet_' + sub.cidr;
    subnetMap[sub.cidr] = hubId;
    nodes.push({
      id: hubId, type: 'subnet', label: sub.cidr, subnet: sub.cidr,
      r: 16, host_count: sub.host_count
    });
  });

  data.nodes.forEach(function(n) {
    var nodeId = 'host_' + n.id;
    nodes.push({
      id: nodeId, type: 'host', dbId: n.id,
      ip: n.ip, hostname: n.hostname, os: n.os,
      subnet: n.subnet, primary_service: n.primary_service,
      worst_severity: n.worst_severity,
      ports: n.ports, technologies: n.technologies,
      findings_count: n.findings_count,
      critical_count: n.critical_count,
      high_count: n.high_count, medium_count: n.medium_count,
      low_count: n.low_count || 0,
      ports_count: n.ports_count,
      risk_score: n.risk_score || 0,
      cves: n.cves || [],
      r: Math.max(8, Math.sqrt(n.ports_count || 1) * 5),
      label: n.ip
    });
    var hubId = subnetMap[n.subnet];
    if (hubId) links.push({ source: nodeId, target: hubId });
  });

  s.nodes = nodes;
  s.links = links;

  var svg = d3.select(container).append('svg')
    .attr('width', width).attr('height', height)
    .attr('id', 'topoSvg')
    .style('background', 'var(--bg-main)');

  s.svg = svg;

  WG._topoInitHeatmap(svg);

  var g = svg.append('g').attr('class', 'topo-root');

  var zoom = d3.zoom()
    .scaleExtent([0.15, 5])
    .on('zoom', function(event) {
      g.attr('transform', event.transform);
      s.currentTransform = event.transform;
      WG._topoUpdateMinimap(event.transform);
      var k = event.transform.k;
      if (s.sel.label) {
        s.sel.label.attr('opacity', function(d) {
          if (d.type === 'subnet') return Math.max(0, Math.min(1, (k - 0.25) / 0.25));
          return Math.max(0, Math.min(1, (k - 0.5) / 0.4));
        });
      }
    });

  svg.call(zoom);
  s.zoom = zoom;

  var hullGroup = g.append('g').attr('class', 'hulls');
  var haloGroup = g.append('g').attr('class', 'halos');
  var linkGroup = g.append('g').attr('class', 'links');
  var nodeGroup = g.append('g').attr('class', 'nodes');
  var labelGroup = g.append('g').attr('class', 'labels');

  s.sel.hull = hullGroup;
  s.sel.halo = haloGroup;

  WG._topoInitEdges(g, data);

  var linkSel = linkGroup.selectAll('line').data(links).enter().append('line')
    .attr('stroke', 'var(--border-dim)').attr('stroke-width', 1).attr('stroke-opacity', 0.4);

  var nodeSel = nodeGroup.selectAll('circle').data(nodes).enter().append('circle')
    .attr('r', 0)
    .attr('fill', function(d) { return WG._topoNodeColor(d); })
    .attr('stroke', function(d) { return d.type === 'subnet' ? 'var(--text-dim)' : 'rgba(255,255,255,0.15)'; })
    .attr('stroke-width', function(d) { return d.type === 'subnet' ? 2 : 1.5; })
    .attr('stroke-dasharray', function(d) { return d.type === 'subnet' ? '4,3' : 'none'; })
    .attr('cursor', function(d) { return d.type === 'host' ? 'pointer' : 'default'; })
    .attr('opacity', 0)
    .on('mouseover', function(event, d) {
      d3.select(this).transition().duration(150)
        .attr('stroke-width', d.type === 'host' ? 2.5 : 2)
        .attr('stroke', 'rgba(255,255,255,0.35)')
        .attr('filter', d.type === 'host' ? 'url(#topo-glow-' + (d.worst_severity || 'clean') + ')' : null);
      WG._topoShowTooltip(event, d);
    })
    .on('mousemove', WG._topoMoveTooltip)
    .on('mouseout', function(event, d) {
      d3.select(this).transition().duration(200)
        .attr('stroke-width', d.type === 'subnet' ? 2 : 1.5)
        .attr('stroke', d.type === 'subnet' ? 'var(--text-dim)' : 'rgba(255,255,255,0.15)')
        .attr('filter', null);
      WG._topoHideTooltip();
    })
    .on('click', function(event, d) {
      if (d.type === 'host') {
        if (event.shiftKey) WG._topoShowDetail(d);
        else WG._topoExpandHost(d);
      } else if (d.type === 'cluster') {
        WG._topoExpandCluster(d);
      }
    })
    .on('contextmenu', function(event, d) {
      if (d.type === 'host') WG._topoContextMenu(event, d);
    });

  var alphaDecay = nodes.length > 100 ? 0.03 : 0.02;
  var simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(function(d) { return d.id; }).distance(80).strength(0.7))
    .force('charge', d3.forceManyBody().strength(function(d) { return d.type === 'subnet' ? -400 : -150; }))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collide', d3.forceCollide().radius(function(d) { return d.r + 6; }))
    .alphaDecay(alphaDecay);

  nodeSel.call(d3.drag()
    .on('start', function(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    })
    .on('drag', function(event, d) { d.fx = event.x; d.fy = event.y; })
    .on('end', function(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      if (s.layoutMode === 'force') { d.fx = null; d.fy = null; }
    })
  );

  nodeSel.transition().duration(500).ease(d3.easeCubicOut)
    .delay(function(d, i) { return Math.min(i * 30, 600); })
    .attr('r', function(d) { return d.r; })
    .attr('opacity', function(d) { return d.type === 'subnet' ? 0.6 : 1; });

  var labelSel = labelGroup.selectAll('text').data(nodes).enter().append('text')
    .text(function(d) { return d.label; })
    .attr('font-size', function(d) { return d.type === 'subnet' ? '10px' : '8px'; })
    .attr('font-family', 'var(--font-mono)')
    .attr('fill', 'var(--text-dim)')
    .attr('text-anchor', 'middle')
    .attr('dy', function(d) { return d.r + 12; })
    .attr('pointer-events', 'none');

  simulation.on('tick', function() {
    linkSel.attr('x1', function(d) { return d.source.x; }).attr('y1', function(d) { return d.source.y; })
           .attr('x2', function(d) { return d.target.x; }).attr('y2', function(d) { return d.target.y; });
    nodeSel.attr('cx', function(d) { return d.x; }).attr('cy', function(d) { return d.y; });
    labelSel.attr('x', function(d) { return d.x; }).attr('y', function(d) { return d.y; });
    WG._topoDrawHulls(hullGroup, nodes);
    WG._topoDrawHalos(haloGroup, nodes);
    WG._topoUpdateEdgePositions();
    WG._topoUpdateMinimapNodes();
  }).on('end', function() { WG._topoZoomToFit(750); });

  s.simulation = simulation;
  s.sel.node = nodeSel;
  s.sel.label = labelSel;
  s.sel.link = linkSel;

  WG._topoUpdateLegend();
  WG._topoBuildSearchIndex(data);
  WG._topoInitMinimap(container);
};

/* ═══════════════ ZOOM TO FIT ═══════════════ */

WG._topoZoomToFit = function(duration) {
  var s = WG._topo.state;
  if (!s.svg || !s.zoom || !s.nodes.length) return;
  var bounds = WG._topoGetBounds(s.nodes);
  if (!bounds) return;
  var pad = 60;
  var w = parseInt(s.svg.attr('width')) || 800;
  var h = parseInt(s.svg.attr('height')) || 600;
  var bw = bounds.maxX - bounds.minX + pad * 2;
  var bh = bounds.maxY - bounds.minY + pad * 2;
  var scale = Math.min(w / bw, h / bh, 2);
  var cx = (bounds.minX + bounds.maxX) / 2;
  var cy = (bounds.minY + bounds.maxY) / 2;
  var transform = d3.zoomIdentity
    .translate(w / 2, h / 2).scale(scale).translate(-cx, -cy);
  s.svg.transition().duration(duration || 750).ease(d3.easeCubicInOut)
    .call(s.zoom.transform, transform);
};

/* ═══════════════ SUBNET HULLS ═══════════════ */

WG._topoHullLine = d3.line().curve(d3.curveCardinalClosed.tension(0.85));

WG._topoDrawHulls = function(hullGroup, nodes) {
  var subnets = {};
  nodes.forEach(function(n) {
    if (n.type === 'host' && n.x !== undefined) {
      if (!subnets[n.subnet]) subnets[n.subnet] = [];
      subnets[n.subnet].push([n.x, n.y]);
    }
  });

  var hullData = [];
  var subnetColors = ['#3b82f6', '#f59e0b', '#34d399', '#a78bfa', '#f97316', '#ec4899', '#6b7280'];
  var subnetKeys = Object.keys(subnets);

  subnetKeys.forEach(function(cidr, i) {
    var points = subnets[cidr];
    var padded = [];
    points.forEach(function(p) {
      padded.push([p[0] - 20, p[1] - 20]); padded.push([p[0] + 20, p[1] - 20]);
      padded.push([p[0] + 20, p[1] + 20]); padded.push([p[0] - 20, p[1] + 20]);
    });
    if (points.length < 3) {
      if (points.length === 1) {
        var p = points[0];
        padded = [[p[0]-35, p[1]-35], [p[0]+35, p[1]-35], [p[0]+35, p[1]+35], [p[0]-35, p[1]+35]];
      }
    }
    var hull = d3.polygonHull(padded);
    if (hull) hullData.push({ cidr: cidr, path: hull, color: subnetColors[i % subnetColors.length] });
  });

  var hulls = hullGroup.selectAll('path').data(hullData, function(d) { return d.cidr; });
  hulls.enter().append('path')
    .attr('fill', function(d) { return d.color; }).attr('fill-opacity', 0.06)
    .attr('stroke', function(d) { return d.color; }).attr('stroke-opacity', 0.2)
    .attr('stroke-width', 1.5)
    .merge(hulls)
    .attr('d', function(d) { return WG._topoHullLine(d.path); });
  hulls.exit().remove();
};

/* ═══════════════ COLOR MODES ═══════════════ */

WG._topoNodeColor = function(d) {
  if (d.type === 'subnet') return 'var(--bg-card)';
  if (d.type === 'cluster') {
    return WG._topoSeverityColors[d.worst_severity] || WG._topoSeverityColors.clean;
  }
  if (WG._topo.state.colorMode === 'severity') {
    return WG._topoSeverityColors[d.worst_severity] || WG._topoSeverityColors.clean;
  }
  return WG._topoServiceColors[d.primary_service] || WG._topoServiceColors.other;
};

WG._topoSetColorMode = function(mode) {
  WG._topo.state.colorMode = mode;
  if (WG._topo.state.sel.node) {
    WG._topo.state.sel.node.transition().duration(300).ease(d3.easeCubicOut)
      .attr('fill', function(d) { return WG._topoNodeColor(d); });
  }
  WG._topoUpdateLegend();
};

WG._topoUpdateLegend = function() {
  var el = document.getElementById('topoLegend');
  if (!el) return;
  var esc = WG.escHtml;
  var mode = WG._topo.state.colorMode;
  var colors = mode === 'severity' ? WG._topoSeverityColors : WG._topoServiceColors;
  var labels = mode === 'severity'
    ? { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', clean: 'Clean' }
    : WG._topoServiceLabels;

  var frag = document.createDocumentFragment();
  Object.keys(colors).forEach(function(key) {
    var row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:4px;';
    var dot = document.createElement('span');
    dot.style.cssText = 'width:10px;height:10px;border-radius:50%;flex-shrink:0;background:' + colors[key];
    var txt = document.createElement('span');
    txt.style.cssText = 'font-size:0.72rem;color:var(--text-dim);';
    txt.textContent = labels[key] || key;
    row.appendChild(dot);
    row.appendChild(txt);
    frag.appendChild(row);
  });
  el.textContent = '';
  el.appendChild(frag);
};

/* ═══════════════ SERVICE FILTER ═══════════════ */

WG._topoToggleFilter = function(svc, show) {
  var s = WG._topo.state;
  s.filters[svc] = show;
  if (!s.sel.node) return;

  s.sel.node.attr('display', function(d) {
    if (d.type === 'subnet') return null;
    return s.filters[d.primary_service] === false ? 'none' : null;
  });
  s.sel.label.attr('display', function(d) {
    if (d.type === 'subnet') return null;
    return s.filters[d.primary_service] === false ? 'none' : null;
  });
  s.sel.link.attr('display', function(d) {
    var src = typeof d.source === 'object' ? d.source : null;
    if (src && src.type === 'host' && s.filters[src.primary_service] === false) return 'none';
    return null;
  });
};

/* ═══════════════ TOOLTIP ═══════════════ */

WG._topoShowTooltip = function(event, d) {
  var tip = document.getElementById('topoTooltip');
  if (!tip) return;

  tip.textContent = '';

  if (d.type === 'subnet') {
    var t1 = document.createElement('div');
    t1.style.cssText = 'font-weight:600;color:var(--text-bright);';
    t1.textContent = d.label;
    var t2 = document.createElement('div');
    t2.style.cssText = 'color:var(--text-dim);margin-top:2px;';
    t2.textContent = d.host_count + ' hosts';
    tip.appendChild(t1); tip.appendChild(t2);
  } else if (d.type === 'port') {
    var pt = document.createElement('div');
    pt.style.cssText = 'font-weight:600;color:var(--text-bright);';
    pt.textContent = 'Port ' + d.portNumber + '/' + (d.protocol || 'tcp');
    tip.appendChild(pt);
    if (d.serviceName) {
      var sn = document.createElement('div');
      sn.style.cssText = 'color:var(--text-dim);font-size:0.72rem;';
      sn.textContent = d.serviceName;
      tip.appendChild(sn);
    }
  } else if (d.type === 'cluster') {
    var ct = document.createElement('div');
    ct.style.cssText = 'font-weight:600;color:var(--text-bright);';
    ct.textContent = d.subnet;
    tip.appendChild(ct);
    var cc = document.createElement('div');
    cc.style.cssText = 'color:var(--text-dim);margin-top:2px;';
    cc.textContent = d.host_count + ' hosts (clustered)';
    tip.appendChild(cc);
  } else {
    var h = document.createElement('div');
    h.style.cssText = 'font-weight:600;color:var(--text-bright);';
    h.textContent = d.ip;
    tip.appendChild(h);
    if (d.hostname) { var hn = document.createElement('div'); hn.style.cssText = 'color:var(--text-dim);font-size:0.72rem;'; hn.textContent = d.hostname; tip.appendChild(hn); }
    if (d.os) { var os = document.createElement('div'); os.style.cssText = 'color:var(--text-dim);font-size:0.72rem;'; os.textContent = d.os; tip.appendChild(os); }
    var row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;margin-top:6px;font-size:0.72rem;';
    var svcSpan = document.createElement('span');
    svcSpan.style.color = WG._topoServiceColors[d.primary_service] || '#6b7280';
    svcSpan.textContent = WG._topoServiceLabels[d.primary_service] || d.primary_service;
    var sevSpan = document.createElement('span');
    sevSpan.style.color = WG._topoSeverityColors[d.worst_severity] || '#6b7280';
    sevSpan.textContent = d.worst_severity;
    row.appendChild(svcSpan); row.appendChild(sevSpan);
    tip.appendChild(row);

    var riskScore = d.risk_score || WG._topoRiskScore(d);
    var info = document.createElement('div');
    info.style.cssText = 'font-size:0.68rem;color:var(--text-dim);margin-top:4px;';
    info.textContent = d.ports_count + ' ports · ' + d.findings_count + ' findings · risk: ' + riskScore;
    tip.appendChild(info);

    if (d.cves && d.cves.length) {
      var cveDiv = document.createElement('div');
      cveDiv.style.cssText = 'font-size:0.66rem;color:var(--critical);margin-top:3px;';
      cveDiv.textContent = d.cves.slice(0, 3).join(', ') + (d.cves.length > 3 ? ' +' + (d.cves.length - 3) + ' more' : '');
      tip.appendChild(cveDiv);
    }

    var hint = document.createElement('div');
    hint.style.cssText = 'font-size:0.62rem;color:var(--text-dim);margin-top:3px;';
    hint.textContent = 'Click: ports · Shift+click: details · Right-click: menu';
    tip.appendChild(hint);
  }
  tip.style.opacity = '1';
  tip.style.visibility = 'visible';
  tip.style.left = (event.clientX + 14) + 'px';
  tip.style.top = (event.clientY - 10) + 'px';
};

WG._topoMoveTooltip = function(event) {
  var tip = document.getElementById('topoTooltip');
  if (tip) { tip.style.left = (event.clientX + 14) + 'px'; tip.style.top = (event.clientY - 10) + 'px'; }
};

WG._topoHideTooltip = function() {
  var tip = document.getElementById('topoTooltip');
  if (tip) { tip.style.opacity = '0'; tip.style.visibility = 'hidden'; }
};

/* ═══════════════ DETAIL PANEL ═══════════════ */

WG._topoShowDetail = function(d) {
  var panel = document.getElementById('topoDetail');
  var title = document.getElementById('topoDetailTitle');
  var body = document.getElementById('topoDetailBody');
  if (!panel || !body) return;
  var esc = WG.escHtml;

  title.textContent = d.ip + (d.hostname ? ' (' + d.hostname + ')' : '');
  panel.classList.add('open');

  var riskScore = d.risk_score || WG._topoRiskScore(d);

  /* Detail panel uses DOM construction for data cells, escHtml for table
     content — same pattern as host-detail.js and finding-detail.js. */
  var detailFrag = document.createDocumentFragment();

  var grid = document.createElement('div');
  grid.style.cssText = 'display:grid;grid-template-columns:1fr 1fr 1fr 1fr 1fr;gap:12px;margin-bottom:16px;';

  var fields = [
    { label: 'OS', value: d.os || 'Unknown', color: 'var(--text-bright)' },
    { label: 'Service', value: WG._topoServiceLabels[d.primary_service] || d.primary_service, color: WG._topoServiceColors[d.primary_service] || '#6b7280' },
    { label: 'Severity', value: d.worst_severity || 'clean', color: WG._topoSeverityColors[d.worst_severity] || '#22c55e' },
    { label: 'Risk Score', value: riskScore + '/100', color: 'var(--text-bright)' },
    { label: 'Findings', value: parseInt(d.findings_count) + ' (' + parseInt(d.critical_count || 0) + 'C/' + parseInt(d.high_count || 0) + 'H/' + parseInt(d.medium_count || 0) + 'M)', color: 'var(--text-bright)' }
  ];

  fields.forEach(function(f) {
    var cell = document.createElement('div');
    var lbl = document.createElement('span');
    lbl.style.cssText = 'font-size:0.7rem;color:var(--text-dim);';
    lbl.textContent = f.label;
    var val = document.createElement('div');
    val.style.cssText = 'font-size:0.85rem;color:' + f.color + ';';
    val.textContent = f.value;
    cell.appendChild(lbl);
    cell.appendChild(val);
    grid.appendChild(cell);
  });
  detailFrag.appendChild(grid);

  if (d.cves && d.cves.length) {
    var cveWrap = document.createElement('div');
    cveWrap.style.cssText = 'margin-bottom:12px;';
    var cveLbl = document.createElement('span');
    cveLbl.style.cssText = 'font-size:0.7rem;color:var(--text-dim);';
    cveLbl.textContent = 'CVEs';
    cveWrap.appendChild(cveLbl);
    var cveTags = document.createElement('div');
    cveTags.style.cssText = 'display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;';
    d.cves.forEach(function(c) {
      var tag = document.createElement('span');
      tag.className = 'tag';
      tag.style.cssText = 'background:var(--critical-dim);color:var(--critical);';
      tag.textContent = c;
      cveTags.appendChild(tag);
    });
    cveWrap.appendChild(cveTags);
    detailFrag.appendChild(cveWrap);
  }

  if (d.technologies && d.technologies.length) {
    var techWrap = document.createElement('div');
    techWrap.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;';
    d.technologies.forEach(function(t) {
      var tag = document.createElement('span');
      tag.className = 'tag';
      tag.textContent = t;
      techWrap.appendChild(tag);
    });
    detailFrag.appendChild(techWrap);
  }

  if (d.ports && d.ports.length) {
    var table = document.createElement('table');
    table.className = 'data-table';
    table.style.fontSize = '0.78rem';
    var thead = document.createElement('thead');
    var hrow = document.createElement('tr');
    ['Port', 'Protocol', 'Service', 'Product'].forEach(function(h) {
      var th = document.createElement('th');
      th.textContent = h;
      hrow.appendChild(th);
    });
    thead.appendChild(hrow);
    table.appendChild(thead);
    var tbody = document.createElement('tbody');
    d.ports.forEach(function(p) {
      var tr = document.createElement('tr');
      var td1 = document.createElement('td'); td1.className = 'mono'; td1.textContent = parseInt(p.number);
      var td2 = document.createElement('td'); td2.textContent = p.protocol || 'tcp';
      var td3 = document.createElement('td'); td3.textContent = p.service_name || '';
      var td4 = document.createElement('td'); td4.textContent = p.service_product || '';
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    detailFrag.appendChild(table);
  } else {
    var noPort = document.createElement('div');
    noPort.style.cssText = 'color:var(--text-dim);font-size:0.8rem;';
    noPort.textContent = 'No port data';
    detailFrag.appendChild(noPort);
  }

  var btnWrap = document.createElement('div');
  btnWrap.style.marginTop = '12px';
  var btn = document.createElement('button');
  btn.className = 'btn btn-secondary btn-sm';
  btn.textContent = 'View Full Host Details';
  btn.onclick = function() { WG.navigate('host', { id: d.dbId }); };
  btnWrap.appendChild(btn);
  detailFrag.appendChild(btnWrap);

  body.textContent = '';
  body.appendChild(detailFrag);
};
