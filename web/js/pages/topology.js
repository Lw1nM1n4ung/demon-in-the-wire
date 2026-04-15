/* Wire_Ghost — Network Topology Map (D3.js force-directed graph)
   Security note: All user-supplied values are escaped via WG.escHtml()
   before insertion into HTML strings. D3 .text() bindings are inherently
   safe from XSS. innerHTML usage follows the same pattern as all other
   Wire_Ghost SPA pages (vanilla JS string-based rendering). */

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

WG._topoState = { colorMode: 'service', simulation: null, svg: null, data: null, filters: {} };

/* ═══════════════ PAGE RENDER ═══════════════ */

WG.renderTopology = function(scanId) {
  var scans = WG.getCached('scans', '/scans/', 'scans');
  var esc = WG.escHtml;
  var completedScans = scans.filter(function(s) { return s.status === 'completed'; });

  var scanOpts = completedScans.map(function(s) {
    var sel = (scanId && s.id === scanId) ? ' selected' : '';
    return '<option value="' + s.id + '"' + sel + '>' + esc(s.name) + ' (' + esc(s.target) + ')</option>';
  }).join('');

  var html = '' +
    '<div class="page-header"><div class="page-header-left"><h1>Network Topology</h1><p>Interactive network architecture map</p></div>' +
    '<div class="page-header-actions" style="display:flex;gap:8px;align-items:center;">' +
      '<select class="form-select" id="topoScanSelect" onchange="WG._topoLoadScan(this.value)" style="width:260px;">' +
        '<option value="">Select a scan...</option>' + scanOpts +
      '</select>' +
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
        '<div class="panel" style="margin-bottom:12px;"><div class="panel-header"><div class="panel-title">Color By</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:6px;">' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.82rem;color:var(--text-bright);">' +
              '<input type="radio" name="topoColor" value="service" checked onchange="WG._topoSetColorMode(\'service\')"> Service Type</label>' +
            '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.82rem;color:var(--text-bright);">' +
              '<input type="radio" name="topoColor" value="severity" onchange="WG._topoSetColorMode(\'severity\')"> Severity</label>' +
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

    '<div class="panel" id="topoDetail" style="margin-top:16px;display:none;">' +
      '<div class="panel-header"><div class="panel-title" id="topoDetailTitle">Host Details</div>' +
        '<button class="btn btn-ghost btn-sm" onclick="document.getElementById(\'topoDetail\').style.display=\'none\'">Close</button></div>' +
      '<div class="panel-body" id="topoDetailBody"></div>' +
    '</div>' +

    '<div id="topoTooltip" style="display:none;position:fixed;pointer-events:none;z-index:1000;background:var(--bg-card);border:1px solid var(--border-dim);border-radius:var(--radius-md);padding:10px 14px;font-size:0.78rem;box-shadow:var(--shadow-lg);max-width:280px;"></div>';

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
    } else if (WG.MOCK && WG.MOCK['topology_' + scanId]) {
      WG._topoRenderGraph(WG.MOCK['topology_' + scanId]);
    } else {
      if (empty) empty.textContent = 'No topology data available for this scan';
    }
  });
};

/* ═══════════════ D3 GRAPH RENDERING ═══════════════ */

WG._topoRenderGraph = function(data) {
  WG._topoState.data = data;

  var el = function(id) { return document.getElementById(id); };
  if (el('topoStatHosts')) el('topoStatHosts').textContent = data.nodes.length;
  if (el('topoStatSubnets')) el('topoStatSubnets').textContent = data.subnets.length;
  var critCount = data.nodes.reduce(function(s, n) { return s + (n.critical_count || 0); }, 0);
  var highCount = data.nodes.reduce(function(s, n) { return s + (n.high_count || 0); }, 0);
  if (el('topoStatCritical')) el('topoStatCritical').textContent = critCount;
  if (el('topoStatHigh')) el('topoStatHigh').textContent = highCount;
  var svcs = {};
  data.nodes.forEach(function(n) { svcs[n.primary_service] = true; });
  if (el('topoStatServices')) el('topoStatServices').textContent = Object.keys(svcs).length;

  var empty = document.getElementById('topoEmpty');
  if (empty) empty.style.display = 'none';

  var container = document.getElementById('topoContainer');
  if (!container) return;
  container.innerHTML = '';

  var width = container.clientWidth || 800;
  var height = container.clientHeight || 600;

  var nodes = [];
  var links = [];
  var subnetMap = {};

  data.subnets.forEach(function(s) {
    var hubId = 'subnet_' + s.cidr;
    subnetMap[s.cidr] = hubId;
    nodes.push({
      id: hubId, type: 'subnet', label: s.cidr, subnet: s.cidr,
      r: 16, host_count: s.host_count
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
      ports_count: n.ports_count,
      r: Math.max(8, Math.sqrt(n.ports_count || 1) * 5),
      label: n.ip
    });
    var hubId = subnetMap[n.subnet];
    if (hubId) links.push({ source: nodeId, target: hubId });
  });

  var svg = d3.select(container).append('svg')
    .attr('width', width).attr('height', height)
    .attr('id', 'topoSvg')
    .style('background', 'var(--bg-main)');

  var g = svg.append('g').attr('class', 'topo-root');

  svg.call(d3.zoom()
    .scaleExtent([0.15, 5])
    .on('zoom', function(event) { g.attr('transform', event.transform); })
  );

  var hullGroup = g.append('g').attr('class', 'hulls');
  var linkGroup = g.append('g').attr('class', 'links');
  var nodeGroup = g.append('g').attr('class', 'nodes');
  var labelGroup = g.append('g').attr('class', 'labels');

  var linkSel = linkGroup.selectAll('line').data(links).enter().append('line')
    .attr('stroke', 'var(--border-dim)').attr('stroke-width', 1).attr('stroke-opacity', 0.4);

  var nodeSel = nodeGroup.selectAll('circle').data(nodes).enter().append('circle')
    .attr('r', function(d) { return d.r; })
    .attr('fill', function(d) { return WG._topoNodeColor(d); })
    .attr('stroke', function(d) { return d.type === 'subnet' ? 'var(--text-dim)' : 'rgba(255,255,255,0.15)'; })
    .attr('stroke-width', function(d) { return d.type === 'subnet' ? 2 : 1.5; })
    .attr('stroke-dasharray', function(d) { return d.type === 'subnet' ? '4,3' : 'none'; })
    .attr('cursor', function(d) { return d.type === 'host' ? 'pointer' : 'default'; })
    .attr('opacity', function(d) { return d.type === 'subnet' ? 0.6 : 1; })
    .on('mouseover', WG._topoShowTooltip)
    .on('mousemove', WG._topoMoveTooltip)
    .on('mouseout', WG._topoHideTooltip)
    .on('click', function(event, d) { if (d.type === 'host') WG._topoShowDetail(d); });

  var simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(function(d) { return d.id; }).distance(80).strength(0.7))
    .force('charge', d3.forceManyBody().strength(function(d) { return d.type === 'subnet' ? -400 : -150; }))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collide', d3.forceCollide().radius(function(d) { return d.r + 6; }))
    .alphaDecay(0.02);

  nodeSel.call(d3.drag()
    .on('start', function(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    })
    .on('drag', function(event, d) { d.fx = event.x; d.fy = event.y; })
    .on('end', function(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null; d.fy = null;
    })
  );

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
  });

  WG._topoState.simulation = simulation;
  WG._topoState.svg = svg;
  WG._topoState.nodeSel = nodeSel;
  WG._topoState.labelSel = labelSel;
  WG._topoState.linkSel = linkSel;
  WG._topoState.nodes = nodes;
  WG._topoState.links = links;
  WG._topoUpdateLegend();
};

/* ═══════════════ SUBNET HULLS ═══════════════ */

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
    .attr('d', function(d) { return 'M' + d.path.join('L') + 'Z'; });
  hulls.exit().remove();
};

/* ═══════════════ COLOR MODES ═══════════════ */

WG._topoNodeColor = function(d) {
  if (d.type === 'subnet') return 'var(--bg-card)';
  if (WG._topoState.colorMode === 'severity') {
    return WG._topoSeverityColors[d.worst_severity] || WG._topoSeverityColors.clean;
  }
  return WG._topoServiceColors[d.primary_service] || WG._topoServiceColors.other;
};

WG._topoSetColorMode = function(mode) {
  WG._topoState.colorMode = mode;
  if (WG._topoState.nodeSel) {
    WG._topoState.nodeSel.attr('fill', function(d) { return WG._topoNodeColor(d); });
  }
  WG._topoUpdateLegend();
};

WG._topoUpdateLegend = function() {
  var el = document.getElementById('topoLegend');
  if (!el) return;
  var esc = WG.escHtml;
  var mode = WG._topoState.colorMode;
  var colors = mode === 'severity' ? WG._topoSeverityColors : WG._topoServiceColors;
  var labels = mode === 'severity'
    ? { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', clean: 'Clean' }
    : WG._topoServiceLabels;

  el.innerHTML = Object.keys(colors).map(function(key) {
    return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">' +
      '<span style="width:10px;height:10px;border-radius:50%;background:' + colors[key] + ';flex-shrink:0;"></span>' +
      '<span style="font-size:0.72rem;color:var(--text-dim);">' + esc(labels[key] || key) + '</span></div>';
  }).join('');
};

/* ═══════════════ SERVICE FILTER ═══════════════ */

WG._topoToggleFilter = function(svc, show) {
  WG._topoState.filters[svc] = show;
  if (!WG._topoState.nodeSel) return;

  WG._topoState.nodeSel.attr('display', function(d) {
    if (d.type === 'subnet') return null;
    return WG._topoState.filters[d.primary_service] === false ? 'none' : null;
  });
  WG._topoState.labelSel.attr('display', function(d) {
    if (d.type === 'subnet') return null;
    return WG._topoState.filters[d.primary_service] === false ? 'none' : null;
  });
  WG._topoState.linkSel.attr('display', function(d) {
    var src = typeof d.source === 'object' ? d.source : null;
    if (src && src.type === 'host' && WG._topoState.filters[src.primary_service] === false) return 'none';
    return null;
  });
};

/* ═══════════════ TOOLTIP ═══════════════ */

WG._topoShowTooltip = function(event, d) {
  var tip = document.getElementById('topoTooltip');
  if (!tip) return;
  var esc = WG.escHtml;

  if (d.type === 'subnet') {
    tip.textContent = '';
    var t1 = document.createElement('div');
    t1.style.cssText = 'font-weight:600;color:var(--text-bright);';
    t1.textContent = d.label;
    var t2 = document.createElement('div');
    t2.style.cssText = 'color:var(--text-dim);margin-top:2px;';
    t2.textContent = d.host_count + ' hosts';
    tip.appendChild(t1); tip.appendChild(t2);
  } else {
    tip.textContent = '';
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
    var info = document.createElement('div');
    info.style.cssText = 'font-size:0.68rem;color:var(--text-dim);margin-top:4px;';
    info.textContent = d.ports_count + ' ports \u00b7 ' + d.findings_count + ' findings';
    tip.appendChild(info);
    var hint = document.createElement('div');
    hint.style.cssText = 'font-size:0.62rem;color:var(--text-dim);margin-top:3px;';
    hint.textContent = 'Click for details';
    tip.appendChild(hint);
  }
  tip.style.display = 'block';
  tip.style.left = (event.clientX + 14) + 'px';
  tip.style.top = (event.clientY - 10) + 'px';
};

WG._topoMoveTooltip = function(event) {
  var tip = document.getElementById('topoTooltip');
  if (tip) { tip.style.left = (event.clientX + 14) + 'px'; tip.style.top = (event.clientY - 10) + 'px'; }
};

WG._topoHideTooltip = function() {
  var tip = document.getElementById('topoTooltip');
  if (tip) tip.style.display = 'none';
};

/* ═══════════════ DETAIL PANEL ═══════════════ */

WG._topoShowDetail = function(d) {
  var panel = document.getElementById('topoDetail');
  var title = document.getElementById('topoDetailTitle');
  var body = document.getElementById('topoDetailBody');
  if (!panel || !body) return;
  var esc = WG.escHtml;

  title.textContent = d.ip + (d.hostname ? ' (' + d.hostname + ')' : '');
  panel.style.display = '';

  var portsHtml = (d.ports && d.ports.length) ?
    '<table class="data-table" style="font-size:0.78rem;"><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th></tr></thead><tbody>' +
    d.ports.map(function(p) {
      return '<tr><td class="mono">' + parseInt(p.number) + '</td><td>' + esc(p.protocol || 'tcp') + '</td>' +
        '<td>' + esc(p.service_name || '') + '</td><td>' + esc(p.service_product || '') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div style="color:var(--text-dim);font-size:0.8rem;">No port data</div>';

  var techHtml = (d.technologies && d.technologies.length) ?
    '<div style="display:flex;gap:6px;flex-wrap:wrap;">' +
    d.technologies.map(function(t) { return '<span class="tag">' + esc(t) + '</span>'; }).join('') + '</div>'
    : '';

  body.innerHTML = '' +
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;margin-bottom:16px;">' +
      '<div><span style="font-size:0.7rem;color:var(--text-dim);">OS</span><div style="font-size:0.85rem;color:var(--text-bright);">' + esc(d.os || 'Unknown') + '</div></div>' +
      '<div><span style="font-size:0.7rem;color:var(--text-dim);">Service</span><div style="font-size:0.85rem;color:' + (WG._topoServiceColors[d.primary_service] || '#6b7280') + ';">' + esc(WG._topoServiceLabels[d.primary_service] || d.primary_service) + '</div></div>' +
      '<div><span style="font-size:0.7rem;color:var(--text-dim);">Severity</span><div style="font-size:0.85rem;color:' + (WG._topoSeverityColors[d.worst_severity] || '#22c55e') + ';">' + esc(d.worst_severity || 'clean') + '</div></div>' +
      '<div><span style="font-size:0.7rem;color:var(--text-dim);">Findings</span><div style="font-size:0.85rem;color:var(--text-bright);">' +
        parseInt(d.findings_count) + ' <span style="font-size:0.7rem;color:var(--text-dim);">(' + parseInt(d.critical_count || 0) + 'C / ' + parseInt(d.high_count || 0) + 'H / ' + parseInt(d.medium_count || 0) + 'M)</span></div></div>' +
    '</div>' +
    (techHtml ? '<div style="margin-bottom:12px;">' + techHtml + '</div>' : '') +
    portsHtml +
    '<div style="margin-top:12px;"><button class="btn btn-secondary btn-sm" onclick="WG.navigate(\'host\',{id:\'' + d.dbId + '\'})">View Full Host Details</button></div>';
};

/* ═══════════════ EXPORT ═══════════════ */

WG._topoToggleExport = function() {
  var menu = document.getElementById('topoExportMenu');
  if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
};

WG._topoExportSVG = function() {
  var svg = document.getElementById('topoSvg');
  if (!svg) return;
  var clone = svg.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.style.background = '#0f1419';
  var blob = new Blob([new XMLSerializer().serializeToString(clone)], { type: 'image/svg+xml' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = 'wireghost-topology.svg'; a.click();
  URL.revokeObjectURL(url);
  WG._topoToggleExport();
  WG.toast('SVG exported', 'success');
};

WG._topoExportPNG = function() {
  var svg = document.getElementById('topoSvg');
  if (!svg) return;
  var clone = svg.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.style.background = '#0f1419';
  var svgData = new XMLSerializer().serializeToString(clone);
  var img = new Image();
  var w = parseInt(svg.getAttribute('width')) * 2;
  var h = parseInt(svg.getAttribute('height')) * 2;
  img.onload = function() {
    var canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#0f1419';
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    var a = document.createElement('a');
    a.href = canvas.toDataURL('image/png');
    a.download = 'wireghost-topology.png'; a.click();
    WG.toast('PNG exported', 'success');
  };
  img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
  WG._topoToggleExport();
};
