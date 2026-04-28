WG._topo = WG._topo || {};

WG._topoInitMinimap = function(container) {
  var panel = document.getElementById('topoGraphPanel');
  if (!panel) return;

  var existing = document.getElementById('topoMinimap');
  if (existing) existing.remove();

  var wrap = document.createElement('div');
  wrap.id = 'topoMinimapWrap';
  wrap.style.cssText = 'position:absolute;bottom:12px;right:12px;width:180px;height:120px;' +
    'border:1px solid var(--border-soft);border-radius:var(--radius-sm);' +
    'background:var(--bg-panel);overflow:hidden;z-index:10;opacity:0.85;';
  panel.appendChild(wrap);

  var miniSvg = d3.select(wrap).append('svg')
    .attr('id', 'topoMinimap')
    .attr('width', 180).attr('height', 120);

  miniSvg.append('g').attr('class', 'mini-nodes');

  var viewport = miniSvg.append('rect')
    .attr('class', 'mini-viewport')
    .attr('fill', 'var(--accent)')
    .attr('fill-opacity', 0.1)
    .attr('stroke', 'var(--accent)')
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.6)
    .attr('rx', 2);

  WG._topo.state.sel.minimap = { svg: miniSvg, viewport: viewport };
  WG._topo._miniTickCount = 0;
};

WG._topoUpdateMinimap = function(transform) {
  var s = WG._topo.state;
  if (!s.sel.minimap) return;

  var svg = s.svg;
  if (!svg) return;
  var w = parseInt(svg.attr('width')) || 800;
  var h = parseInt(svg.attr('height')) || 600;

  var bounds = WG._topoGetBounds(s.nodes);
  if (!bounds) return;

  var pad = 50;
  var bw = bounds.maxX - bounds.minX + pad * 2;
  var bh = bounds.maxY - bounds.minY + pad * 2;
  var scale = Math.min(180 / bw, 120 / bh);

  var vp = s.sel.minimap.viewport;
  var vw = (w / (transform ? transform.k : 1)) * scale;
  var vh = (h / (transform ? transform.k : 1)) * scale;
  var vx = (-(transform ? transform.x : 0) / (transform ? transform.k : 1) - bounds.minX + pad) * scale;
  var vy = (-(transform ? transform.y : 0) / (transform ? transform.k : 1) - bounds.minY + pad) * scale;

  vp.attr('x', vx).attr('y', vy).attr('width', Math.max(vw, 10)).attr('height', Math.max(vh, 8));
};

WG._topoUpdateMinimapNodes = function() {
  WG._topo._miniTickCount = (WG._topo._miniTickCount || 0) + 1;
  if (WG._topo._miniTickCount % 5 !== 0) return;

  var s = WG._topo.state;
  if (!s.sel.minimap) return;

  var hosts = s.nodes.filter(function(n) { return n.type === 'host' && n.x !== undefined; });
  var bounds = WG._topoGetBounds(s.nodes);
  if (!bounds) return;

  var pad = 50;
  var bw = bounds.maxX - bounds.minX + pad * 2;
  var bh = bounds.maxY - bounds.minY + pad * 2;
  var scale = Math.min(180 / bw, 120 / bh);

  var dots = s.sel.minimap.svg.select('.mini-nodes')
    .selectAll('circle').data(hosts, function(d) { return d.id; });

  dots.enter().append('circle')
    .attr('r', 2)
    .attr('fill', function(d) { return WG._topoNodeColor(d); })
    .merge(dots)
    .attr('cx', function(d) { return (d.x - bounds.minX + pad) * scale; })
    .attr('cy', function(d) { return (d.y - bounds.minY + pad) * scale; });

  dots.exit().remove();
};

WG._topoGetBounds = function(nodes) {
  var xs = [], ys = [];
  nodes.forEach(function(n) {
    if (n.x !== undefined) { xs.push(n.x); ys.push(n.y); }
  });
  if (!xs.length) return null;
  return {
    minX: Math.min.apply(null, xs), maxX: Math.max.apply(null, xs),
    minY: Math.min.apply(null, ys), maxY: Math.max.apply(null, ys)
  };
};
