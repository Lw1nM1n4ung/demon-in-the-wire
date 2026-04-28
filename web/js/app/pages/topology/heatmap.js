WG._topo = WG._topo || {};

WG._topoRiskScore = function(node) {
  return Math.min(100,
    (node.critical_count || 0) * 10 +
    (node.high_count || 0) * 5 +
    (node.medium_count || 0) * 2 +
    (node.low_count || 0)
  );
};

WG._topoInitHeatmap = function(svg) {
  var defs = svg.select('defs');
  if (defs.empty()) defs = svg.append('defs');

  var severities = [
    { key: 'critical', dev: 6 },
    { key: 'high', dev: 5 },
    { key: 'medium', dev: 4 },
    { key: 'low', dev: 3 },
    { key: 'clean', dev: 2 }
  ];

  severities.forEach(function(s) {
    var filter = defs.append('filter')
      .attr('id', 'topo-glow-' + s.key)
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%');
    filter.append('feGaussianBlur')
      .attr('in', 'SourceGraphic')
      .attr('stdDeviation', s.dev)
      .attr('result', 'blur');
    filter.append('feMerge')
      .selectAll('feMergeNode')
      .data(['blur', 'SourceGraphic'])
      .enter().append('feMergeNode')
      .attr('in', function(d) { return d; });
  });
};

WG._topoDrawHalos = function(haloGroup, nodes) {
  if (!haloGroup) return;
  var sevColors = WG._topoSeverityColors;
  var data = nodes.filter(function(d) {
    return d.type === 'host' && WG._topoRiskScore(d) > 0;
  });

  var halos = haloGroup.selectAll('circle.topo-halo')
    .data(data, function(d) { return d.id; });

  halos.enter().append('circle')
    .attr('class', 'topo-halo')
    .attr('pointer-events', 'none')
    .merge(halos)
    .attr('r', function(d) { return d.r + 8; })
    .attr('cx', function(d) { return d.x; })
    .attr('cy', function(d) { return d.y; })
    .attr('fill', function(d) {
      return sevColors[d.worst_severity] || sevColors.clean;
    })
    .attr('fill-opacity', function(d) {
      return (WG._topoRiskScore(d) / 100) * 0.45;
    })
    .attr('filter', function(d) {
      return 'url(#topo-glow-' + (d.worst_severity || 'clean') + ')';
    });

  halos.exit().remove();
};

WG._topoSetSizeMode = function(mode) {
  var s = WG._topo.state;
  s.sizeMode = mode;
  if (!s.sel.node) return;

  s.nodes.forEach(function(d) {
    if (d.type !== 'host') return;
    if (mode === 'risk') {
      d.r = Math.max(8, Math.sqrt(WG._topoRiskScore(d)) * 3);
    } else {
      d.r = Math.max(8, Math.sqrt(d.ports_count || 1) * 5);
    }
  });

  s.sel.node.transition().duration(400)
    .attr('r', function(d) { return d.r; });

  if (s.sel.halo) {
    s.sel.halo.selectAll('circle.topo-halo')
      .transition().duration(400)
      .attr('r', function(d) { return d.r + 8; });
  }

  if (s.simulation) s.simulation.force('collide').initialize(s.nodes);
};
