WG._topo = WG._topo || {};

WG._topoInitEdges = function(g, data) {
  WG._topo._edges = data.edges || [];
  WG._topo._edgeGroup = g.insert('g', '.links').attr('class', 'related-edges');
  WG._topo._edgeGroup.style('display', 'none');

  var nodeMap = {};
  WG._topo.state.nodes.forEach(function(n) {
    if (n.dbId) nodeMap[String(n.dbId)] = n;
  });

  var edgeSel = WG._topo._edgeGroup.selectAll('line.topo-edge')
    .data(WG._topo._edges)
    .enter().append('line')
    .attr('class', 'topo-edge')
    .attr('stroke', function(d) {
      return d.type === 'cve' ? 'var(--critical-dim)' : 'var(--accent-dim)';
    })
    .attr('stroke-width', 1.5)
    .attr('stroke-dasharray', '6,3')
    .attr('stroke-opacity', 0.3);

  WG._topo._edgeSel = edgeSel;
  WG._topo._edgeNodeMap = nodeMap;
  WG._topo.state.sel.edge = edgeSel;
};

WG._topoUpdateEdgePositions = function() {
  if (!WG._topo._edgeSel || !WG._topo.state.edgesVisible) return;
  var nm = WG._topo._edgeNodeMap;

  WG._topo._edgeSel
    .attr('x1', function(d) { var n = nm[d.source]; return n ? n.x : 0; })
    .attr('y1', function(d) { var n = nm[d.source]; return n ? n.y : 0; })
    .attr('x2', function(d) { var n = nm[d.target]; return n ? n.x : 0; })
    .attr('y2', function(d) { var n = nm[d.target]; return n ? n.y : 0; });
};

WG._topoToggleEdges = function(visible) {
  WG._topo.state.edgesVisible = visible;
  if (WG._topo._edgeGroup) {
    WG._topo._edgeGroup.style('display', visible ? null : 'none');
    if (visible) WG._topoUpdateEdgePositions();
  }
};
