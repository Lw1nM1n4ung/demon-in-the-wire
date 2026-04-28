WG._topo = WG._topo || {};

WG._topoExpandHost = function(d) {
  if (d.type !== 'host') return;
  var s = WG._topo.state;
  var hostId = d.id;

  var idx = s.expandedHosts.indexOf(hostId);
  if (idx !== -1) {
    WG._topoCollapseHost(hostId);
    return;
  }

  if (s.expandedHosts.length >= 3) {
    WG._topoCollapseHost(s.expandedHosts[0]);
  }

  s.expandedHosts.push(hostId);

  var ports = d.ports || [];
  if (!ports.length) return;

  var angle = (2 * Math.PI) / ports.length;

  ports.forEach(function(p, i) {
    var portId = 'port_' + d.dbId + '_' + p.number;
    var dist = d.r + 25;
    s.nodes.push({
      id: portId, type: 'port',
      portNumber: p.number, protocol: p.protocol || 'tcp',
      serviceName: p.service_name || '', hostId: hostId,
      r: 5, label: String(p.number),
      x: d.x + Math.cos(angle * i) * dist,
      y: d.y + Math.sin(angle * i) * dist
    });
    s.links.push({
      source: portId, target: hostId, linkType: 'satellite'
    });
  });

  WG._topoRebindGraph();
};

WG._topoCollapseHost = function(hostId) {
  var s = WG._topo.state;
  var idx = s.expandedHosts.indexOf(hostId);
  if (idx !== -1) s.expandedHosts.splice(idx, 1);

  s.nodes = s.nodes.filter(function(n) { return n.hostId !== hostId; });
  s.links = s.links.filter(function(l) {
    var src = typeof l.source === 'object' ? l.source : { id: l.source, type: '', hostId: '' };
    return !(src.type === 'port' && src.hostId === hostId);
  });

  WG._topoRebindGraph();
};

WG._topoRebindGraph = function() {
  var s = WG._topo.state;
  if (!s.simulation || !s.sel.node) return;

  var container = s.svg.select('.nodes');
  var linkContainer = s.svg.select('.links');
  var labelContainer = s.svg.select('.labels');

  s.sel.link = linkContainer.selectAll('line').data(s.links, function(d) {
    var src = typeof d.source === 'object' ? d.source.id : d.source;
    var tgt = typeof d.target === 'object' ? d.target.id : d.target;
    return src + '-' + tgt;
  });
  s.sel.link.exit().remove();
  s.sel.link = s.sel.link.enter().append('line')
    .attr('stroke', function(d) {
      return d.linkType === 'satellite' ? 'var(--accent-dim)' : 'var(--border-dim)';
    })
    .attr('stroke-width', function(d) { return d.linkType === 'satellite' ? 0.8 : 1; })
    .attr('stroke-opacity', 0.4)
    .merge(s.sel.link);

  s.sel.node = container.selectAll('circle').data(s.nodes, function(d) { return d.id; });
  s.sel.node.exit().remove();
  var enter = s.sel.node.enter().append('circle')
    .attr('r', 0).attr('opacity', 0)
    .attr('fill', function(d) {
      if (d.type === 'port') {
        return WG._topoServiceColors[d.serviceName] || WG._topoServiceColors.other;
      }
      return WG._topoNodeColor(d);
    })
    .attr('stroke', 'rgba(255,255,255,0.15)')
    .attr('stroke-width', 1)
    .attr('cursor', function(d) { return d.type === 'host' ? 'pointer' : 'default'; })
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
      }
    })
    .on('contextmenu', function(event, d) {
      if (d.type === 'host' && WG._topoContextMenu) WG._topoContextMenu(event, d);
    });

  enter.call(d3.drag()
    .on('start', function(event, d) {
      if (!event.active) s.simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    })
    .on('drag', function(event, d) { d.fx = event.x; d.fy = event.y; })
    .on('end', function(event, d) {
      if (!event.active) s.simulation.alphaTarget(0);
      d.fx = null; d.fy = null;
    })
  );

  enter.transition().duration(300).ease(d3.easeCubicOut)
    .attr('r', function(d) { return d.r; })
    .attr('opacity', 1);

  s.sel.node = enter.merge(s.sel.node);

  s.sel.label = labelContainer.selectAll('text').data(s.nodes, function(d) { return d.id; });
  s.sel.label.exit().remove();
  s.sel.label = s.sel.label.enter().append('text')
    .text(function(d) { return d.label; })
    .attr('font-size', function(d) { return d.type === 'port' ? '7px' : d.type === 'subnet' ? '10px' : '8px'; })
    .attr('font-family', 'var(--font-mono)')
    .attr('fill', 'var(--text-dim)')
    .attr('text-anchor', 'middle')
    .attr('dy', function(d) { return d.r + 12; })
    .attr('pointer-events', 'none')
    .merge(s.sel.label);

  s.simulation.nodes(s.nodes);
  s.simulation.force('link').links(s.links);
  s.simulation.alpha(0.3).restart();

  if (WG._topo._edgeNodeMap) {
    var nm = {};
    s.nodes.forEach(function(n) { if (n.dbId) nm[String(n.dbId)] = n; });
    WG._topo._edgeNodeMap = nm;
  }
};
