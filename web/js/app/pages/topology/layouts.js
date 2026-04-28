WG._topo = WG._topo || {};

WG._topoSetLayout = function(mode) {
  var s = WG._topo.state;
  s.layoutMode = mode;

  document.querySelectorAll('.topo-layout-btn').forEach(function(btn) {
    btn.classList.toggle('active', btn.getAttribute('data-layout') === mode);
  });

  if (mode === 'force') {
    s.nodes.forEach(function(d) { d.fx = null; d.fy = null; });
    if (s.simulation) s.simulation.alpha(0.5).restart();
    return;
  }

  if (s.simulation) s.simulation.stop();

  var hosts = s.nodes.filter(function(n) { return n.type === 'host'; });
  var subnets = s.nodes.filter(function(n) { return n.type === 'subnet' || n.type === 'cluster'; });
  var svg = s.svg;
  if (!svg) return;
  var width = parseInt(svg.attr('width')) || 800;
  var height = parseInt(svg.attr('height')) || 600;
  var cx = width / 2, cy = height / 2;

  if (mode === 'grid') {
    hosts.sort(function(a, b) {
      if (a.subnet !== b.subnet) return a.subnet < b.subnet ? -1 : 1;
      return (a.ip || '').localeCompare(b.ip || '');
    });
    var cols = Math.ceil(Math.sqrt(hosts.length));
    var spacing = 80;
    var ox = cx - (cols * spacing) / 2;
    var oy = cy - (Math.ceil(hosts.length / cols) * spacing) / 2;
    hosts.forEach(function(d, i) {
      d.targetX = ox + (i % cols) * spacing;
      d.targetY = oy + Math.floor(i / cols) * spacing;
    });
    subnets.forEach(function(d) {
      var children = hosts.filter(function(h) { return h.subnet === d.subnet || d.id === 'subnet_' + h.subnet; });
      if (children.length) {
        d.targetX = children.reduce(function(s, c) { return s + c.targetX; }, 0) / children.length;
        d.targetY = children[0].targetY - 60;
      }
    });
  } else if (mode === 'hierarchical') {
    var subnetKeys = [];
    subnets.forEach(function(sn) { subnetKeys.push(sn.subnet || sn.id.replace('subnet_', '')); });
    var xStep = width / (subnetKeys.length + 1);

    subnetKeys.forEach(function(sk, si) {
      var subnetNode = subnets.find(function(sn) { return sn.subnet === sk || sn.id === 'subnet_' + sk; });
      if (subnetNode) {
        subnetNode.targetX = xStep * (si + 1);
        subnetNode.targetY = 80;
      }
      var children = hosts.filter(function(h) { return h.subnet === sk; });
      var yStep = (height - 160) / (children.length + 1);
      children.forEach(function(h, hi) {
        h.targetX = xStep * (si + 1) + (Math.random() - 0.5) * 30;
        h.targetY = 140 + yStep * (hi + 1);
      });
    });
  } else if (mode === 'radial') {
    var subnetList = [];
    subnets.forEach(function(sn) { subnetList.push(sn); });
    var ringAngle = (2 * Math.PI) / Math.max(subnetList.length, 1);

    subnetList.forEach(function(sn, si) {
      var a = ringAngle * si - Math.PI / 2;
      sn.targetX = cx + Math.cos(a) * 120;
      sn.targetY = cy + Math.sin(a) * 120;

      var children = hosts.filter(function(h) {
        return h.subnet === (sn.subnet || sn.id.replace('subnet_', ''));
      });
      var childAngle = (2 * Math.PI) / Math.max(children.length, 1);
      children.forEach(function(h, hi) {
        var ca = a + childAngle * hi - Math.PI;
        var dist = 120 + 80 + (hi % 2) * 30;
        h.targetX = cx + Math.cos(ca) * dist;
        h.targetY = cy + Math.sin(ca) * dist;
      });
    });
  }

  s.nodes.forEach(function(d) {
    if (d.targetX === undefined) return;
  });

  if (s.sel.node) {
    s.sel.node.transition().duration(600).ease(d3.easeCubicOut)
      .attr('cx', function(d) { return d.targetX !== undefined ? d.targetX : d.x; })
      .attr('cy', function(d) { return d.targetY !== undefined ? d.targetY : d.y; })
      .on('end', function(d) {
        if (d.targetX !== undefined) { d.x = d.targetX; d.fx = d.targetX; }
        if (d.targetY !== undefined) { d.y = d.targetY; d.fy = d.targetY; }
      });
  }
  if (s.sel.label) {
    s.sel.label.transition().duration(600).ease(d3.easeCubicOut)
      .attr('x', function(d) { return d.targetX !== undefined ? d.targetX : d.x; })
      .attr('y', function(d) { return d.targetY !== undefined ? d.targetY : d.y; });
  }
  if (s.sel.link) {
    setTimeout(function() {
      s.sel.link
        .attr('x1', function(d) { var n = typeof d.source === 'object' ? d.source : null; return n ? n.x : 0; })
        .attr('y1', function(d) { var n = typeof d.source === 'object' ? d.source : null; return n ? n.y : 0; })
        .attr('x2', function(d) { var n = typeof d.target === 'object' ? d.target : null; return n ? n.x : 0; })
        .attr('y2', function(d) { var n = typeof d.target === 'object' ? d.target : null; return n ? n.y : 0; });
    }, 620);
  }
  if (s.sel.halo) {
    s.sel.halo.selectAll('.topo-halo').transition().duration(600).ease(d3.easeCubicOut)
      .attr('cx', function(d) { return d.targetX !== undefined ? d.targetX : d.x; })
      .attr('cy', function(d) { return d.targetY !== undefined ? d.targetY : d.y; });
  }

  setTimeout(function() { WG._topoZoomToFit(500); }, 650);
};
