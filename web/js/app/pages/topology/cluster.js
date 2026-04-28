WG._topo = WG._topo || {};

WG._topoAutoCluster = function(nodes, threshold) {
  threshold = threshold || 50;
  if (nodes.length < threshold) return nodes;

  var subnets = {};
  var nonHost = [];

  nodes.forEach(function(n) {
    if (n.type === 'host') {
      if (!subnets[n.subnet]) subnets[n.subnet] = [];
      subnets[n.subnet].push(n);
    } else {
      nonHost.push(n);
    }
  });

  var result = nonHost.slice();

  Object.keys(subnets).forEach(function(subnet) {
    var hosts = subnets[subnet];
    if (hosts.length <= 5) {
      result = result.concat(hosts);
      return;
    }

    var totalRisk = 0;
    var worstSev = 'clean';
    var sevOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1, clean: 0 };
    var hostIds = [];

    hosts.forEach(function(h) {
      totalRisk += WG._topoRiskScore ? WG._topoRiskScore(h) : 0;
      hostIds.push(h.id);
      if ((sevOrder[h.worst_severity] || 0) > (sevOrder[worstSev] || 0)) {
        worstSev = h.worst_severity;
      }
    });

    result.push({
      id: 'cluster_' + subnet,
      type: 'cluster',
      subnet: subnet,
      hostIds: hostIds,
      host_count: hosts.length,
      worst_severity: worstSev,
      total_risk: totalRisk,
      label: subnet + ' (' + hosts.length + ')',
      r: 20 + Math.log(hosts.length) * 6
    });
  });

  return result;
};

WG._topoExpandCluster = function(clusterNode) {
  if (!clusterNode || clusterNode.type !== 'cluster') return;
  var s = WG._topo.state;
  var data = s.data;
  if (!data) return;

  var idx = s.nodes.indexOf(clusterNode);
  if (idx === -1) return;

  s.nodes.splice(idx, 1);

  var subnet = clusterNode.subnet;
  data.nodes.forEach(function(n) {
    if (n.subnet !== subnet) return;
    var nodeId = 'host_' + n.id;
    s.nodes.push({
      id: nodeId, type: 'host', dbId: n.id,
      ip: n.ip, hostname: n.hostname, os: n.os,
      subnet: n.subnet, primary_service: n.primary_service,
      worst_severity: n.worst_severity,
      ports: n.ports, technologies: n.technologies,
      findings_count: n.findings_count,
      critical_count: n.critical_count,
      high_count: n.high_count, medium_count: n.medium_count,
      low_count: n.low_count, ports_count: n.ports_count,
      risk_score: n.risk_score,
      cves: n.cves || [],
      r: Math.max(8, Math.sqrt(n.ports_count || 1) * 5),
      label: n.ip,
      x: clusterNode.x + (Math.random() - 0.5) * 40,
      y: clusterNode.y + (Math.random() - 0.5) * 40
    });

    var hubId = 'subnet_' + n.subnet;
    s.links.push({ source: nodeId, target: hubId });
  });

  WG._topoRebindGraph();
};

WG._topoCollapseCluster = function(subnet) {
  var s = WG._topo.state;
  var removed = [];
  s.nodes = s.nodes.filter(function(n) {
    if (n.type === 'host' && n.subnet === subnet) {
      removed.push(n);
      return false;
    }
    return true;
  });

  s.links = s.links.filter(function(l) {
    var src = typeof l.source === 'object' ? l.source : { id: l.source, type: '' };
    if (src.type === 'host' && src.subnet === subnet) return false;
    if (typeof l.source === 'string' && l.source.indexOf('host_') === 0) {
      var node = s.nodes.find(function(n) { return n.id === l.source; });
      if (!node) return false;
    }
    return true;
  });

  if (removed.length) {
    var cluster = WG._topoAutoCluster(removed, 0);
    if (cluster.length === 1 && cluster[0].type === 'cluster') {
      s.nodes.push(cluster[0]);
      var hubId = 'subnet_' + subnet;
      s.links.push({ source: cluster[0].id, target: hubId });
    }
  }

  WG._topoRebindGraph();
};
