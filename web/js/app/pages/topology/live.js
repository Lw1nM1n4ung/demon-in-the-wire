WG._topo = WG._topo || {};

WG._topoStartPolling = function(scanId) {
  WG._topoStopPolling();
  var s = WG._topo.state;

  s.pollHandle = setInterval(function() {
    WG.api('/scans/' + scanId + '/').then(function(scan) {
      if (!scan) return;

      if (scan.status !== 'running') {
        WG._topoStopPolling();
        WG.toast('Scan complete', 'success');
        WG.api('/scans/' + scanId + '/topology/').then(function(data) {
          if (data && data.nodes) WG._topoMergeUpdate(data);
        });
        return;
      }

      WG.api('/scans/' + scanId + '/topology/').then(function(data) {
        if (!data || !data.nodes) return;
        WG._topoMergeUpdate(data);
      });
    });
  }, 4000);
};

WG._topoStopPolling = function() {
  var s = WG._topo.state;
  if (s.pollHandle) {
    clearInterval(s.pollHandle);
    s.pollHandle = null;
  }
};

WG._topoMergeUpdate = function(data) {
  var s = WG._topo.state;
  if (!s.sel.node || !s.data) return;

  var existingIds = {};
  s.data.nodes.forEach(function(n) { existingIds[n.id] = true; });

  var newNodes = [];
  data.nodes.forEach(function(n) {
    if (!existingIds[n.id]) newNodes.push(n);
  });

  if (!newNodes.length) return;

  s.data = data;

  newNodes.forEach(function(n) {
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
      risk_score: n.risk_score, cves: n.cves || [],
      r: Math.max(8, Math.sqrt(n.ports_count || 1) * 5),
      label: n.ip
    });

    var hubId = 'subnet_' + n.subnet;
    var hubExists = s.nodes.some(function(nn) { return nn.id === hubId; });
    if (hubExists) {
      s.links.push({ source: nodeId, target: hubId });
    }
  });

  WG._topoRebindGraph();

  if (s.sel.node) {
    s.sel.node.filter(function(d) {
      return newNodes.some(function(n) { return 'host_' + n.id === d.id; });
    })
    .attr('opacity', 0)
    .transition().duration(600)
    .attr('opacity', 1);
  }
};
