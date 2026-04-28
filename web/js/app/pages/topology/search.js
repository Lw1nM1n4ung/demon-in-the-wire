WG._topo = WG._topo || {};

WG._topoBuildSearchIndex = function(data) {
  WG._topo.state.searchIndex = (data.nodes || []).map(function(n) {
    var tokens = [
      n.ip, n.hostname || '', n.primary_service || '',
      String(n.ports_count || ''),
      (n.cves || []).join(' ')
    ];
    if (n.ports) {
      n.ports.forEach(function(p) {
        tokens.push(String(p.number));
        if (p.service_name) tokens.push(p.service_name);
      });
    }
    return { nodeId: 'host_' + n.id, tokens: tokens.join(' ').toLowerCase() };
  });
};

WG._topo._searchTimer = null;

WG._topoSearch = function(query) {
  clearTimeout(WG._topo._searchTimer);
  WG._topo._searchTimer = setTimeout(function() {
    WG._topoSearchExec(query);
  }, 150);
};

WG._topoSearchExec = function(query) {
  var s = WG._topo.state;
  if (!s.sel.node) return;
  var q = (query || '').toLowerCase().trim();

  if (!q) {
    s.sel.node.classed('topo-matched', false).classed('topo-dimmed', false);
    if (s.sel.label) s.sel.label.classed('topo-dimmed', false);
    if (s.sel.link) s.sel.link.classed('topo-dimmed', false);
    if (s.sel.hull) s.sel.hull.classed('topo-dimmed', false);
    return;
  }

  var matched = {};
  s.searchIndex.forEach(function(entry) {
    if (entry.tokens.indexOf(q) !== -1) matched[entry.nodeId] = true;
  });

  s.sel.node
    .classed('topo-matched', function(d) { return !!matched[d.id]; })
    .classed('topo-dimmed', function(d) {
      return d.type === 'host' && !matched[d.id];
    });

  if (s.sel.label) {
    s.sel.label.classed('topo-dimmed', function(d) {
      return d.type === 'host' && !matched[d.id];
    });
  }
  if (s.sel.link) {
    s.sel.link.classed('topo-dimmed', function(d) {
      var src = typeof d.source === 'object' ? d.source : null;
      return src && src.type === 'host' && !matched[src.id];
    });
  }
};

WG._topoSearchClear = function() {
  var inp = document.getElementById('topoSearch');
  if (inp) inp.value = '';
  WG._topoSearchExec('');
};
