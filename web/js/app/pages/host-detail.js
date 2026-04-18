/* Wire_Ghost — Host detail page */

WG.renderHostDetail = function(id) {
  // Fetch full host detail from API (once per cache cycle)
  /* Fetch host from API; show "not found" if 404 instead of spinning forever.
     Note: innerHTML here uses only static strings (no user input), safe from XSS. */
  if (!WG._cache['host_' + id]) {
    WG.api('/hosts/' + id + '/').then(function(data) {
      if (WG.state.currentPage === 'host') {
        var main = document.getElementById('mainContent');
        if (data) {
          WG._cache['host_' + id] = data;
          WG._cacheTime['host_' + id] = Date.now();
          if (main && !document.querySelector(".modal-overlay.active")) main.innerHTML = WG.renderHostDetail(id);
        } else if (main) {
          main.innerHTML = '<div class="empty-state"><div class="icon">&#9678;</div><h3>Host not found</h3><p>This host may have been deleted or belongs to another scan.</p><button class="btn btn-secondary" style="margin-top:16px;" onclick="WG.navigate(\'hosts\')">Back to Hosts</button></div>';
        }
      }
    });
  }

  var host = WG._cache['host_' + id] || WG.getCached('hosts', '/hosts/').find(function(h) { return h.id === id; });
  if (!host) return '<div class="empty-state"><div class="icon">&#9678;</div><h3>Loading host...</h3><div class="spinner" style="margin:16px auto;"></div></div>';

  var esc = WG.escHtml;
  var scan = WG.getCached('scans', '/scans/').find(function(s) { return s.id === host.scan; });
  var ports = host.ports || [].filter(function(p) { return p.host === id; });
  var techs = host.technologies || [].filter(function(t) { return t.host === id; });
  var hFindings = WG.getCached('host_findings_' + id, '/findings/?scan=' + (host.scan || ''), 'findings').filter(function(f) { return f.host === id || f.host_ip === host.ip; });

  var sevCards = ['critical','high','medium','low','info'].map(function(sev) {
    var count = hFindings.filter(function(f) { return f.severity === sev; }).length;
    return '<div class="stat-card ' + sev + '"><div class="stat-label">' + sev + '</div><div class="stat-value">' + count + '</div></div>';
  }).join('');

  return '' +
    '<div class="breadcrumbs"><a onclick="WG.navigate(\'scans\')">Scans</a><span class="sep">/</span><a onclick="WG.navigate(\'scan\',{id:\'' + host.scan + '\'})">' + esc(scan ? scan.name : 'Scan') + '</a><span class="sep">/</span><span>' + esc(host.ip) + '</span></div>' +
    '<div class="page-header"><div class="page-header-left"><h1>' + esc(host.ip) + '</h1><p>' + esc(host.hostname || 'No hostname') + ' &mdash; ' + esc(host.os || 'Unknown OS') + '</p></div></div>' +
    '<div class="info-grid" style="margin-bottom:24px;">' +
      '<div class="info-item"><div class="info-label">IP Address</div><div class="info-value mono">' + host.ip + '</div></div>' +
      '<div class="info-item"><div class="info-label">Hostname</div><div class="info-value">' + (host.hostname || '\u2014') + '</div></div>' +
      '<div class="info-item"><div class="info-label">OS</div><div class="info-value"><span class="tag">' + (host.os || '\u2014') + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Open Ports</div><div class="info-value mono">' + host.ports_count + '</div></div>' +
      '<div class="info-item"><div class="info-label">Findings</div><div class="info-value mono">' + host.findings_count + '</div></div>' +
      '<div class="info-item"><div class="info-label">Scan</div><div class="info-value"><a onclick="WG.navigate(\'scan\',{id:\'' + host.scan + '\'})">' + esc(scan ? scan.name : '') + '</a></div></div>' +
    '</div>' +
    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:24px;">' + sevCards + '</div>' +
    '<div class="tabs" id="hostTabs">' +
      '<div class="tab active" data-tab="ports" onclick="WG.switchHostTab(\'ports\',\'' + id + '\')">Ports <span class="count">' + ports.length + '</span></div>' +
      '<div class="tab" data-tab="findings" onclick="WG.switchHostTab(\'findings\',\'' + id + '\')">Findings <span class="count">' + hFindings.length + '</span></div>' +
      '<div class="tab" data-tab="tech" onclick="WG.switchHostTab(\'tech\',\'' + id + '\')">Technologies <span class="count">' + techs.length + '</span></div>' +
    '</div>' +
    '<div id="hostTabContent">' + WG._hostPortsTab(ports) + '</div>';
};

WG._hostPortsTab = function(ports) {
  if (!ports.length) return '<div class="panel-empty"><div class="icon">&#8862;</div>No open ports</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>' +
    ports.map(function(p) {
      return '<tr>' +
        '<td class="mono" style="font-weight:600;color:var(--text-bright);">' + p.number + '</td>' +
        '<td class="mono">' + p.protocol + '</td>' +
        '<td><span class="status-badge completed" style="font-size:0.65rem;padding:2px 7px;">' + p.state + '</span></td>' +
        '<td>' + esc(p.service_name) + '</td>' +
        '<td>' + (esc(p.service_product) || '<span style="color:var(--text-dim)">\u2014</span>') + '</td>' +
        '<td class="mono">' + (esc(p.service_version) || '\u2014') + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG._hostTechTab = function(techs) {
  if (!techs.length) return '<div class="panel-empty"><div class="icon">&#9881;</div>No technologies detected</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>Technology</th><th>Version</th><th>URL</th></tr></thead><tbody>' +
    techs.map(function(t) {
      return '<tr><td style="font-weight:600;color:var(--text-bright);">' + esc(t.name) + '</td><td class="mono">' + (esc(t.version) || '\u2014') + '</td><td class="mono" style="font-size:0.75rem;">' + esc(t.url) + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG.switchHostTab = function(tab, hostId) {
  document.querySelectorAll('#hostTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('hostTabContent');
  if (tab === 'ports') el.innerHTML = WG._hostPortsTab([].filter(function(p) { return p.host === hostId; }));
  else if (tab === 'findings') el.innerHTML = WG._scanFindingsTab([].filter(function(f) { return f.host === hostId; }));
  else if (tab === 'tech') el.innerHTML = WG._hostTechTab([].filter(function(t) { return t.host === hostId; }));
};
