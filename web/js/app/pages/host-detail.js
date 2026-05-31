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
  var ports = host.ports || [];
  var techs = host.technologies || [];
  var hFindings = WG.getCached('host_findings_' + id, '/findings/?scan=' + (host.scan || ''), 'findings').filter(function(f) { return f.host === id || f.host_ip === host.ip; });
  var hostArts = WG._cache['host_artifacts_' + id] || [];

  // Fetch artifacts for this host (background — updates count badge and tab content on next render)
  if (!WG._cache['host_artifacts_' + id]) {
    WG.api('/artifacts/?host=' + id).then(function(arts) {
      if (arts) {
        WG._cache['host_artifacts_' + id] = arts;
        WG._cacheTime['host_artifacts_' + id] = Date.now();
        var badge = document.getElementById('hostArtifactCount');
        if (badge) badge.textContent = arts.length;
      }
    });
  }

  var sevCards = ['critical','high','medium','low','info'].map(function(sev) {
    var count = hFindings.filter(function(f) { return f.severity === sev; }).length;
    return '<div class="stat-card ' + sev + '"><div class="stat-label">' + sev + '</div><div class="stat-value">' + count + '</div></div>';
  }).join('');

  return '' +
    '<div class="breadcrumbs"><a onclick="WG.navigate(\'scans\')">Scans</a><span class="sep">/</span><a onclick="WG.navigate(\'scan\',{id:\'' + host.scan + '\'})">' + esc(scan ? scan.name : 'Scan') + '</a><span class="sep">/</span><span>' + esc(host.ip) + '</span></div>' +
    '<div class="page-header"><div class="page-header-left"><h1>' + esc(host.ip) + '</h1><p>' + esc(host.hostname || 'No hostname') + ' &mdash; ' + esc(host.os || 'Unknown OS') + '</p></div></div>' +
    '<div class="info-grid" style="margin-bottom:24px;">' +
      '<div class="info-item"><div class="info-label">IP Address</div><div class="info-value mono">' + esc(host.ip) + '</div></div>' +
      '<div class="info-item"><div class="info-label">Hostname</div><div class="info-value">' + esc(host.hostname || '\u2014') + '</div></div>' +
      '<div class="info-item"><div class="info-label">MAC Address</div><div class="info-value mono">' + esc(host.mac_address || '\u2014') + '</div></div>' +
      '<div class="info-item"><div class="info-label">Vendor</div><div class="info-value">' + esc(host.vendor || '\u2014') + '</div></div>' +
      (function() {
        var m = host.discovery_method || '';
        var badge = '';
        if (m === 'nmap') badge = '<span style="font-size:0.65rem;padding:2px 8px;border-radius:3px;background:rgba(59,130,246,0.15);color:#60a5fa;">nmap</span>';
        else if (m === 'fping') badge = '<span style="font-size:0.65rem;padding:2px 8px;border-radius:3px;background:rgba(52,211,153,0.15);color:#34d399;">fping</span>';
        else if (m === 'fping_unreachable') badge = '<span style="font-size:0.65rem;padding:2px 8px;border-radius:3px;background:rgba(251,191,36,0.15);color:#fbbf24;">unreachable</span>';
        else if (m === 'arp') badge = '<span style="font-size:0.65rem;padding:2px 8px;border-radius:3px;background:rgba(168,85,247,0.15);color:#a855f7;">ARP</span>';
        return '<div class="info-item"><div class="info-label">Discovery Method</div><div class="info-value">' + (badge || '<span style="color:var(--text-dim)">\u2014</span>') + '</div></div>';
      })() +
      '<div class="info-item"><div class="info-label">OS</div><div class="info-value"><span class="tag">' + esc(host.os || '\u2014') + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Open Ports</div><div class="info-value mono">' + host.ports_count + '</div></div>' +
      '<div class="info-item"><div class="info-label">Findings</div><div class="info-value mono">' + host.findings_count + '</div></div>' +
      '<div class="info-item"><div class="info-label">Scan</div><div class="info-value"><a onclick="WG.navigate(\'scan\',{id:\'' + host.scan + '\'})">' + esc(scan ? scan.name : '') + '</a></div></div>' +
    '</div>' +
    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:24px;">' + sevCards + '</div>' +
    '<div class="tabs" id="hostTabs">' +
      '<div class="tab active" data-tab="ports" onclick="WG.switchHostTab(\'ports\',\'' + id + '\')">Ports <span class="count">' + ports.length + '</span></div>' +
      '<div class="tab" data-tab="findings" onclick="WG.switchHostTab(\'findings\',\'' + id + '\')">Findings <span class="count">' + hFindings.length + '</span></div>' +
      '<div class="tab" data-tab="tech" onclick="WG.switchHostTab(\'tech\',\'' + id + '\')">Technologies <span class="count">' + techs.length + '</span></div>' +
      ((host.screenshots && host.screenshots.length) ? '<div class="tab" data-tab="screenshots" onclick="WG.switchHostTab(\'screenshots\',\'' + id + '\')">Screenshots <span class="count">' + host.screenshots.length + '</span></div>' : '') +
      '<div class="tab" data-tab="artifacts" onclick="WG.switchHostTab(\'artifacts\',\'' + id + '\')">Artifacts <span class="count" id="hostArtifactCount">' + hostArts.length + '</span></div>' +
    '</div>' +
    '<div id="hostTabContent">' + WG._hostPortsTab(ports) + '</div>';
};

WG._hostPortsTab = function(ports) {
  if (!ports.length) return '<div class="panel-empty"><div class="icon">&#8862;</div>No open ports</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Source</th></tr></thead><tbody>' +
    ports.map(function(p) {
      var src = p.service_source || '';
      var srcBadge = '';
      if (src === 'nmap') srcBadge = '<span style="font-size:0.6rem;padding:1px 6px;border-radius:3px;background:rgba(59,130,246,0.15);color:#60a5fa;">nmap</span>';
      else if (src === 'fingerprintx') srcBadge = '<span style="font-size:0.6rem;padding:1px 6px;border-radius:3px;background:rgba(52,211,153,0.15);color:#34d399;">fpx</span>';
      else srcBadge = '<span style="color:var(--text-dim)">\u2014</span>';
      return '<tr>' +
        '<td class="mono" style="font-weight:600;color:var(--text-bright);">' + esc(p.number) + '</td>' +
        '<td class="mono">' + esc(p.protocol) + '</td>' +
        '<td><span class="status-badge completed" style="font-size:0.65rem;padding:2px 7px;">' + esc(p.state) + '</span></td>' +
        '<td>' + esc(p.service_name) + '</td>' +
        '<td>' + (esc(p.service_product) || '<span style="color:var(--text-dim)">\u2014</span>') + '</td>' +
        '<td class="mono">' + (esc(p.service_version) || '\u2014') + '</td>' +
        '<td>' + srcBadge + '</td></tr>';
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

WG._hostScreenshotsTab = function(screenshots) {
  if (!screenshots || !screenshots.length) return '<div class="panel-empty"><div class="icon">&#128247;</div>No screenshots captured</div>';
  var esc = WG.escHtml;
  var cards = screenshots.map(function(ss, i) {
    var statusClass = ss.status_code < 300 ? 'tag-success' : ss.status_code < 400 ? 'tag-warning' : 'tag-danger';
    return '<div class="screenshot-card" data-ss-idx="' + i + '">' +
      '<img src="' + esc(ss.image_url) + '" loading="lazy" alt="screenshot">' +
      '<div class="screenshot-card-info">' +
      '<div class="url">' + esc(ss.url) + '</div>' +
      (ss.title ? '<div class="title">' + esc(ss.title) + '</div>' : '') +
      (ss.status_code ? '<span class="tag ' + statusClass + '">' + ss.status_code + '</span>' : '') +
      '</div></div>';
  });
  return '<div class="screenshot-gallery">' + cards.join('') + '</div>';
};

WG._hostArtifactsTab = function(artifacts) {
  if (!artifacts || !artifacts.length) return '<div class="panel-empty"><div class="icon">&#128196;</div>No raw tool output captured</div>';
  var esc = WG.escHtml;
  return '<div class="panel">' +
    artifacts.map(function(a, i) {
      return '<div class="accordion-item" style="border-bottom:1px solid var(--border-color);">' +
        '<div class="accordion-header" onclick="WG._toggleArtifact(this,\'' + a.id + '\')" style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;cursor:pointer;transition:background var(--transition-fast);">' +
          '<div style="display:flex;align-items:center;gap:10px;">' +
            '<span class="tag" style="font-size:0.7rem;">' + esc(a.tool) + '</span>' +
            '<span class="mono" style="font-size:0.8rem;color:var(--text-primary);">' + esc(a.name) + '</span>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:12px;">' +
            '<span style="font-size:0.7rem;color:var(--text-dim);">' + esc(a.content_type) + '</span>' +
            '<span style="font-size:0.7rem;color:var(--text-dim);">' + WG.fmtBytes(a.size) + '</span>' +
            '<svg class="artifact-chevron" viewBox="0 0 24 24" style="width:14px;height:14px;opacity:0.4;transition:transform 0.2s;"><path d="M9 18l6-6-6-6"/></svg>' +
          '</div>' +
        '</div>' +
        '<div class="artifact-content" style="display:none;"><div class="code-block" style="margin:0;border-radius:0;max-height:500px;overflow:auto;font-size:0.75rem;"><span style="color:var(--text-dim);">Loading...</span></div></div>' +
      '</div>';
    }).join('') +
    '</div>';
};

WG._toggleArtifact = function(el, artifactId) {
  var body = el.nextElementSibling;
  var chevron = el.querySelector('.artifact-chevron');
  if (!body) return;
  if (body.style.display === 'none') {
    body.style.display = 'block';
    if (chevron) chevron.style.transform = 'rotate(90deg)';
    var codeBlock = body.querySelector('.code-block');
    if (codeBlock && codeBlock.textContent.indexOf('Loading...') !== -1) {
      WG.api('/artifacts/' + artifactId + '/').then(function(data) {
        if (data && codeBlock) codeBlock.textContent = data.content || '(empty)';
      });
    }
  } else {
    body.style.display = 'none';
    if (chevron) chevron.style.transform = '';
  }
};

WG._bindScreenshotClicks = function(screenshots) {
  document.querySelectorAll('.screenshot-card[data-ss-idx]').forEach(function(card) {
    card.onclick = function() { WGLightbox.open(screenshots, parseInt(card.dataset.ssIdx)); };
  });
};

WG.switchHostTab = function(tab, hostId) {
  document.querySelectorAll('#hostTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('hostTabContent');
  var host = WG._cache['host_' + hostId];
  if (tab === 'ports') el.innerHTML = WG._hostPortsTab(host ? host.ports || [] : []);
  else if (tab === 'findings') el.innerHTML = WG._scanFindingsTab((WG._cache['host_findings_' + hostId] || []).filter(function(f) { return f.host === hostId || f.host_ip === (host && host.ip); }));
  else if (tab === 'tech') el.innerHTML = WG._hostTechTab(host ? host.technologies || [] : []);
  else if (tab === 'screenshots' && host) {
    el.innerHTML = WG._hostScreenshotsTab(host.screenshots);
    WG._bindScreenshotClicks(host.screenshots);
  }
  else if (tab === 'artifacts') {
    var arts = WG._cache['host_artifacts_' + hostId] || [];
    el.innerHTML = WG._hostArtifactsTab(arts);
  }
};
