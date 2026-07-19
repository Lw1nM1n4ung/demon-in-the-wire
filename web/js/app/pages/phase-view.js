/* Wire_Ghost — Phase View page (shared by portscan, webdetect, webcrawl, enumeration).
 *
 * Each phase gets a dedicated route (/phase/<phase>) that renders hosts currently
 * in that pipeline phase across all active and completed scans. Uses the same
 * async-load-then-rerender pattern as live-discovery.js.
 *
 * All user-supplied data is escaped via WG.escHtml() before interpolation — same
 * trust model as every other page module in this SPA. */

/* ── Phase description helpers ── */
WG._PHASE_DESCRIPTIONS = {
  'portscan': 'Open ports and services discovered during port scanning.',
  'webdetect': 'Web servers identified via HTTP/HTTPS detection.',
  'webcrawl': 'Web endpoints crawled and screenshots captured.',
  'enumeration': 'Service enumeration results — SMB, LDAP, SNMP, and more.'
};

/* ── Main renderer ── */
WG.renderPhaseView = function(phase) {
  var esc = WG.escHtml;
  var scans = WG.getCached('scans', '/scans/') || [];

  var title = WG.PHASE_LABELS[phase] || phase;
  var desc = WG._PHASE_DESCRIPTIONS[phase] || '';

  var html = '<div class="page-header"><h1>' + esc(title) + '</h1>';
  html += '<p>' + esc(desc) + '</p></div>';

  /* Find scans that have reached this phase. */
  var relevantScans = scans.filter(function(s) {
    return s.status === 'running' || s.status === 'completed';
  });

  if (!relevantScans.length) {
    html += '<div class="empty-state"><div class="icon">&#8987;</div>';
    html += '<h3>No scans available</h3>';
    html += '<p>Launch a scan to see hosts in this phase.</p>';
    html += '<button class="btn btn-primary" onclick="WG.openModal(\'scanModal\')" style="margin-top:16px;">';
    html += '<span>&#9654;</span> New Scan</button></div>';
    return html;
  }

  /* Kick off async fetches for scans that don't have cached host data. */
  relevantScans.forEach(function(scan) {
    var cacheKey = 'phase_hosts_' + scan.id;
    if (!WG._cache[cacheKey]) {
      WG.api('/scans/' + scan.id + '/hosts/').then(function(data) {
        if (Array.isArray(data)) {
          WG._cache[cacheKey] = data;
          WG._cacheTime[cacheKey] = Date.now();
          var main = document.getElementById('mainContent');
          if (main && WG._isPhasePage(phase) && !document.querySelector('.modal-overlay.active')) {
            main.innerHTML = WG.renderPhaseView(phase);
          }
        }
      });
    }
  });

  /* Collect all hosts in this phase across all scans. */
  var allHosts = [];
  var anyLoading = false;

  relevantScans.forEach(function(scan) {
    var cacheKey = 'phase_hosts_' + scan.id;
    var hosts = WG._cache[cacheKey];

    if (!hosts) {
      anyLoading = true;
      return;
    }

    var phaseHosts = hosts.filter(function(h) {
      return h.current_phase === phase;
    });

    phaseHosts.forEach(function(h) {
      h._scanName = scan.name;
      h._scanId = scan.id;
    });

    allHosts = allHosts.concat(phaseHosts);
  });

  /* Stats row */
  var activeCount = relevantScans.filter(function(s) { return s.status === 'running'; }).length;
  html += '<div class="stat-row" style="display:flex;gap:16px;margin-bottom:24px;">';
  html += '<div class="stat-card" style="flex:1;background:var(--bg-secondary);padding:12px;border-radius:8px;text-align:center;">';
  html += '<div style="font-size:1.5rem;font-weight:700;color:var(--accent);">' + allHosts.length + '</div>';
  html += '<div style="font-size:0.8rem;color:var(--text-secondary);">Hosts in Phase</div></div>';
  html += '<div class="stat-card" style="flex:1;background:var(--bg-secondary);padding:12px;border-radius:8px;text-align:center;">';
  html += '<div style="font-size:1.5rem;font-weight:700;">' + activeCount + '</div>';
  html += '<div style="font-size:0.8rem;color:var(--text-secondary);">Active Scans</div></div>';
  html += '<div class="stat-card" style="flex:1;background:var(--bg-secondary);padding:12px;border-radius:8px;text-align:center;">';
  html += '<div style="font-size:1.5rem;font-weight:700;text-transform:capitalize;">' + esc(title) + '</div>';
  html += '<div style="font-size:0.8rem;color:var(--text-secondary);">Current Phase</div></div>';
  html += '</div>';

  /* Loading state */
  if (anyLoading) {
    html += '<div style="text-align:center;padding:24px;"><div class="spinner"></div>';
    html += '<p style="margin-top:8px;color:var(--text-secondary);">Loading host data...</p></div>';
  }

  /* Host table */
  if (allHosts.length > 0) {
    html += WG._renderPhaseTable(phase, allHosts, esc);
  } else if (!anyLoading) {
    html += '<div class="empty-state" style="padding:16px;">';
    html += '<p style="color:var(--text-secondary);">No hosts are currently in the ' + esc(title.toLowerCase()) + ' phase.</p></div>';
  }

  return html;
};

/* ── Phase-specific table dispatcher ── */
WG._renderPhaseTable = function(phase, hosts, esc) {
  switch (phase) {
    case 'portscan':     return WG._renderPortScanTable(hosts, esc);
    case 'webdetect':    return WG._renderWebDetectTable(hosts, esc);
    case 'webcrawl':     return WG._renderWebCrawlTable(hosts, esc);
    case 'enumeration':  return WG._renderEnumerationTable(hosts, esc);
    default:             return WG._renderGenericHostTable(hosts, esc);
  }
};

/* ── Port Scan table ── */
WG._renderPortScanTable = function(hosts, esc) {
  var html = '<div style="overflow-x:auto;"><table class="table">';
  html += '<thead><tr><th>IP Address</th><th>Hostname</th><th>Open Ports</th><th>OS</th><th>Scan</th></tr></thead><tbody>';

  hosts.forEach(function(h) {
    html += '<tr onclick="WG.navigate(\'host\',{id:\'' + esc(h.id) + '\'})" style="cursor:pointer;">';
    html += '<td><code style="font-size:0.9rem;">' + esc(h.ip) + '</code></td>';
    html += '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td><span class="badge badge-info">' + (h.ports_count || 0) + '</span></td>';
    html += '<td>' + (h.os ? '<span class="tag">' + esc(h.os) + '</span>' : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td><span style="font-size:0.8rem;color:var(--text-secondary);">' + esc(h._scanName) + '</span></td>';
    html += '</tr>';
  });

  html += '</tbody></table></div>';

  var totalPorts = hosts.reduce(function(sum, h) { return sum + (h.ports_count || 0); }, 0);
  html += '<div style="margin-top:12px;padding:12px;background:var(--bg-secondary);border-radius:8px;">';
  html += '<span style="font-size:0.8rem;color:var(--text-secondary);">';
  html += hosts.length + ' hosts &middot; ' + totalPorts + ' open ports';
  html += '</span></div>';

  return html;
};

/* ── Web Detect table ── */
WG._renderWebDetectTable = function(hosts, esc) {
  var html = '<div style="overflow-x:auto;"><table class="table">';
  html += '<thead><tr><th>IP Address</th><th>Hostname</th><th>Ports</th><th>Screenshot</th><th>Scan</th></tr></thead><tbody>';

  hosts.forEach(function(h) {
    html += '<tr onclick="WG.navigate(\'host\',{id:\'' + esc(h.id) + '\'})" style="cursor:pointer;">';
    html += '<td><code style="font-size:0.9rem;">' + esc(h.ip) + '</code></td>';
    html += '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td><span class="badge badge-info">' + (h.ports_count || 0) + '</span></td>';
    if (h.thumbnail_url) {
      html += '<td><img class="screenshot-thumb" src="' + esc(h.thumbnail_url) + '" loading="lazy" alt="screenshot" style="width:80px;height:45px;"></td>';
    } else {
      html += '<td><span style="color:var(--text-muted);">—</span></td>';
    }
    html += '<td><span style="font-size:0.8rem;color:var(--text-secondary);">' + esc(h._scanName) + '</span></td>';
    html += '</tr>';
  });

  html += '</tbody></table></div>';

  var withShots = hosts.filter(function(h) { return h.thumbnail_url; }).length;
  html += '<div style="margin-top:12px;padding:12px;background:var(--bg-secondary);border-radius:8px;">';
  html += '<span style="font-size:0.8rem;color:var(--text-secondary);">';
  html += hosts.length + ' hosts &middot; ' + withShots + ' with screenshots';
  html += '</span></div>';

  return html;
};

/* ── Web Crawl table ── */
WG._renderWebCrawlTable = function(hosts, esc) {
  var html = '<div style="overflow-x:auto;"><table class="table">';
  html += '<thead><tr><th>IP Address</th><th>Hostname</th><th>Screenshots</th><th>Ports</th><th>Findings</th><th>Scan</th></tr></thead><tbody>';

  hosts.forEach(function(h) {
    html += '<tr onclick="WG.navigate(\'host\',{id:\'' + esc(h.id) + '\'})" style="cursor:pointer;">';
    html += '<td><code style="font-size:0.9rem;">' + esc(h.ip) + '</code></td>';
    html += '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    if (h.thumbnail_url) {
      var sc = (h.screenshot_count || 1);
      html += '<td><img class="screenshot-thumb" src="' + esc(h.thumbnail_url) + '" loading="lazy" alt="screenshot" style="width:80px;height:45px;">';
      if (sc > 1) html += ' <span class="screenshot-more">+' + (sc - 1) + '</span>';
      html += '</td>';
    } else {
      html += '<td><span style="color:var(--text-muted);">—</span></td>';
    }
    html += '<td><span class="badge badge-info">' + (h.ports_count || 0) + '</span></td>';
    html += '<td><span class="badge" style="background:var(--critical-dim);color:var(--critical);">' + (h.findings_count || 0) + '</span></td>';
    html += '<td><span style="font-size:0.8rem;color:var(--text-secondary);">' + esc(h._scanName) + '</span></td>';
    html += '</tr>';
  });

  html += '</tbody></table></div>';

  var withShots = hosts.filter(function(h) { return h.thumbnail_url; }).length;
  var totalFindings = hosts.reduce(function(s, h) { return s + (h.findings_count || 0); }, 0);
  html += '<div style="margin-top:12px;padding:12px;background:var(--bg-secondary);border-radius:8px;">';
  html += '<span style="font-size:0.8rem;color:var(--text-secondary);">';
  html += hosts.length + ' hosts &middot; ' + withShots + ' with screenshots &middot; ' + totalFindings + ' findings';
  html += '</span></div>';

  return html;
};

/* ── Enumeration table ── */
WG._renderEnumerationTable = function(hosts, esc) {
  var html = '<div style="overflow-x:auto;"><table class="table">';
  html += '<thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Findings</th><th>Scan</th></tr></thead><tbody>';

  hosts.forEach(function(h) {
    html += '<tr onclick="WG.navigate(\'host\',{id:\'' + esc(h.id) + '\'})" style="cursor:pointer;">';
    html += '<td><code style="font-size:0.9rem;">' + esc(h.ip) + '</code></td>';
    html += '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td>' + (h.os ? '<span class="tag">' + esc(h.os) + '</span>' : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td><span class="badge badge-info">' + (h.ports_count || 0) + '</span></td>';
    html += '<td><span class="badge" style="background:var(--critical-dim);color:var(--critical);">' + (h.findings_count || 0) + '</span></td>';
    html += '<td><span style="font-size:0.8rem;color:var(--text-secondary);">' + esc(h._scanName) + '</span></td>';
    html += '</tr>';
  });

  html += '</tbody></table></div>';

  var tp = hosts.reduce(function(s, h) { return s + (h.ports_count || 0); }, 0);
  var tf = hosts.reduce(function(s, h) { return s + (h.findings_count || 0); }, 0);
  html += '<div style="margin-top:12px;padding:12px;background:var(--bg-secondary);border-radius:8px;">';
  html += '<span style="font-size:0.8rem;color:var(--text-secondary);">';
  html += hosts.length + ' hosts &middot; ' + tp + ' ports &middot; ' + tf + ' findings';
  html += '</span></div>';

  return html;
};

/* ── Generic fallback table ── */
WG._renderGenericHostTable = function(hosts, esc) {
  var html = '<div style="overflow-x:auto;"><table class="table">';
  html += '<thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Findings</th><th>Phase</th><th>Scan</th></tr></thead><tbody>';

  hosts.forEach(function(h) {
    html += '<tr onclick="WG.navigate(\'host\',{id:\'' + esc(h.id) + '\'})" style="cursor:pointer;">';
    html += '<td><code style="font-size:0.9rem;">' + esc(h.ip) + '</code></td>';
    html += '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td>' + (h.os ? '<span class="tag">' + esc(h.os) + '</span>' : '<span style="color:var(--text-muted);">—</span>') + '</td>';
    html += '<td>' + (h.ports_count || 0) + '</td>';
    html += '<td>' + (h.findings_count || 0) + '</td>';
    html += '<td><span class="badge badge-info" style="text-transform:capitalize;">' + esc(h.current_phase || '—') + '</span></td>';
    html += '<td><span style="font-size:0.8rem;color:var(--text-secondary);">' + esc(h._scanName) + '</span></td>';
    html += '</tr>';
  });

  html += '</tbody></table></div>';
  return html;
};

/* ── Helper: guard re-renders to the current phase page ── */
WG._isPhasePage = function(phase) {
  return WG.state.currentPage === 'phase-' + phase;
};
