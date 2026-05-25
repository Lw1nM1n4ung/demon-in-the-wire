/* Wire_Ghost — Live Host Discovery page.
 *
 * Polls running scans for real-time discovery status. Shows live host table,
 * subnet progress, and overall scan progress. Designed for 2-second polling
 * during active discovery phases. */

WG._discoveryPollTimer = null;

WG._stopDiscoveryPolling = function() {
  if (WG._discoveryPollTimer) {
    clearInterval(WG._discoveryPollTimer);
    WG._discoveryPollTimer = null;
  }
};

WG.renderLiveDiscovery = function() {
  var esc = WG.escHtml;
  var scans = WG.getCached('scans', '/scans/') || [];

  var discoveryScans = scans.filter(function(s) {
    return s.status === 'running' && (!s.current_phase || s.current_phase === 'discovery' || s.current_phase === 'pending');
  });

  var html = '<div class="page-header"><h1>Live Discovery</h1>';
  html += '<p>Real-time host discovery — hosts appear as they are found during active scans.</p></div>';

  if (!discoveryScans.length) {
    html += '<div class="empty-state"><div class="icon">&#8987;</div>';
    html += '<h3>No active discovery scans</h3>';
    html += '<p>Launch a scan to see hosts appear here in real time.</p>';
    html += '<button class="btn btn-primary" onclick="WG.navigate(\'new-scan\')" style="margin-top:16px;">';
    html += '<span>&#9654;</span> New Scan</button></div>';
    WG._stopDiscoveryPolling();
    return html;
  }

  WG._startDiscoveryPolling();

  discoveryScans.forEach(function(scan) {
    var cacheKey = 'discovery_' + scan.id;
    if (!WG._cache[cacheKey]) {
      WG.api('/scans/' + scan.id + '/discovery/').then(function(data) {
        if (data) {
          WG._cache[cacheKey] = data;
          WG._cacheTime[cacheKey] = Date.now();
          var main = document.getElementById('mainContent');
          if (main && WG.state.currentPage === 'live-discovery' && !document.querySelector('.modal-overlay.active')) {
            main.innerHTML = WG.renderLiveDiscovery();
          }
        }
      });
    }
  });

  discoveryScans.forEach(function(scan) {
    var cacheKey = 'discovery_' + scan.id;
    var data = WG._cache[cacheKey];

    html += '<div class="card" style="margin-bottom:24px;">';
    html += '<div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">';
    html += '<div><h3 style="margin:0;">' + esc(scan.name) + '</h3>';
    html += '<span style="color:var(--text-secondary);font-size:0.85rem;">' + esc(scan.target) + '</span></div>';
    html += '<div style="display:flex;align-items:center;gap:12px;">';
    html += '<span class="badge badge-running" style="display:flex;align-items:center;gap:4px;">';
    html += '<span class="pulse-dot"></span> Live</span>';
    html += '<button class="btn btn-sm btn-secondary" onclick="WG.navigate(\'scan\',{id:\'' + esc(scan.id) + '\'})">View Scan</button>';
    html += '</div></div>';

    html += '<div class="card-body">';

    if (!data) {
      html += '<div style="text-align:center;padding:24px;"><div class="spinner"></div><p style="margin-top:8px;">Loading discovery data...</p></div>';
    } else {
      var pct = data.hosts_total > 0 ? Math.round((data.hosts_scanned / data.hosts_total) * 100) : 0;
      html += '<div style="margin-bottom:16px;">';
      html += '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">';
      html += '<span style="font-size:0.85rem;color:var(--text-secondary);">Discovery Progress</span>';
      html += '<span style="font-size:0.85rem;font-weight:600;">' + data.hosts_scanned + ' / ' + (data.hosts_total || '?') + ' subnets scanned</span>';
      html += '</div>';
      html += '<div class="progress-bar" style="height:6px;background:var(--border);border-radius:3px;overflow:hidden;">';
      html += '<div class="progress-fill" style="height:100%;width:' + pct + '%;background:var(--accent);border-radius:3px;transition:width 0.5s;"></div>';
      html += '</div></div>';

      html += '<div class="stat-row" style="display:flex;gap:16px;margin-bottom:16px;">';
      html += '<div class="stat-card" style="flex:1;background:var(--bg-secondary);padding:12px;border-radius:8px;text-align:center;">';
      html += '<div style="font-size:1.5rem;font-weight:700;color:var(--accent);">' + data.live_hosts + '</div>';
      html += '<div style="font-size:0.8rem;color:var(--text-secondary);">Live Hosts</div></div>';
      html += '<div class="stat-card" style="flex:1;background:var(--bg-secondary);padding:12px;border-radius:8px;text-align:center;">';
      html += '<div style="font-size:1.5rem;font-weight:700;">' + (data.hosts_total || '?') + '</div>';
      html += '<div style="font-size:0.8rem;color:var(--text-secondary);">Target Subnets</div></div>';
      html += '<div class="stat-card" style="flex:1;background:var(--bg-secondary);padding:12px;border-radius:8px;text-align:center;">';
      html += '<div style="font-size:1.5rem;font-weight:700;text-transform:capitalize;">' + esc(data.current_phase || 'discovery') + '</div>';
      html += '<div style="font-size:0.8rem;color:var(--text-secondary);">Phase</div></div>';
      html += '</div>';

      var hosts = data.hosts || [];
      if (!hosts.length) {
        html += '<div class="empty-state" style="padding:16px;"><p style="color:var(--text-secondary);">Waiting for hosts to be discovered...</p></div>';
      } else {
        html += '<div style="overflow-x:auto;"><table class="table">';
        html += '<thead><tr>';
        html += '<th>IP Address</th><th>Hostname</th><th>MAC Address</th><th>Vendor</th><th>Phase</th>';
        html += '</tr></thead><tbody>';

        hosts.forEach(function(h) {
          html += '<tr>';
          html += '<td><code style="font-size:0.9rem;">' + esc(h.ip) + '</code></td>';
          html += '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
          html += '<td><code style="font-size:0.8rem;">' + (h.mac_address ? esc(h.mac_address) : '<span style="color:var(--text-muted);">—</span>') + '</code></td>';
          html += '<td>' + (h.vendor ? esc(h.vendor) : '<span style="color:var(--text-muted);">—</span>') + '</td>';
          html += '<td><span class="badge badge-info" style="text-transform:capitalize;">' + esc(h.current_phase || 'discovery') + '</span></td>';
          html += '</tr>';
        });

        html += '</tbody></table></div>';
      }
    }

    html += '</div></div>';
  });

  var recentScans = scans.filter(function(s) {
    return s.status === 'completed' && s.hosts_count > 0;
  }).slice(0, 3);

  if (recentScans.length > 0) {
    html += '<div style="margin-top:32px;">';
    html += '<h3 style="margin-bottom:12px;">Recently Completed</h3>';

    recentScans.forEach(function(scan) {
      html += '<div class="card" style="margin-bottom:12px;opacity:0.75;">';
      html += '<div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">';
      html += '<div><h4 style="margin:0;">' + esc(scan.name) + '</h4>';
      html += '<span style="color:var(--text-secondary);font-size:0.8rem;">' + esc(scan.target) + '</span></div>';
      html += '<div style="display:flex;align-items:center;gap:12px;">';
      html += '<span class="badge badge-success">Completed</span>';
      html += '<span style="font-size:0.9rem;color:var(--text-secondary);">' + scan.hosts_count + ' hosts</span>';
      html += '<button class="btn btn-sm btn-secondary" onclick="WG.navigate(\'scan\',{id:\'' + esc(scan.id) + '\'})">View</button>';
      html += '</div></div></div>';
    });

    html += '</div>';
  }

  return html;
};

WG._startDiscoveryPolling = function() {
  if (WG._discoveryPollTimer) return;

  WG._discoveryPollTimer = setInterval(function() {
    if (WG.state.currentPage !== 'live-discovery') {
      WG._stopDiscoveryPolling();
      return;
    }

    var scans = WG._cache['scans'];
    if (!scans) {
      WG.api('/scans/').then(function(data) {
        if (data && data.results) {
          WG._cache['scans'] = data.results;
          WG._cacheTime['scans'] = Date.now();
        }
      });
    }

    (scans || []).forEach(function(s) {
      if (s.status === 'running') {
        var key = 'discovery_' + s.id;
        delete WG._cache[key];
        delete WG._cacheTime[key];
      }
    });

    delete WG._cache['scans'];
    delete WG._cacheTime['scans'];

    var main = document.getElementById('mainContent');
    if (main && WG.state.currentPage === 'live-discovery' && !document.querySelector('.modal-overlay.active')) {
      main.innerHTML = WG.renderLiveDiscovery();
    }
  }, 2000);
};
