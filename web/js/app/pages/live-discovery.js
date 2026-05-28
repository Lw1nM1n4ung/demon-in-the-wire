/* Wire_Ghost — Live Discovery page (v2)
 *
 * Targeted DOM updates instead of full innerHTML replacement.
 * Single 2s poll loop, diff-based table updates, tool provenance tabs.
 */
(function() {
  'use strict';

  WG._discoveryPollTimer = null;
  WG._discoveryActiveTool = {};

  WG._stopDiscoveryPolling = function() {
    if (WG._discoveryPollTimer) {
      clearInterval(WG._discoveryPollTimer);
      WG._discoveryPollTimer = null;
    }
  };

  WG._discoveryExport = function(scanId, format) {
    WG.api('/scans/' + scanId + '/discovery_export/?format=' + format).then(function(data) {
      if (!data) { WG.toast('Export failed', 'error'); return; }
      var blob, ext;
      if (format === 'csv') {
        blob = new Blob([data.csv || ''], { type: 'text/csv' });
        ext = 'csv';
      } else {
        blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        ext = 'json';
      }
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = 'discovery-' + scanId + '.' + ext;
      a.click(); URL.revokeObjectURL(url);
    });
  };

  WG._discoveryRetry = function(scanId) {
    WG.api('/scans/' + scanId + '/retry/', { method: 'POST' }).then(function(res) {
      if (!res) { WG.toast('Retry failed', 'error'); return; }
      WG.toast('Scan restarted', 'success');
      WG.invalidateCache('scans');
      WG._startDiscoveryPolling();
    });
  };

  function _toolBadges(tools) {
    if (!tools || !tools.length) return '<span class="tool-badge nmap">NMAP</span>';
    return tools.map(function(t) {
      var cls = t.toLowerCase().replace(/[^a-z0-9-]/g, '');
      return '<span class="tool-badge ' + cls + '">' + WG.escHtml(t.toUpperCase()) + '</span>';
    }).join('');
  }

  function _toolList(h) {
    var tools = h.discovered_by || [];
    return tools.length ? tools : ['nmap'];
  }

  function _buildToolTabs(scanId, hosts, activeTool) {
    var tools = {};
    hosts.forEach(function(h) {
      _toolList(h).forEach(function(t) {
        var key = t.toLowerCase().replace(/[^a-z0-9-]/g, '');
        tools[key] = (tools[key] || 0) + 1;
      });
    });
    var cur = activeTool || 'all';
    var h = '<div class="tool-tabs" id="discovery-tabs-' + scanId + '">';
    h += '<button class="tool-tab' + (cur === 'all' ? ' active' : '') +
         '" data-tool="all" onclick="WG._filterDiscoveryHosts(\'' + scanId + '\',\'all\',this)">All (' + hosts.length + ')</button>';
    ['nmap','fping','arp-scan','netdiscover','passive-dns'].forEach(function(t) {
      if (tools[t]) {
        h += '<button class="tool-tab' + (cur === t ? ' active' : '') +
             '" data-tool="' + t + '" onclick="WG._filterDiscoveryHosts(\'' + scanId + '\',\'' + t + '\',this)">' +
             t.toUpperCase() + ' (' + tools[t] + ')</button>';
      }
    });
    h += '</div>';
    return h;
  }

  function _buildHostRow(h) {
    var tools = _toolList(h);
    var esc = WG.escHtml;
    return '<td><code>' + esc(h.ip) + '</code></td>' +
           '<td>' + (h.hostname ? esc(h.hostname) : '<span style="color:var(--text-dim)">&mdash;</span>') + '</td>' +
           '<td class="mono" style="font-size:0.72rem">' + (h.mac_address ? esc(h.mac_address) : '<span style="color:var(--text-dim)">&mdash;</span>') + '</td>' +
           '<td style="font-size:0.75rem">' + (h.vendor ? esc(h.vendor) : '<span style="color:var(--text-dim)">&mdash;</span>') + '</td>' +
           '<td style="white-space:nowrap">' + _toolBadges(tools) + '</td>' +
           '<td><span class="status-badge" style="font-size:0.65rem;text-transform:capitalize">' + esc(h.current_phase || 'discovery') + '</span></td>';
  }

  WG._filterDiscoveryHosts = function(scanId, tool, btn) {
    WG._discoveryActiveTool[scanId] = tool;
    var tabBar = document.getElementById('discovery-tabs-' + scanId);
    if (tabBar) {
      tabBar.querySelectorAll('.tool-tab').forEach(function(t) { t.classList.remove('active'); });
      if (btn) btn.classList.add('active');
    }
    var tbody = document.getElementById('discovery-hosts-' + scanId);
    if (!tbody) return;
    tbody.querySelectorAll('tr[data-ip]').forEach(function(tr) {
      if (tool === 'all') { tr.style.display = ''; return; }
      var attr = (tr.getAttribute('data-tools') || '').toLowerCase();
      tr.style.display = attr.indexOf(tool) !== -1 ? '' : 'none';
    });
  };

  /* MAIN RENDER */
  WG.renderLiveDiscovery = function() {
    var html = '<div class="page-header">' +
      '<h1 class="page-title">Live Host Discovery</h1>' +
      '<p class="page-subtitle">Real-time visibility into which tools found each live host across your target scope.</p>' +
      '</div><div id="discoveryContainer">' +
      '<div class="empty-state"><div class="spinner"></div><p>Loading scans…</p></div></div>';

    var scansPromise = WG.getCached ? WG.getCached('scans', '/scans/') : WG.api('/scans/');
    Promise.resolve(scansPromise).then(function(data) {
      if (!data) return;
      var scans = data.results || data;
      if (!Array.isArray(scans)) return;

      var activeDiscovery = scans.filter(function(s) {
        return s.status === 'running' && s.scan_type === 'discovery';
      });
      var allDiscovery = scans.filter(function(s) { return s.scan_type === 'discovery'; });

      if (!allDiscovery.length) {
        document.getElementById('discoveryContainer').innerHTML =
          '<div class="empty-state"><div style="font-size:2rem;margin-bottom:8px;opacity:0.3">&#8998;</div>' +
          '<p>No discovery scans yet</p>' +
          '<p style="font-size:0.78rem;color:var(--text-dim)">Launch a new scan from the Scan Queue.</p></div>';
        WG._stopDiscoveryPolling();
        return;
      }

      var cardsHtml = '';
      allDiscovery.forEach(function(scan) {
        var isRunning = scan.status === 'running';
        var dd = WG._discoveryData ? WG._discoveryData[scan.id] : null;
        var hosts = dd ? dd.hosts || [] : [];
        var activeTool = (WG._discoveryActiveTool && WG._discoveryActiveTool[scan.id]) || 'all';
        var pct = (dd && dd.hosts_total > 0) ? Math.round(dd.hosts_scanned / dd.hosts_total * 100) : 0;

        cardsHtml += '<div class="card" style="margin-bottom:20px" id="discovery-card-' + scan.id + '">';
        cardsHtml += '<div class="card-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">';
        cardsHtml += '<div><strong>' + WG.escHtml(scan.name) + '</strong> ' +
          '<span style="font-size:0.72rem;color:var(--text-dim);margin-left:8px">' + WG.escHtml(scan.target) + '</span></div>';
        cardsHtml += '<div style="display:flex;align-items:center;gap:10px">';

        if (isRunning) {
          cardsHtml += '<span class="status-badge running"><span class="dot"></span> Live</span>';
          cardsHtml += '<span class="elapsed-live mono" style="font-size:0.7rem;color:var(--text-dim)" data-started-at="' + (scan.started_at || '') + '">' + WG.fmtDuration(scan.elapsed_seconds || 0) + '</span>';
        } else if (scan.status === 'completed') {
          cardsHtml += '<span class="status-badge completed">Complete</span>';
        } else if (scan.status === 'failed') {
          cardsHtml += '<span class="status-badge failed">Failed</span>';
          if (scan.error_message) cardsHtml += '<span style="font-size:0.72rem;color:var(--critical);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + WG.escHtml(scan.error_message.substring(0, 120)) + '</span>';
        } else if (scan.status === 'cancelled') {
          cardsHtml += '<span class="status-badge cancelled">Cancelled</span>';
        }

        if (scan.status === 'completed') {
          cardsHtml += '<button class="btn btn-ghost" style="font-size:0.68rem;padding:2px 8px" onclick="WG._discoveryExport(\'' + scan.id + '\',\'csv\')">CSV</button>';
          cardsHtml += '<button class="btn btn-ghost" style="font-size:0.68rem;padding:2px 8px" onclick="WG._discoveryExport(\'' + scan.id + '\',\'json\')">JSON</button>';
        }
        if (scan.status === 'failed' || scan.status === 'cancelled') {
          cardsHtml += '<button class="btn btn-ghost" style="font-size:0.68rem;padding:2px 8px" onclick="WG._discoveryRetry(\'' + scan.id + '\')">Retry</button>';
        }
        cardsHtml += '</div></div>';

        cardsHtml += '<div style="display:flex;gap:16px;padding:12px 0;flex-wrap:wrap">';
        cardsHtml += '<div class="stat-card"><div class="stat-label">Live Hosts</div><div class="stat-value mono" id="dlh-' + scan.id + '">' + (dd ? dd.live_hosts || 0 : '…') + '</div></div>';
        cardsHtml += '<div class="stat-card"><div class="stat-label">Subnets Scanned</div><div class="stat-value mono" id="dsc-' + scan.id + '">' + (dd ? (dd.hosts_scanned || 0) + ' / ' + (dd.hosts_total || '?') : '…') + '</div></div>';
        cardsHtml += '<div class="stat-card"><div class="stat-label">Phase</div><div class="stat-value mono" id="dph-' + scan.id + '" style="text-transform:capitalize">' + (dd ? dd.current_phase || 'discovery' : 'discovery') + '</div></div>';
        cardsHtml += '</div>';
        cardsHtml += '<div class="progress-bar" style="margin-bottom:12px"><div class="progress-fill" id="dpf-' + scan.id + '" style="width:' + pct + '%"></div></div>';

        cardsHtml += _buildToolTabs(scan.id, hosts, activeTool);

        cardsHtml += '<div style="overflow-x:auto"><table style="width:100%;font-size:0.78rem">';
        cardsHtml += '<thead><tr><th>IP Address</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Discovered By</th><th>Phase</th></tr></thead>';
        cardsHtml += '<tbody id="discovery-hosts-' + scan.id + '">';

        if (isRunning && !hosts.length) {
          cardsHtml += '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:20px"><div class="spinner" style="margin:0 auto 8px"></div>Waiting for hosts to be discovered…</td></tr>';
        } else if (!hosts.length) {
          cardsHtml += '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:20px">No hosts found</td></tr>';
        } else {
          hosts.forEach(function(h) {
            var tools = _toolList(h);
            cardsHtml += '<tr data-ip="' + WG.escHtml(h.ip) + '" data-tools="' + tools.join(',').toLowerCase() + '">' + _buildHostRow(h) + '</tr>';
          });
        }
        cardsHtml += '</tbody></table></div>';
        cardsHtml += '<div style="font-size:0.68rem;color:var(--text-dim);margin-top:6px"><span id="dhc-' + scan.id + '">' + hosts.length + '</span> host(s) shown</div>';
        cardsHtml += '</div>';
      });

      document.getElementById('discoveryContainer').innerHTML = cardsHtml;
      if (activeDiscovery.length > 0) { WG._startDiscoveryPolling(); }
      else { WG._stopDiscoveryPolling(); }
    });

    if (WG._startElapsedTicker) WG._startElapsedTicker();
    return html;
  };

  /* POLLING — targeted DOM updates only */
  WG._startDiscoveryPolling = function() {
    if (WG._discoveryPollTimer) return;
    WG._discoveryPollTimer = setInterval(function() {
      if (WG.state.currentPage !== 'live-discovery') { WG._stopDiscoveryPolling(); return; }
      if (document.querySelector('.modal-overlay.active')) return;

      WG.api('/scans/').then(function(data) {
        if (!data || !data.results) return;
        WG._cache['scans'] = data.results;

        var activeDiscovery = data.results.filter(function(s) {
          return s.status === 'running' && s.scan_type === 'discovery';
        });

        if (!activeDiscovery.length) { WG._stopDiscoveryPolling(); return; }

        activeDiscovery.forEach(function(scan) {
          WG.api('/scans/' + scan.id + '/discovery/').then(function(dd) {
            if (!dd) return;
            if (!WG._discoveryData) WG._discoveryData = {};
            WG._discoveryData[scan.id] = dd;
            _updateScanCard(scan.id, dd);
            _updateHostTable(scan.id, dd.hosts || []);
            _updateToolTabs(scan.id, dd.hosts || []);
          });
        });
      });
    }, 2000);
  };

  function _updateScanCard(scanId, data) {
    var el;
    el = document.getElementById('dlh-' + scanId);
    if (el && data.live_hosts !== undefined) el.textContent = data.live_hosts;
    el = document.getElementById('dsc-' + scanId);
    if (el) el.textContent = (data.hosts_scanned || 0) + ' / ' + (data.hosts_total || '?');
    el = document.getElementById('dph-' + scanId);
    if (el && data.current_phase) el.textContent = data.current_phase;
    el = document.getElementById('dpf-' + scanId);
    if (el && data.hosts_total > 0) el.style.width = Math.round(data.hosts_scanned / data.hosts_total * 100) + '%';
    el = document.getElementById('dhc-' + scanId);
    if (el && data.hosts) el.textContent = data.hosts.length;
  }

  function _updateHostTable(scanId, hosts) {
    var tbody = document.getElementById('discovery-hosts-' + scanId);
    if (!tbody) return;
    var placeholder = tbody.querySelector('tr:not([data-ip])');
    if (placeholder && hosts.length) placeholder.remove();

    var newIps = {};
    hosts.forEach(function(h) { newIps[h.ip] = h; });
    var newIpSet = new Set(Object.keys(newIps));

    tbody.querySelectorAll('tr[data-ip]').forEach(function(tr) {
      if (!newIpSet.has(tr.getAttribute('data-ip'))) tr.remove();
    });

    hosts.forEach(function(h) {
      var existing = tbody.querySelector('tr[data-ip="' + h.ip + '"]');
      var tools = _toolList(h);
      var toolsAttr = tools.join(',').toLowerCase();

      if (!existing) {
        var tr = document.createElement('tr');
        tr.setAttribute('data-ip', h.ip);
        tr.setAttribute('data-tools', toolsAttr);
        tr.setAttribute('data-tools-old', toolsAttr);
        tr.innerHTML = _buildHostRow(h);
        var inserted = false;
        var rows = tbody.querySelectorAll('tr[data-ip]');
        for (var i = 0; i < rows.length; i++) {
          if (rows[i].getAttribute('data-ip') > h.ip) {
            tbody.insertBefore(tr, rows[i]); inserted = true; break;
          }
        }
        if (!inserted) tbody.appendChild(tr);
      } else {
        var oldTools = existing.getAttribute('data-tools-old') || '';
        if (oldTools !== toolsAttr) {
          existing.setAttribute('data-tools', toolsAttr);
          existing.setAttribute('data-tools-old', toolsAttr);
          var cells = existing.querySelectorAll('td');
          if (cells.length >= 5) {
            if (h.hostname) cells[1].textContent = h.hostname;
            if (h.mac_address) cells[2].textContent = h.mac_address;
            if (h.vendor) cells[3].textContent = h.vendor;
            cells[4].innerHTML = _toolBadges(tools);
          }
        }
      }
    });

    var activeTool = WG._discoveryActiveTool[scanId] || 'all';
    if (activeTool !== 'all') {
      tbody.querySelectorAll('tr[data-ip]').forEach(function(tr) {
        var a = (tr.getAttribute('data-tools') || '').toLowerCase();
        tr.style.display = a.indexOf(activeTool) !== -1 ? '' : 'none';
      });
    }
  }

  function _updateToolTabs(scanId, hosts) {
    var container = document.getElementById('discovery-tabs-' + scanId);
    if (!container) return;
    var activeTool = WG._discoveryActiveTool[scanId] || 'all';
    container.innerHTML = _buildToolTabs(scanId, hosts, activeTool);
  }

})();
