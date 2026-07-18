/* Wire_Ghost — Scan detail page */

WG.renderScanDetail = function(id) {
  WG.state.currentScanId = id;
  if (!WG._scanFindingsPage) WG._scanFindingsPage = 1;
  var scan = WG.getCached('scans', '/scans/').find(function(s) { return s.id === id; });

  // Fetch full scan detail + hosts + findings from API (once per cache cycle).
  // Completed scans need hosts/findings fetched explicitly — the live poll
  // only runs for running scans, so without this completed scan tabs show 0.
  if (!WG._cache['scan_' + id]) {
    Promise.all([
      WG.api('/scans/' + id + '/'),
      WG.api('/scans/' + id + '/hosts/'),
      WG.api('/scans/' + id + '/findings/')
    ]).then(function(results) {
      if (!results[0] || WG.state.currentPage !== 'scan') return;
      WG._cache['scan_' + id] = results[0];
      WG._cacheTime['scan_' + id] = Date.now();
      if (Array.isArray(results[1])) {
        WG._cache['scan_hosts_' + id] = results[1];
        WG._cacheTime['scan_hosts_' + id] = Date.now();
      }
      if (Array.isArray(results[2])) {
        WG._cache['scan_findings_' + id] = results[2];
        WG._cacheTime['scan_findings_' + id] = Date.now();
      }
      var main = document.getElementById('mainContent');
      if (main && !document.querySelector(".modal-overlay.active")) main.innerHTML = WG.renderScanDetail(id);
    });
  }

  // Use cached full detail if available
  if (WG._cache['scan_' + id]) scan = WG._cache['scan_' + id];
  if (!scan) return '<div class="empty-state"><div class="icon">&#8862;</div><h3>Loading scan...</h3><div class="spinner" style="margin:16px auto;"></div></div>';

  var esc = WG.escHtml;
  var scanHosts = WG.getCached('scan_hosts_' + id, '/scans/' + id + '/hosts/', 'hosts').filter(function(h) { return h.scan === id || true; });
  var scanFindings = WG.getCached('scan_findings_' + id, '/scans/' + id + '/findings/', 'findings').filter(function(f) { return f.scan === id || true; });
  var scanReports = scan.reports || [];
  var progress = scan.status === 'running' ? WG.phaseProgress(scan) : scan.status === 'completed' ? 100 : 0;
  var phase = scan.current_phase || 'pending';

  // ── Live polling for running scans ──
  // Every 3s, re-fetch scan detail + hosts + findings. Update cache + DOM
  // in-place so the user sees results trickle in without page flicker.
  WG._stopScanPolling();
  if (scan.status === 'running') {
    WG._startElapsedTicker();
    WG._scanPollTimer = setInterval(function() {
      if (WG.state.currentPage !== 'scan') { WG._stopScanPolling(); return; }
      // Fetch all three endpoints in parallel
      Promise.all([
        WG.api('/scans/' + id + '/'),
        WG.api('/scans/' + id + '/hosts/'),
        WG.api('/scans/' + id + '/findings/')
      ]).then(function(results) {
        var scanData = results[0];
        var hostsData = results[1];
        var findingsData = results[2];
        if (!scanData) return;
        // Update caches
        WG._cache['scan_' + id] = scanData;
        WG._cacheTime['scan_' + id] = Date.now();
        if (Array.isArray(hostsData)) {
          WG._cache['scan_hosts_' + id] = hostsData;
          WG._cacheTime['scan_hosts_' + id] = Date.now();
        }
        if (Array.isArray(findingsData)) {
          WG._cache['scan_findings_' + id] = findingsData;
          WG._cacheTime['scan_findings_' + id] = Date.now();
        }
        // Update counts in stat cards
        var _u = function(sel, val) { var el = document.querySelector(sel); if (el) el.textContent = val; };
        _u('#scan-hosts-count', scanData.hosts_count);
        _u('#scan-ports-count', scanData.ports_count);
        _u('#scan-critical-count', scanData.critical_count);
        _u('#scan-high-count', scanData.high_count);
        _u('#scan-medium-count', scanData.medium_count);
        _u('#scan-low-count', scanData.low_count);
        _u('#scan-info-count', scanData.info_count);
        _u('#scan-findings-count', scanData.findings_count);
        // Update host/finding tab counts
        _u('#scanTabContent-hosts-count .count', Array.isArray(hostsData) ? hostsData.length : 0);
        _u('#scanTabContent-findings-count .count', Array.isArray(findingsData) ? findingsData.length : 0);
        // Update phase + progress
        var phase = scanData.current_phase || 'pending';
        var progress = WG.phaseProgress(scanData);
        _u('#scan-phase-label', WG.phaseLabel(phase));
        _u('#scan-progress-pct', progress + '%');
        var fill = document.querySelector('.progress-fill');
        if (fill) fill.style.width = progress + '%';
        // Re-render the active tab content if new data arrived
        var activeTab = document.querySelector('#scanTabs .tab.active');
        if (activeTab) {
          var tab = activeTab.dataset.tab;
          var content = document.getElementById('scanTabContent');
          if (content) {
            if (tab === 'hosts' && Array.isArray(hostsData)) content.innerHTML = WG._scanHostsTab(hostsData);
            else if (tab === 'findings' && Array.isArray(findingsData)) content.innerHTML = WG._scanFindingsTab(findingsData);
          }
        }
        // If scan finished, stop polling
        if (scanData.status !== 'running') WG._stopScanPolling();
      });
    }, 3000);
  }

  return '' +
    '<div class="breadcrumbs"><a onclick="WG.navigate(\'scans\')">Scans</a><span class="sep">/</span><span>' + esc(scan.name) + '</span></div>' +
    '<div class="page-header">' +
      '<div class="page-header-left"><h1>' + esc(scan.name) + '</h1><p>' + esc(scan.target) + ' &mdash; ' + esc(scan.scan_type) + ' scan</p></div>' +
      '<div class="page-header-actions">' +
        (scan.scan_type === 'phase_based' ? '<button class="btn btn-primary btn-sm" onclick="WG.navigate(\'phase-workflow\',{id:\'' + id + '\'})">Phase Workflow</button>' : '') +
        (scan.status === 'running' ? '<button class="btn btn-danger btn-sm" onclick="WG.cancelScan(\'' + id + '\')">Cancel Scan</button>' : '') +
        (scan.status === 'completed' ? '<button class="btn btn-secondary btn-sm" onclick="WG.toast(\'Rescan queued\',\'info\')">Rescan</button>' : '') +
      '</div>' +
    '</div>' +
    '<div class="info-grid" style="margin-bottom:24px;">' +
      '<div class="info-item"><div class="info-label">Status</div><div class="info-value"><span class="status-badge ' + esc(scan.status) + '"><span class="dot"></span> ' + esc(scan.status) + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Target</div><div class="info-value"><span class="host-tag">' + esc(scan.target) + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Type</div><div class="info-value"><span class="tag">' + esc(scan.scan_type) + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Port Range</div><div class="info-value mono">' + esc(scan.port_range || '1-65535') + '</div></div>' +
      '<div class="info-item"><div class="info-label">Started</div><div class="info-value mono">' + WG.fmtDate(scan.started_at) + '</div></div>' +
      '<div class="info-item"><div class="info-label">Duration</div><div class="info-value mono">' + (scan.status === 'running' ? '<span class="elapsed-live" data-started-at="' + (scan.started_at || '') + '">' + WG.fmtDuration(scan.elapsed_seconds || 0) + '</span>' : WG.fmtDuration(scan.duration_seconds)) + '</div></div>' +
      '<div class="info-item"><div class="info-label">Phase</div><div class="info-value mono" id="scan-phase-label">' + WG.phaseLabel(phase) + (scan.hosts_scanned && scan.hosts_total ? ' (' + scan.hosts_scanned + '/' + scan.hosts_total + ')' : '') + '</div></div>' +
      '<div class="info-item"><div class="info-label">Parallelism</div><div class="info-value mono">' + scan.parallelism + '</div></div>' +
    '</div>' +
    (scan.status === 'running' ?
      '<div style="margin-bottom:24px;"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span class="mono" style="font-size:0.75rem;color:var(--text-dim);">Scan progress — <span id="scan-phase-label">' + WG.phaseLabel(phase) + '</span></span><span class="mono" style="font-size:0.75rem;color:var(--accent);" id="scan-progress-pct">' + progress + '%</span></div><div class="progress-bar"><div class="progress-fill" style="width:' + progress + '%;"></div></div></div>' : '') +
    (scan.error_message ?
      '<div class="panel" style="border-color:rgba(255,59,92,0.2);margin-bottom:20px;"><div class="panel-body" style="color:var(--critical);font-family:var(--font-mono);font-size:0.82rem;">Error: ' + esc(scan.error_message) + '</div></div>' : '') +
    '<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:24px;">' +
      '<div class="stat-card"><div class="stat-label">Hosts</div><div class="stat-value" id="scan-hosts-count">' + scan.hosts_count + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Ports</div><div class="stat-value" id="scan-ports-count">' + scan.ports_count + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Findings</div><div class="stat-value" id="scan-findings-count">' + scan.findings_count + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Duration</div><div class="stat-value mono" id="scan-duration">' + WG.fmtDuration(scan.duration_seconds) + '</div></div>' +
    '</div>' +
    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:24px;">' +
      '<div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value" id="scan-critical-count">' + scan.critical_count + '</div></div>' +
      '<div class="stat-card high"><div class="stat-label">High</div><div class="stat-value" id="scan-high-count">' + scan.high_count + '</div></div>' +
      '<div class="stat-card medium"><div class="stat-label">Medium</div><div class="stat-value" id="scan-medium-count">' + scan.medium_count + '</div></div>' +
      '<div class="stat-card low"><div class="stat-label">Low</div><div class="stat-value" id="scan-low-count">' + scan.low_count + '</div></div>' +
      '<div class="stat-card info"><div class="stat-label">Info</div><div class="stat-value" id="scan-info-count">' + scan.info_count + '</div></div>' +
    '</div>' +
    (function() {
      var flags = [
        { key: 'version_detect', label: 'Version Detect' },
        { key: 'os_detect', label: 'OS Detect' },
        { key: 'service_enum', label: 'Service Enum' },
        { key: 'enum4linux', label: 'Enum4Linux' },
        { key: 'scan_unresponsive', label: 'Scan Unresponsive' },
        { key: 'skip_nuclei', label: 'Nuclei', invert: true },
        { key: 'skip_screenshots', label: 'Screenshots', invert: true },
        { key: 'skip_nikto', label: 'Nikto', invert: true },
        { key: 'skip_netexec', label: 'NetExec', invert: true },
      ];
      var activeFlags = flags.filter(function(f) {
        var val = scan[f.key];
        return f.invert ? val === false || val === true : val === true;
      });
      if (activeFlags.length === 0) return '';
      var badges = activeFlags.map(function(f) {
        var val = scan[f.key];
        var on = f.invert ? !val : val;
        return '<span class="tag" style="font-size:0.68rem;' + (on ? '' : 'opacity:0.5;') + '">' + esc(f.label) + (on ? '' : ' (off)') + '</span>';
      }).join('');
      return '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">Scan Configuration</div></div><div class="panel-body" style="display:flex;gap:6px;flex-wrap:wrap;">' + badges + '</div></div>';
    })() +
    '<div class="tabs" id="scanTabs">' +
      '<div class="tab active" data-tab="hosts" id="scanTabContent-hosts-count" onclick="WG.switchScanTab(\'hosts\',\'' + id + '\')">Hosts <span class="count">' + scanHosts.length + '</span></div>' +
      '<div class="tab" data-tab="findings" id="scanTabContent-findings-count" onclick="WG.switchScanTab(\'findings\',\'' + id + '\')">Findings <span class="count">' + scanFindings.length + '</span></div>' +
      '<div class="tab" data-tab="reports" onclick="WG.switchScanTab(\'reports\',\'' + id + '\')">Reports <span class="count">' + scanReports.length + '</span></div>' +
    '</div>' +
    '<div id="scanTabContent">' + WG._scanHostsTab(scanHosts) + '</div>';
};

WG._scanHostsTab = function(hosts) {
  if (!hosts.length) return '<div class="panel-empty"><div class="icon">&#9678;</div>No hosts discovered</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Phase</th><th>Ports</th><th>Findings</th><th>Screenshots</th></tr></thead><tbody>' +
    hosts.map(function(h) {
      var ssCell = '<span style="color:var(--text-dim)">\u2014</span>';
      if (h.thumbnail_url) {
        ssCell = '<img class="screenshot-thumb" src="' + esc(h.thumbnail_url) + '" loading="lazy" alt="screenshot" style="width:80px;height:45px;" onclick="event.stopPropagation();WG.navigate(\'host\',{id:\'' + h.id + '\'})">';
        if ((h.screenshot_count || 0) > 1) ssCell += ' <span class="screenshot-more">+' + (h.screenshot_count - 1) + '</span>';
      }
      return '<tr onclick="WG.navigate(\'host\',{id:\'' + h.id + '\'})">' +
        '<td><span class="host-tag">' + esc(h.ip) + '</span></td>' +
        '<td>' + (esc(h.hostname) || '<span style="color:var(--text-dim)">\u2014</span>') + '</td>' +
        '<td><span class="tag">' + (esc(h.os) || '\u2014') + '</span></td>' +
        '<td><span class="tag" style="font-family:var(--font-mono);font-size:0.65rem;">' + WG.phaseLabel(h.current_phase || '') + '</span></td>' +
        '<td class="mono">' + h.ports_count + '</td>' +
        '<td class="mono">' + h.findings_count + '</td>' +
        '<td style="padding:4px 8px;">' + ssCell + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG._scanFindingsTab = function(findings) {
  if (!findings.length) return '<div class="panel-empty"><div class="icon">&#9888;</div>No findings</div>';
  var esc = WG.escHtml;
  var pageSize = 100;
  var totalPages = Math.ceil(findings.length / pageSize);
  var scanId = WG.state.currentScanId || '';
  // Clamp page to valid range
  if (!WG._scanFindingsPage || WG._scanFindingsPage < 1) WG._scanFindingsPage = 1;
  if (WG._scanFindingsPage > totalPages) WG._scanFindingsPage = totalPages;
  var page = WG._scanFindingsPage || 1;
  var start = (page - 1) * pageSize;
  var pageItems = findings.slice(start, start + pageSize);
  var sorted = [].concat(pageItems).sort(function(a, b) { return WG.sevOrder(a.severity) - WG.sevOrder(b.severity); });

  var rows = sorted.map(function(f) {
    return '<tr onclick="WG.navigate(\'finding\',{id:\'' + f.id + '\'})">' +
      '<td><span class="sev-badge ' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
      '<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(f.title) + '</td>' +
      '<td><span class="host-tag">' + esc(f.host_ip) + '</span></td>' +
      '<td class="mono">' + esc(f.port || '\u2014') + '</td>' +
      '<td><span class="tag">' + esc(f.source) + '</span>' + (f.source === 'nuclei_external' ? '<span class="tag" style="background:var(--medium-bg,#f59e0b22);color:var(--medium,#f59e0b);font-size:0.6rem;margin-left:4px;" title="External template \u2014 may be a false positive">FP?</span>' : '') + '</td>' +
      '<td class="mono" style="color:var(--accent);">' + esc(f.cve || '\u2014') + '</td></tr>';
  }).join('');

  var paginationHtml = WG._renderScanPagination('findings', page, totalPages, findings.length, scanId);

  return '<div class="panel">' + paginationHtml + '<table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>Source</th><th>CVE</th></tr></thead><tbody>' +
    rows + '</tbody></table>' + paginationHtml + '</div>';
};

WG._renderScanPagination = function(tab, page, totalPages, totalItems, scanId) {
  if (totalPages <= 1) return '';
  var esc = WG.escHtml;
  var start = (page - 1) * 100 + 1;
  var end = Math.min(page * 100, totalItems);
  var html = '<div class="pagination-bar" style="display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;">';
  html += '<span class="pagination-info" style="font-size:0.78rem;color:var(--text-dim);">Showing <strong>' + start + '\u2013' + end + '</strong> of <strong>' + totalItems + '</strong></span>';
  html += '<div class="pagination-btns" style="display:flex;gap:4px;align-items:center;">';
  // Prev
  html += '<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();WG._goScanFindingsPage(' + (page - 1) + ',\'' + scanId + '\')" ' + (page <= 1 ? 'disabled style="opacity:0.4;"' : '') + '>\u2039 Prev</button>';
  // Page numbers
  var maxButtons = 5;
  var firstPage = Math.max(1, page - Math.floor(maxButtons / 2));
  var lastPage = Math.min(totalPages, firstPage + maxButtons - 1);
  if (lastPage - firstPage < maxButtons - 1) firstPage = Math.max(1, lastPage - maxButtons + 1);
  for (var p = firstPage; p <= lastPage; p++) {
    html += '<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();WG._goScanFindingsPage(' + p + ',\'' + scanId + '\')" style="' + (p === page ? 'background:var(--accent);color:#fff;' : '') + 'min-width:32px;">' + p + '</button>';
  }
  // Next
  html += '<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();WG._goScanFindingsPage(' + (page + 1) + ',\'' + scanId + '\')" ' + (page >= totalPages ? 'disabled style="opacity:0.4;"' : '') + '>Next \u203A</button>';
  html += '</div></div>';
  return html;
};

WG._goScanFindingsPage = function(page, scanId) {
  WG._scanFindingsPage = page;
  var findings = WG._cache['scan_findings_' + scanId] || [];
  var el = document.getElementById('scanTabContent');
  if (el) el.innerHTML = WG._scanFindingsTab(findings);
};

WG._scanReportsTab = function(reports) {
  if (!reports.length) return '<div class="panel-empty"><div class="icon">&#128196;</div>No reports generated</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>Format</th><th>File</th><th>Size</th><th>Generated</th><th></th></tr></thead><tbody>' +
    reports.map(function(r) {
      return '<tr>' +
        '<td><span class="tag">' + esc(r.format.toUpperCase()) + '</span></td>' +
        '<td class="mono" style="font-size:0.75rem;">' + esc(r.filename || (r.file_path ? r.file_path.split('/').pop() : r.format)) + '</td>' +
        '<td class="mono">' + WG.fmtBytes(r.file_size) + '</td>' +
        '<td class="mono">' + WG.fmtDate(r.created_at) + '</td>' +
        '<td><button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();WG.downloadReport(\'' + r.id + '\')">Download</button></td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG._stopScanPolling = function() {
  if (WG._scanPollTimer) { clearInterval(WG._scanPollTimer); WG._scanPollTimer = null; }
};

WG.switchScanTab = function(tab, scanId) {
  document.querySelectorAll('#scanTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('scanTabContent');
  var hosts = WG._cache['scan_hosts_' + scanId] || [];
  var findings = WG._cache['scan_findings_' + scanId] || [];
  var scan = WG._cache['scan_' + scanId];
  var reports = scan && scan.reports ? scan.reports : [];
  if (tab === 'hosts') { el.innerHTML = WG._scanHostsTab(hosts); }
  else if (tab === 'findings') { WG._scanFindingsPage = 1; el.innerHTML = WG._scanFindingsTab(findings); }
  else if (tab === 'reports') el.innerHTML = WG._scanReportsTab(reports);
};
