/* Wire_Ghost — Scan detail page */

WG.renderScanDetail = function(id) {
  var scan = WG.getCached('scans', '/scans/').find(function(s) { return s.id === id; });

  // Fetch full scan detail from API (once per cache cycle)
  if (!WG._cache['scan_' + id]) {
    WG.api('/scans/' + id + '/').then(function(data) {
      if (data && WG.state.currentPage === 'scan') {
        WG._cache['scan_' + id] = data;
        WG._cacheTime['scan_' + id] = Date.now();
        var main = document.getElementById('mainContent');
        if (main && !document.querySelector(".modal-overlay.active")) main.innerHTML = WG.renderScanDetail(id);
      }
    });
  }

  // Use cached full detail if available
  if (WG._cache['scan_' + id]) scan = WG._cache['scan_' + id];
  if (!scan) return '<div class="empty-state"><div class="icon">&#8862;</div><h3>Loading scan...</h3><div class="spinner" style="margin:16px auto;"></div></div>';

  var esc = WG.escHtml;
  var scanHosts = WG.getCached('scan_hosts_' + id, '/scans/' + id + '/hosts/', 'hosts').filter(function(h) { return h.scan === id || true; });
  var scanFindings = WG.getCached('scan_findings_' + id, '/scans/' + id + '/findings/', 'findings').filter(function(f) { return f.scan === id || true; });
  var scanReports = scan.reports || [];
  var progress = scan.status === 'running' ? 65 : scan.status === 'completed' ? 100 : 0;

  return '' +
    '<div class="breadcrumbs"><a onclick="WG.navigate(\'scans\')">Scans</a><span class="sep">/</span><span>' + esc(scan.name) + '</span></div>' +
    '<div class="page-header">' +
      '<div class="page-header-left"><h1>' + esc(scan.name) + '</h1><p>' + esc(scan.target) + ' &mdash; ' + esc(scan.scan_type) + ' scan</p></div>' +
      '<div class="page-header-actions">' +
        (scan.status === 'running' ? '<button class="btn btn-danger btn-sm" onclick="WG.cancelScan(\'' + id + '\')">Cancel Scan</button>' : '') +
        (scan.status === 'completed' ? '<button class="btn btn-secondary btn-sm" onclick="WG.toast(\'Rescan queued\',\'info\')">Rescan</button>' : '') +
      '</div>' +
    '</div>' +
    '<div class="info-grid" style="margin-bottom:24px;">' +
      '<div class="info-item"><div class="info-label">Status</div><div class="info-value"><span class="status-badge ' + esc(scan.status) + '"><span class="dot"></span> ' + esc(scan.status) + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Target</div><div class="info-value"><span class="host-tag">' + esc(scan.target) + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Type</div><div class="info-value"><span class="tag">' + esc(scan.scan_type) + '</span></div></div>' +
      '<div class="info-item"><div class="info-label">Started</div><div class="info-value mono">' + WG.fmtDate(scan.started_at) + '</div></div>' +
      '<div class="info-item"><div class="info-label">Duration</div><div class="info-value mono">' + WG.fmtDuration(scan.duration_seconds) + '</div></div>' +
      '<div class="info-item"><div class="info-label">Parallelism</div><div class="info-value mono">' + scan.parallelism + '</div></div>' +
    '</div>' +
    (scan.status === 'running' ?
      '<div style="margin-bottom:24px;"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span class="mono" style="font-size:0.75rem;color:var(--text-dim);">Scan progress</span><span class="mono" style="font-size:0.75rem;color:var(--accent);">' + progress + '%</span></div><div class="progress-bar"><div class="progress-fill" style="width:' + progress + '%;"></div></div></div>' : '') +
    (scan.error_message ?
      '<div class="panel" style="border-color:rgba(255,59,92,0.2);margin-bottom:20px;"><div class="panel-body" style="color:var(--critical);font-family:var(--font-mono);font-size:0.82rem;">Error: ' + esc(scan.error_message) + '</div></div>' : '') +
    '<div class="stats-grid" style="margin-bottom:24px;">' +
      '<div class="stat-card"><div class="stat-label">Hosts</div><div class="stat-value">' + scan.hosts_count + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Ports</div><div class="stat-value">' + scan.ports_count + '</div></div>' +
      '<div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value">' + scan.critical_count + '</div></div>' +
      '<div class="stat-card high"><div class="stat-label">High</div><div class="stat-value">' + scan.high_count + '</div></div>' +
      '<div class="stat-card medium"><div class="stat-label">Medium</div><div class="stat-value">' + scan.medium_count + '</div></div>' +
    '</div>' +
    '<div class="tabs" id="scanTabs">' +
      '<div class="tab active" data-tab="hosts" onclick="WG.switchScanTab(\'hosts\',\'' + id + '\')">Hosts <span class="count">' + scanHosts.length + '</span></div>' +
      '<div class="tab" data-tab="findings" onclick="WG.switchScanTab(\'findings\',\'' + id + '\')">Findings <span class="count">' + scanFindings.length + '</span></div>' +
      '<div class="tab" data-tab="reports" onclick="WG.switchScanTab(\'reports\',\'' + id + '\')">Reports <span class="count">' + scanReports.length + '</span></div>' +
    '</div>' +
    '<div id="scanTabContent">' + WG._scanHostsTab(scanHosts) + '</div>';
};

WG._scanHostsTab = function(hosts) {
  if (!hosts.length) return '<div class="panel-empty"><div class="icon">&#9678;</div>No hosts discovered</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Findings</th></tr></thead><tbody>' +
    hosts.map(function(h) {
      return '<tr onclick="WG.navigate(\'host\',{id:\'' + h.id + '\'})">' +
        '<td><span class="host-tag">' + esc(h.ip) + '</span></td>' +
        '<td>' + (esc(h.hostname) || '<span style="color:var(--text-dim)">\u2014</span>') + '</td>' +
        '<td><span class="tag">' + (esc(h.os) || '\u2014') + '</span></td>' +
        '<td class="mono">' + h.ports_count + '</td>' +
        '<td class="mono">' + h.findings_count + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG._scanFindingsTab = function(findings) {
  if (!findings.length) return '<div class="panel-empty"><div class="icon">&#9888;</div>No findings</div>';
  var esc = WG.escHtml;
  return '<div class="panel"><table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>Source</th><th>CVE</th></tr></thead><tbody>' +
    findings.sort(function(a, b) { return WG.sevOrder(a.severity) - WG.sevOrder(b.severity); }).map(function(f) {
      return '<tr onclick="WG.navigate(\'finding\',{id:\'' + f.id + '\'})">' +
        '<td><span class="sev-badge ' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
        '<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(f.title) + '</td>' +
        '<td><span class="host-tag">' + esc(f.host_ip) + '</span></td>' +
        '<td class="mono">' + esc(f.port || '\u2014') + '</td>' +
        '<td><span class="tag">' + esc(f.source) + '</span>' + (f.source === 'nuclei_external' ? '<span class="tag" style="background:var(--medium-bg,#f59e0b22);color:var(--medium,#f59e0b);font-size:0.6rem;margin-left:4px;" title="External template \u2014 may be a false positive">FP?</span>' : '') + '</td>' +
        '<td class="mono" style="color:var(--accent);">' + esc(f.cve || '\u2014') + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
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

WG.switchScanTab = function(tab, scanId) {
  document.querySelectorAll('#scanTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('scanTabContent');
  var hosts = WG._cache['scan_hosts_' + scanId] || [];
  var findings = WG._cache['scan_findings_' + scanId] || [];
  var scan = WG._cache['scan_' + scanId];
  var reports = scan && scan.reports ? scan.reports : [];
  if (tab === 'hosts') el.innerHTML = WG._scanHostsTab(hosts);
  else if (tab === 'findings') el.innerHTML = WG._scanFindingsTab(findings);
  else if (tab === 'reports') el.innerHTML = WG._scanReportsTab(reports);
};
