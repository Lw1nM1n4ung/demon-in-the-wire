/* Wire_Ghost — Dashboard page (API-connected) */

WG.renderDashboard = function() {
  // Render with cached/mock data immediately
  var html = WG._buildDashboard();

  // Fetch fresh data from API in background, re-render when ready
  WG.fetchData('/dashboard/', 'dashboard').then(function(data) {
    if (data && data.total_scans !== undefined) {
      WG._cache['dashboard_stats'] = data;
      WG._cacheTime['dashboard_stats'] = Date.now();
    }
  });
  WG.fetchData('/scans/', 'scans').then(function(data) {
    if (data && data.length !== undefined) {
      WG._cache['scans'] = data;
      WG._cacheTime['scans'] = Date.now();
      // Re-render if still on dashboard
      if (WG.state.currentPage === 'dashboard') {
        var main = document.getElementById('mainContent');
        if (main) main.innerHTML = WG._buildDashboard();
      }
    }
  });
  WG.fetchData('/findings/?severity=critical', 'findings').then(function(data) {
    if (data) {
      WG._cache['critical_findings'] = data;
      WG._cacheTime['critical_findings'] = Date.now();
    }
  });

  return html;
};

WG._buildDashboard = function() {
  var stats = WG._cache['dashboard_stats'];
  var scans = WG._cache['scans'] || WG.getMock('scans');
  var findings = WG._cache['critical_findings'] || WG.getMock('findings');
  var esc = WG.escHtml;

  // If we have API stats, use those; otherwise calculate from mock scans
  var totalScans, totalHosts, totalFindings, totalCritical, totalHigh, totalMedium, totalLow, totalInfo, runningScans;

  if (stats) {
    totalScans = stats.total_scans || 0;
    totalHosts = stats.total_hosts || 0;
    totalFindings = stats.total_findings || 0;
    totalCritical = (stats.severity || {}).critical || 0;
    totalHigh = (stats.severity || {}).high || 0;
    totalMedium = (stats.severity || {}).medium || 0;
    totalLow = (stats.severity || {}).low || 0;
    totalInfo = (stats.severity || {}).info || 0;
    runningScans = stats.running_scans || 0;
    if (stats.recent_scans) scans = stats.recent_scans;
  } else {
    totalFindings = scans.reduce(function(s, x) { return s + x.findings_count; }, 0);
    totalCritical = scans.reduce(function(s, x) { return s + x.critical_count; }, 0);
    totalHigh = scans.reduce(function(s, x) { return s + x.high_count; }, 0);
    totalMedium = scans.reduce(function(s, x) { return s + x.medium_count; }, 0);
    totalLow = scans.reduce(function(s, x) { return s + x.low_count; }, 0);
    totalInfo = scans.reduce(function(s, x) { return s + x.info_count; }, 0);
    totalHosts = scans.reduce(function(s, x) { return s + x.hosts_count; }, 0);
    totalScans = scans.length;
    runningScans = scans.filter(function(s) { return s.status === 'running'; }).length;
  }

  var sb1 = document.getElementById('sidebarScansBadge');
  var sb2 = document.getElementById('sidebarFindingsBadge');
  if (sb1) sb1.textContent = runningScans || '';
  if (sb2) sb2.textContent = totalFindings || '';

  var sevItems = [
    { name: 'Critical', count: totalCritical, cls: 'critical', color: 'var(--critical)' },
    { name: 'High', count: totalHigh, cls: 'high', color: 'var(--high)' },
    { name: 'Medium', count: totalMedium, cls: 'medium', color: 'var(--medium)' },
    { name: 'Low', count: totalLow, cls: 'low', color: 'var(--low)' },
    { name: 'Info', count: totalInfo, cls: 'info', color: 'var(--info)' },
  ];

  var critHighFindings = findings.filter(function(f) { return f.severity === 'critical' || f.severity === 'high'; }).slice(0, 8);

  return '' +
    '<div class="page-header">' +
      '<div class="page-header-left"><h1>Dashboard</h1><p>Vulnerability assessment overview</p></div>' +
      '<div class="page-header-actions">' +
        '<button class="btn btn-secondary btn-sm" onclick="WG.invalidateCache();WG.render()">&#8635; Refresh</button>' +
        '<button class="btn btn-primary" onclick="WG.openModal(\'scanModal\')"><span>+</span> New Scan</button>' +
      '</div>' +
    '</div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(6,1fr);">' +
      '<div class="stat-card anim-reveal anim-reveal-1"><div class="stat-label">Total Scans</div><div class="stat-value">' + totalScans + '</div><div class="stat-sub up">' + runningScans + ' running</div></div>' +
      '<div class="stat-card anim-reveal anim-reveal-2"><div class="stat-label">Hosts</div><div class="stat-value">' + totalHosts + '</div></div>' +
      '<div class="stat-card critical anim-reveal anim-reveal-3"><div class="stat-label">Critical</div><div class="stat-value">' + totalCritical + '</div></div>' +
      '<div class="stat-card high anim-reveal anim-reveal-4"><div class="stat-label">High</div><div class="stat-value">' + totalHigh + '</div></div>' +
      '<div class="stat-card medium anim-reveal anim-reveal-5"><div class="stat-label">Medium</div><div class="stat-value">' + totalMedium + '</div></div>' +
      '<div class="stat-card low anim-reveal"><div class="stat-label">Low</div><div class="stat-value">' + totalLow + '</div></div>' +
    '</div>' +

    '<div class="grid-2-1" style="margin-bottom:20px;">' +
      '<div class="panel anim-reveal" style="animation-delay:0.3s;">' +
        '<div class="panel-header"><div class="panel-title">Recent Scans <span class="count">' + scans.length + '</span></div><button class="btn btn-ghost btn-sm" onclick="WG.navigate(\'scans\')">View All</button></div>' +
        '<table class="data-table"><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Duration</th><th>Started</th></tr></thead><tbody>' +
        (scans.length ? scans.slice(0, 5).map(function(s) {
          return '<tr onclick="WG.navigate(\'scan\',{id:\'' + s.id + '\'})">' +
            '<td><span class="host-tag">' + esc(s.target) + '</span><div class="mono" style="font-size:0.7rem;margin-top:2px;">' + esc(s.name) + '</div></td>' +
            '<td><span class="status-badge ' + s.status + '"><span class="dot"></span> ' + s.status + '</span></td>' +
            '<td>' + WG.sevBarHtml(s) + '<div class="mono" style="font-size:0.65rem;margin-top:3px;">' + s.findings_count + ' total</div></td>' +
            '<td class="mono">' + WG.fmtDuration(s.duration_seconds) + '</td>' +
            '<td class="mono">' + WG.timeAgo(s.created_at) + '</td></tr>';
        }).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:30px;">No scans yet. Click "New Scan" to start.</td></tr>') +
        '</tbody></table></div>' +

      '<div style="display:flex;flex-direction:column;gap:16px;">' +
        '<div class="panel anim-reveal" style="animation-delay:0.35s;">' +
          '<div class="panel-header"><div class="panel-title">Severity Breakdown</div></div>' +
          '<div class="panel-body">' + WG.sevDistHtml(sevItems, totalFindings) + '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +

    (critHighFindings.length ? '' +
      '<div class="panel anim-reveal" style="animation-delay:0.45s;">' +
        '<div class="panel-header"><div class="panel-title">Critical & High Findings</div><button class="btn btn-ghost btn-sm" onclick="WG.navigate(\'findings\')">View All</button></div>' +
        '<table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>Source</th><th>CVE</th></tr></thead><tbody>' +
        critHighFindings.map(function(f) {
          return '<tr onclick="WG.navigate(\'finding\',{id:\'' + f.id + '\'})">' +
            '<td><span class="sev-badge ' + f.severity + '">' + f.severity + '</span></td>' +
            '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(f.title) + '</td>' +
            '<td><span class="host-tag">' + esc(f.host_ip) + '</span></td>' +
            '<td class="mono">' + (f.port || '\u2014') + '</td>' +
            '<td><span class="tag">' + f.source + '</span>' + (f.source === 'nuclei_external' ? '<span class="tag" style="background:var(--medium-bg,#f59e0b22);color:var(--medium,#f59e0b);font-size:0.6rem;margin-left:4px;" title="External template \u2014 may be a false positive">FP?</span>' : '') + '</td>' +
            '<td class="mono" style="color:var(--accent);">' + (f.cve || '\u2014') + '</td></tr>';
        }).join('') +
        '</tbody></table></div>'
    : '');
};
