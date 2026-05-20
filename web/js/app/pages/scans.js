/* Wire_Ghost — Scans page (enhanced) */

WG.renderScans = function() {
  var scans = WG.getCached('scans', '/scans/');
  // Background refresh
  WG.refreshAndRerender('scans', '/scans/', WG.renderScans, 'scans');
  var esc = WG.escHtml;

  var running = scans.filter(function(s) { return s.status === 'running'; });
  var completed = scans.filter(function(s) { return s.status === 'completed'; });
  var pending = scans.filter(function(s) { return s.status === 'pending'; });
  var failed = scans.filter(function(s) { return s.status === 'failed'; });

  return '' +
    '<div class="page-header">' +
      '<div class="page-header-left"><h1>Scans</h1><p>' + scans.length + ' total scans</p></div>' +
      '<div class="page-header-actions">' +
        '<button class="btn btn-secondary btn-sm" onclick="WG._bulkAction(\'select\')">Select All</button>' +
        '<button class="btn btn-primary" onclick="WG.openModal(\'scanModal\')"><span>+</span> New Scan</button>' +
      '</div>' +
    '</div>' +

    /* Stats row */
    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:20px;">' +
      '<div class="stat-card"><div class="stat-label">Total</div><div class="stat-value">' + scans.length + '</div></div>' +
      '<div class="stat-card" style="cursor:pointer;" onclick="document.getElementById(\'scanStatusFilter\').value=\'running\';WG.filterScans()"><div class="stat-label">Running</div><div class="stat-value" style="color:var(--accent);">' + running.length + '</div></div>' +
      '<div class="stat-card" style="cursor:pointer;" onclick="document.getElementById(\'scanStatusFilter\').value=\'completed\';WG.filterScans()"><div class="stat-label">Completed</div><div class="stat-value" style="color:var(--success);">' + completed.length + '</div></div>' +
      '<div class="stat-card" style="cursor:pointer;" onclick="document.getElementById(\'scanStatusFilter\').value=\'pending\';WG.filterScans()"><div class="stat-label">Pending</div><div class="stat-value" style="color:var(--medium);">' + pending.length + '</div></div>' +
      '<div class="stat-card" style="cursor:pointer;" onclick="document.getElementById(\'scanStatusFilter\').value=\'failed\';WG.filterScans()"><div class="stat-label">Failed</div><div class="stat-value" style="color:var(--critical);">' + failed.length + '</div></div>' +
    '</div>' +

    /* Running scans — live progress cards */
    (running.length ? '' +
      '<div style="margin-bottom:20px;">' +
        '<div style="font-weight:700;color:var(--text-bright);margin-bottom:12px;display:flex;align-items:center;gap:8px;">' +
          '<span class="status-badge running" style="font-size:0.65rem;"><span class="dot"></span> Live</span> Running Scans' +
        '</div>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;">' +
          running.map(function(s) {
            var phase = s.current_phase || 'discovery';
            var progress = WG.phaseProgress(s);
            var phaseOrder = ['discovery', 'portscan', 'reports'];
            var phaseNames = { discovery: 'Discovery', portscan: 'Port Scan', reports: 'Reports' };
            var activeIdx = phaseOrder.indexOf(phase);
            if (activeIdx < 0) activeIdx = 0;
            return '<div class="panel" style="cursor:pointer;" onclick="WG.navigate(\'scan\',{id:\'' + s.id + '\'})">' +
              '<div class="panel-body">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">' +
                  '<div><div style="font-weight:700;color:var(--text-bright);">' + esc(s.name) + '</div>' +
                  '<span class="host-tag" style="font-size:0.75rem;">' + esc(s.target) + '</span></div>' +
                  '<button class="btn btn-danger btn-sm" onclick="event.stopPropagation();WG.cancelScan(\'' + s.id + '\')">Cancel</button>' +
                '</div>' +
                '<div style="display:flex;justify-content:space-between;margin-bottom:6px;">' +
                  '<span class="elapsed-live mono" style="font-size:0.7rem;color:var(--text-dim);" data-started-at="' + (s.started_at || '') + '">' + WG.fmtDuration(s.elapsed_seconds || 0) + '</span>' +
                  '<span class="mono" style="font-size:0.7rem;color:var(--accent);">' + progress + '%</span>' +
                '</div>' +
                '<div class="progress-bar" style="margin-bottom:12px;"><div class="progress-fill" style="width:' + progress + '%;"></div></div>' +
                '<div style="display:flex;gap:4px;">' +
                  phaseOrder.map(function(ph, pi) {
                    var state = pi < activeIdx ? 'done' : pi === activeIdx ? 'active' : 'pending';
                    var style = state === 'done' ? 'background:var(--success-dim);color:var(--success);'
                              : state === 'active' ? 'background:var(--accent-dim);color:var(--accent);'
                              : 'background:var(--bg-card);color:var(--text-dim);';
                    return '<div style="flex:1;text-align:center;padding:4px 0;border-radius:var(--radius-xs);font-size:0.6rem;font-family:var(--font-mono);' + style + '">'
                      + (state === 'done' ? '&#10003; ' : '') + phaseNames[ph] + '</div>';
                  }).join('') +
                '</div>' +
                '<div style="display:flex;gap:12px;margin-top:10px;font-family:var(--font-mono);font-size:0.68rem;color:var(--text-dim);">' +
                  '<span>Phase: ' + WG.phaseLabel(phase) + '</span>' +
                  '<span>Hosts: ' + s.hosts_count + '</span>' +
                  '<span>Findings: ' + s.findings_count + '</span>' +
                  '<span>Critical: ' + s.critical_count + '</span>' +
                '</div>' +
              '</div></div>';
          }).join('') +
        '</div>' +
      '</div>'
    : '') +

    /* Filters */
    '<div class="filters-bar">' +
      '<input class="filter-input" placeholder="Search scans..." id="scanSearch" oninput="WG.filterScans()">' +
      '<select class="filter-select" id="scanStatusFilter" onchange="WG.filterScans()"><option value="">All Status</option><option value="running">Running</option><option value="completed">Completed</option><option value="pending">Pending</option><option value="failed">Failed</option><option value="cancelled">Cancelled</option></select>' +
      '<select class="filter-select" id="scanTypeFilter" onchange="WG.filterScans()"><option value="">All Types</option><option value="full">Full Scan</option><option value="quick">Quick Scan</option><option value="port">Port Scan</option><option value="web">Web App</option><option value="service">Service Enum</option></select>' +
      '<div style="margin-left:auto;display:flex;gap:6px;">' +
        '<button class="btn btn-ghost btn-sm" onclick="WG._bulkAction(\'cancel\')" title="Cancel selected">Cancel Sel.</button>' +
        '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG._bulkAction(\'delete\')" title="Delete selected">Delete Sel.</button>' +
      '</div>' +
    '</div>' +

    /* Scans table */
    '<div class="panel"><table class="data-table" id="scansTable"><thead><tr>' +
      '<th style="width:30px;"><input type="checkbox" id="scanSelectAll" onchange="WG._toggleAllScans(this.checked)" style="cursor:pointer;"></th>' +
      '<th>Name / Target</th><th>Type</th><th>Status</th><th>Hosts</th><th>Findings</th><th>Severity</th><th>Duration</th><th>Created</th><th></th>' +
    '</tr></thead><tbody>' +
    scans.map(function(s) {
      return '<tr data-id="' + s.id + '" data-status="' + s.status + '" data-type="' + s.scan_type + '" data-search="' + esc((s.name + ' ' + s.target).toLowerCase()) + '">' +
        '<td onclick="event.stopPropagation();"><input type="checkbox" class="scan-check" data-id="' + s.id + '" style="cursor:pointer;"></td>' +
        '<td onclick="WG.navigate(\'scan\',{id:\'' + s.id + '\'})" style="cursor:pointer;"><div style="font-weight:600;color:var(--text-bright);">' + esc(s.name) + '</div><span class="host-tag" style="margin-top:2px;">' + esc(s.target) + '</span></td>' +
        '<td><span class="tag">' + esc(s.scan_type) + '</span></td>' +
        '<td><span class="status-badge ' + esc(s.status) + '"><span class="dot"></span> ' + esc(s.status) + '</span></td>' +
        '<td class="mono">' + s.hosts_count + '</td>' +
        '<td class="mono">' + s.findings_count + '</td>' +
        '<td>' + WG.sevBarHtml(s) + '</td>' +
        '<td class="mono">' + (s.status === 'running' ? '<span class="elapsed-live" data-started-at="' + (s.started_at || '') + '">' + WG.fmtDuration(s.elapsed_seconds || 0) + '</span>' : WG.fmtDuration(s.duration_seconds)) + '</td>' +
        '<td class="mono">' + WG.timeAgo(s.created_at) + '</td>' +
        '<td style="text-align:right;" onclick="event.stopPropagation();">' +
          (s.status === 'completed' ? '<button class="btn btn-ghost btn-sm" onclick="WG._rescan(\'' + s.id + '\')" title="Rescan">&#8635;</button>' : '') +
          (s.status === 'running' ? '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG.cancelScan(\'' + s.id + '\')" title="Cancel">&#10005;</button>' : '') +
        '</td>' +
      '</tr>';
    }).join('') +
    '</tbody></table></div>' +

    /* Scan comparison section */
    '<div class="panel" style="margin-top:20px;">' +
      '<div class="panel-header"><div class="panel-title">Scan Comparison</div></div>' +
      '<div class="panel-body">' +
        '<p style="font-size:0.82rem;color:var(--text-dim);margin-bottom:14px;">Compare findings between two completed scans to identify new, resolved, and persistent vulnerabilities.</p>' +
        '<div class="form-row">' +
          '<div class="form-group"><label class="form-label">Scan A (Baseline)</label><select class="form-select" id="compareA">' +
            '<option value="">Select scan...</option>' +
            completed.map(function(s) { return '<option value="' + s.id + '">' + esc(s.name) + ' (' + esc(s.target) + ')</option>'; }).join('') +
          '</select></div>' +
          '<div class="form-group"><label class="form-label">Scan B (Current)</label><select class="form-select" id="compareB">' +
            '<option value="">Select scan...</option>' +
            completed.map(function(s) { return '<option value="' + s.id + '">' + esc(s.name) + ' (' + esc(s.target) + ')</option>'; }).join('') +
          '</select></div>' +
        '</div>' +
        '<button class="btn btn-secondary btn-sm" onclick="WG._compareScans()" style="margin-top:10px;">Compare</button>' +
        '<div id="compareResults" style="margin-top:14px;"></div>' +
      '</div>' +
    '</div>';
};

WG.filterScans = function() {
  var search = (document.getElementById('scanSearch').value || '').toLowerCase();
  var status = document.getElementById('scanStatusFilter').value;
  var type = document.getElementById('scanTypeFilter').value;
  document.querySelectorAll('#scansTable tbody tr').forEach(function(tr) {
    var ok = (!search || tr.dataset.search.includes(search)) &&
             (!status || tr.dataset.status === status) &&
             (!type || tr.dataset.type === type);
    tr.style.display = ok ? '' : 'none';
  });
};

WG._toggleAllScans = function(checked) {
  document.querySelectorAll('.scan-check').forEach(function(cb) { cb.checked = checked; });
};

WG._getSelectedIds = function() {
  var ids = [];
  document.querySelectorAll('.scan-check:checked').forEach(function(cb) { ids.push(cb.dataset.id); });
  return ids;
};

WG._bulkAction = function(action) {
  if (action === 'select') {
    var all = document.getElementById('scanSelectAll');
    if (all) { all.checked = true; WG._toggleAllScans(true); }
    return;
  }
  var ids = WG._getSelectedIds();
  if (!ids.length) { WG.toast('No scans selected', 'info'); return; }

  if (action === 'cancel') {
    var cancelled = 0;
    ids.forEach(function(id) {
      var scan = (WG._cache['scans'] || []).find(function(s) { return s.id === id && s.status === 'running'; });
      if (scan) {
        cancelled++;
        WG.api('/scans/' + id + '/cancel/', { method: 'POST' });
      }
    });
    WG.toast('Cancelled ' + cancelled + ' scan(s)', 'info');
    WG.invalidateCache('scans');
    WG.render();
  }
  if (action === 'delete') {
    ids.forEach(function(id) {
      WG.api('/scans/' + id + '/', { method: 'DELETE' });
    });
    WG.toast('Deleted ' + ids.length + ' scan(s)', 'info');
    WG.invalidateCache('scans');
    WG.render();
  }
};

WG._rescan = function(id) {
  var scan = (WG._cache['scans'] || []).find(function(s) { return s.id === id; });
  if (!scan) return;
  WG.openModal('scanModal');
  setTimeout(function() {
    var t = document.getElementById('scanTarget');
    var n = document.getElementById('scanName');
    if (t) t.value = scan.target;
    if (n) n.value = 'Rescan: ' + scan.name;
  }, 100);
};

WG._compareScans = function() {
  var aId = document.getElementById('compareA').value;
  var bId = document.getElementById('compareB').value;
  var el = document.getElementById('compareResults');
  if (!aId || !bId) { el.innerHTML = '<span style="color:var(--critical);font-size:0.82rem;">Select two scans</span>'; return; }
  if (aId === bId) { el.innerHTML = '<span style="color:var(--medium);font-size:0.82rem;">Select two different scans</span>'; return; }

  var aFindings = (WG._cache['scan_findings_' + aId] || WG.getCached('scan_findings_' + aId, '/scans/' + aId + '/findings/', 'findings'));
  var bFindings = (WG._cache['scan_findings_' + bId] || WG.getCached('scan_findings_' + bId, '/scans/' + bId + '/findings/', 'findings'));

  var aTitles = {};
  aFindings.forEach(function(f) { aTitles[f.title + ':' + f.host_ip] = f; });
  var bTitles = {};
  bFindings.forEach(function(f) { bTitles[f.title + ':' + f.host_ip] = f; });

  var newFindings = bFindings.filter(function(f) { return !aTitles[f.title + ':' + f.host_ip]; });
  var resolvedFindings = aFindings.filter(function(f) { return !bTitles[f.title + ':' + f.host_ip]; });
  var persistent = bFindings.filter(function(f) { return !!aTitles[f.title + ':' + f.host_ip]; });

  el.innerHTML = '' +
    '<div style="display:flex;gap:14px;margin-bottom:14px;">' +
      '<div class="stat-card" style="flex:1;padding:14px;"><div class="stat-label">New</div><div class="stat-value" style="color:var(--critical);font-size:1.4rem;">' + newFindings.length + '</div></div>' +
      '<div class="stat-card" style="flex:1;padding:14px;"><div class="stat-label">Resolved</div><div class="stat-value" style="color:var(--success);font-size:1.4rem;">' + resolvedFindings.length + '</div></div>' +
      '<div class="stat-card" style="flex:1;padding:14px;"><div class="stat-label">Persistent</div><div class="stat-value" style="color:var(--medium);font-size:1.4rem;">' + persistent.length + '</div></div>' +
    '</div>' +
    (newFindings.length ? '<div style="margin-bottom:10px;"><div style="font-weight:600;color:var(--critical);font-size:0.82rem;margin-bottom:6px;">New Findings</div>' +
      newFindings.map(function(f) {
        return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:0.78rem;border-bottom:1px solid var(--border-dim);"><span class="sev-badge ' + WG.escHtml(f.severity) + '" style="font-size:0.6rem;">' + WG.escHtml(f.severity) + '</span><span style="color:var(--text-primary);">' + WG.escHtml(f.title) + '</span><span class="mono" style="color:var(--text-dim);">' + WG.escHtml(f.host_ip) + '</span></div>';
      }).join('') + '</div>' : '') +
    (resolvedFindings.length ? '<div><div style="font-weight:600;color:var(--success);font-size:0.82rem;margin-bottom:6px;">Resolved</div>' +
      resolvedFindings.map(function(f) {
        return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:0.78rem;border-bottom:1px solid var(--border-dim);text-decoration:line-through;opacity:0.6;"><span class="sev-badge ' + WG.escHtml(f.severity) + '" style="font-size:0.6rem;">' + WG.escHtml(f.severity) + '</span><span>' + WG.escHtml(f.title) + '</span><span class="mono">' + WG.escHtml(f.host_ip) + '</span></div>';
      }).join('') + '</div>' : '');
};
