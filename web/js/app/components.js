/* Wire_Ghost — Shared render components */

/* ── Shared phase ordering and labels ──
 * Single source of truth — all pages that render phase pills or progress bars
 * must reference WG.PHASE_ORDER and WG.PHASE_LABELS instead of hardcoding. */
WG.PHASE_ORDER = ['discovery', 'portscan', 'webdetect', 'webcrawl', 'vulnscan', 'enumeration', 'reports'];
WG.PHASE_LABELS = {
  'discovery': 'Discovery', 'portscan': 'Port Scan', 'webdetect': 'Web Detect',
  'webcrawl': 'Web Crawl', 'vulnscan': 'Vuln Scan', 'enumeration': 'Enumeration', 'reports': 'Reports'
};

/* ── Real-time progress calculation ──
 * hosts_scanned is now a pre-computed weighted percentage (0-99) from the
 * orchestrator's per-host phase tracking.  Fast hosts pull the bar forward
 * instead of one slow host stalling it.  Terminal states return 100 or 0. */
WG.phaseProgress = function(s) {
  if (s.status === 'completed' || s.current_phase === 'completed') return 100;
  if (s.status === 'failed' || s.current_phase === 'failed') return 100;
  if (s.status === 'cancelled' || s.current_phase === 'cancelled') return 100;
  if (!s.current_phase || s.current_phase === 'pending') return 0;
  // Running scan — hosts_scanned IS the weighted progress % (0-99).
  return Math.min(99, s.hosts_scanned || 0);
};

/* Weighted progress from PhaseRun statuses for phase-based scans. Each
 * completed/skipped phase contributes equally. Running phases count as
 * partial. Returns 0-100. */
WG.phaseBasedProgress = function(phases) {
  if (!phases || !phases.length) return 0;
  var total = phases.length;
  var done = 0;
  for (var i = 0; i < phases.length; i++) {
    if (phases[i].status === 'completed' || phases[i].status === 'skipped') done++;
  }
  return Math.round((done / total) * 100);
};

/* CSS class for phase status badge. */
WG.phaseStatusBadge = function(status) {
  var map = {
    pending: 'info', running: 'running', completed: 'success',
    failed: 'error', cancelled: 'warning', skipped: 'muted'
  };
  return 'badge badge-' + (map[status] || 'info');
};

/* ── Global elapsed-time ticker ──
 * Updates every .elapsed-live element once per second. Each element carries a
 * data-started-at ISO-8601 timestamp. The ticker runs once and uses a single
 * setInterval for all visible pages — no per-render leak. */
(function() {
  var _tickerStarted = false;
  WG._startElapsedTicker = function() {
    if (_tickerStarted) return;
    _tickerStarted = true;
    setInterval(function() {
      document.querySelectorAll('.elapsed-live').forEach(function(el) {
        var started = el.getAttribute('data-started-at');
        if (!started) return;
        var secs = Math.floor((Date.now() - Date.parse(started)) / 1000);
        if (secs < 0) secs = 0;
        el.textContent = WG.fmtDuration(secs);
      });
    }, 1000);
  };
})();

/* ── Phase label helper ── */
WG.phaseLabel = function(phase) {
  var labels = {
    'pending': 'Pending', 'completed': 'Done', 'failed': 'Failed', 'cancelled': 'Cancelled'
  };
  return WG.PHASE_LABELS[phase] || labels[phase] || phase || 'Pending';
};

/* ── Sidebar collapsible parent ── */
WG._toggleSidebarParent = function(toggleEl) {
  var parent = toggleEl.closest('.sidebar-parent');
  var children = parent.querySelector('.sidebar-children');
  if (!children) return;
  if (parent.classList.contains('expanded')) {
    children.style.maxHeight = '0px';
    parent.classList.remove('expanded'); parent.classList.add('collapsed');
  } else {
    children.style.maxHeight = children.scrollHeight + 'px';
    parent.classList.remove('collapsed'); parent.classList.add('expanded');
  }
  WG._saveSidebarState();
};

WG._saveSidebarState = function() {
  var state = {};
  document.querySelectorAll('.sidebar-parent[data-collapsible]').forEach(function(el) {
    state[el.dataset.collapsible] = el.classList.contains('expanded') ? 'expanded' : 'collapsed';
  });
  try { localStorage.setItem('wg_sidebar_state', JSON.stringify(state)); } catch(e) {}
};

WG._loadSidebarState = function() {
  try {
    var saved = JSON.parse(localStorage.getItem('wg_sidebar_state'));
    if (!saved) return;
    document.querySelectorAll('.sidebar-parent[data-collapsible]').forEach(function(el) {
      var key = el.dataset.collapsible;
      if (!key || saved[key] !== 'expanded') return;
      var children = el.querySelector('.sidebar-children');
      if (!children) return;
      children.style.maxHeight = 'none';
      var h = children.scrollHeight;
      children.style.maxHeight = h + 'px';
      el.classList.remove('collapsed'); el.classList.add('expanded');
    });
  } catch(e) {}
};

WG.sevBarHtml = function(scan) {
  var total = (scan.critical_count || 0) + (scan.high_count || 0) + (scan.medium_count || 0) + (scan.low_count || 0) + (scan.info_count || 0);
  if (!total) return '<div class="sev-bar"><span class="i" style="width:100%"></span></div>';
  var c = ((scan.critical_count || 0) / total * 100).toFixed(0);
  var h = ((scan.high_count || 0) / total * 100).toFixed(0);
  var m = ((scan.medium_count || 0) / total * 100).toFixed(0);
  var l = ((scan.low_count || 0) / total * 100).toFixed(0);
  var i = ((scan.info_count || 0) / total * 100).toFixed(0);
  return '<div class="sev-bar">' +
    '<span class="c" style="width:' + c + '%"></span>' +
    '<span class="h" style="width:' + h + '%"></span>' +
    '<span class="m" style="width:' + m + '%"></span>' +
    '<span class="l" style="width:' + l + '%"></span>' +
    '<span class="i" style="width:' + i + '%"></span>' +
    '</div>';
};

/* Global search handler */
WG.handleGlobalSearch = function(query) {
  var results = document.getElementById('searchResults');
  if (!query.trim()) { results.innerHTML = ''; return; }
  var q = query.toLowerCase();
  var esc = WG.escHtml;

  // Search the in-memory cache populated by recent page visits. Sections stay
  // empty if a category hasn't been loaded yet in this session.
  var _arr = function(k) { var v = WG._cache[k]; return Array.isArray(v) ? v : []; };
  var mf = _arr('findings').filter(function(f) {
    return (f.title || '').toLowerCase().includes(q) || (f.host_ip || '').includes(q) || (f.cve || '').toLowerCase().includes(q);
  }).slice(0, 5);
  var ms = _arr('scans').filter(function(s) {
    return (s.name || '').toLowerCase().includes(q) || (s.target || '').includes(q);
  }).slice(0, 3);

  var html = '';
  if (ms.length) {
    html += '<div style="padding:8px 0 4px;font-family:var(--font-mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);">Scans</div>';
    ms.forEach(function(s) {
      html += '<div class="activity-item" style="cursor:pointer;padding:8px 4px;border-radius:var(--radius-sm);" onclick="WG.closeModal(\'searchModal\');WG.navigate(\'scan\',{id:\'' + s.id + '\'})">' +
        '<div class="activity-icon scan"><svg viewBox="0 0 24 24"><use href="#i-scan"/></svg></div>' +
        '<div class="activity-text"><strong>' + esc(s.name) + '</strong><p>' + esc(s.target) + '</p></div>' +
        '<span class="status-badge ' + esc(s.status) + '" style="font-size:0.6rem;"><span class="dot"></span> ' + esc(s.status) + '</span></div>';
    });
  }
  if (mf.length) {
    html += '<div style="padding:8px 0 4px;font-family:var(--font-mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);">Findings</div>';
    mf.forEach(function(f) {
      html += '<div class="activity-item" style="cursor:pointer;padding:8px 4px;border-radius:var(--radius-sm);" onclick="WG.closeModal(\'searchModal\');WG.navigate(\'finding\',{id:\'' + f.id + '\'})">' +
        '<div class="activity-icon vuln"><svg viewBox="0 0 24 24"><use href="#i-alert"/></svg></div>' +
        '<div class="activity-text"><strong>' + esc(f.title) + '</strong><p>' + esc(f.host_ip) + ':' + esc(f.port) + '</p></div>' +
        '<span class="sev-badge ' + esc(f.severity) + '" style="font-size:0.6rem;">' + esc(f.severity) + '</span></div>';
    });
  }
  if (!ms.length && !mh.length && !mf.length) {
    html = '<div style="padding:20px;text-align:center;color:var(--text-dim);">No results</div>';
  }
  results.innerHTML = html;
};

/* Scan launch */
WG.launchScan = function() {
  var target = document.getElementById('scanTarget').value.trim();
  if (!target) { WG.toast('Target is required', 'error'); return; }

  var scanData = {
    target: target,
    name: document.getElementById('scanName').value.trim() || target,
    scan_type: document.getElementById('scanType').value,
    parallelism: parseInt(document.getElementById('scanParallelism').value),
    timeout: parseInt(document.getElementById('scanTimeout').value),
    report_formats: document.getElementById('scanReport').value,
    version_detect: document.querySelector('[data-opt="version_detect"]').classList.contains('on'),
    os_detect: document.querySelector('[data-opt="os_detect"]').classList.contains('on'),
    service_enum: document.querySelector('[data-opt="service_enum"]').classList.contains('on'),
    skip_nuclei: document.querySelector('[data-opt="skip_nuclei"]').classList.contains('on'),
  };

  WG.api('/scans/', { method: 'POST', body: JSON.stringify(scanData) }).then(function(res) {
    if (res && res.id) {
      WG.toast('Scan launched: ' + target, 'success');
      WG.invalidateCache('scans');
      WG.navigate('scan', { id: res.id });
    } else {
      WG.toast((res && res.error) || 'Scan launch failed', 'error');
    }
  });

  WG.closeModal('scanModal');
  document.getElementById('scanTarget').value = '';
  document.getElementById('scanName').value = '';
};

WG.launchDiscoveryScan = function() {
  var target = (document.getElementById('discTarget').value || '').trim();
  if (!target) { WG.toast('Target is required', 'error'); return; }

  var scanData = {
    target: target,
    name: (document.getElementById('discName').value || '').trim() || target,
    scan_type: 'discovery',
    parallelism: parseInt(document.getElementById('discParallelism').value) || 10,
    timeout: parseInt(document.getElementById('discTimeout').value) || 3600,
    scan_unresponsive: document.getElementById('discScanUnresponsive').classList.contains('on'),
    report_formats: 'dashboard',
  };

  WG.api('/scans/', { method: 'POST', body: JSON.stringify(scanData) }).then(function(res) {
    if (res && res.id) {
      WG.toast('Discovery scan launched: ' + target, 'success');
      WG.invalidateCache('scans');
      WG.navigate('live-discovery');
    } else {
      WG.toast((res && res.error) || 'Discovery scan launch failed', 'error');
    }
  });

  WG.closeModal('discoveryModal');
  document.getElementById('discTarget').value = '';
  document.getElementById('discName').value = '';
};

WG.cancelScan = function(id) {
  WG.api('/scans/' + id + '/cancel/', { method: 'POST' }).then(function(res) {
    if (!res) { WG.toast('Cancel failed', 'error'); return; }
    WG.toast('Scan cancelled', 'info');
    WG.invalidateCache('scans');
    WG.render();
  });
};

WG.downloadReport = function(id) {
  window.open(WG.API_BASE + '/reports/' + id + '/download/', '_blank');
};

WG.testApi = function() {
  WG.api('/dashboard/').then(function(res) {
    if (res) WG.toast('API connected', 'success');
    else WG.toast('API unreachable', 'error');
  });
};
