/* Wire_Ghost — Shared render components */

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
  var mh = _arr('hosts').filter(function(h) {
    return (h.ip || '').includes(q) || (h.hostname || '').toLowerCase().includes(q);
  }).slice(0, 5);
  var ms = _arr('scans').filter(function(s) {
    return (s.name || '').toLowerCase().includes(q) || (s.target || '').includes(q);
  }).slice(0, 3);

  var html = '';
  if (ms.length) {
    html += '<div style="padding:8px 0 4px;font-family:var(--font-mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);">Scans</div>';
    ms.forEach(function(s) {
      html += '<div class="activity-item" style="cursor:pointer;padding:8px 4px;border-radius:var(--radius-sm);" onclick="WG.closeModal(\'searchModal\');WG.navigate(\'scan\',{id:\'' + s.id + '\'})">' +
        '<div class="activity-icon scan">&#8862;</div>' +
        '<div class="activity-text"><strong>' + esc(s.name) + '</strong><p>' + esc(s.target) + '</p></div>' +
        '<span class="status-badge ' + s.status + '" style="font-size:0.6rem;"><span class="dot"></span> ' + s.status + '</span></div>';
    });
  }
  if (mh.length) {
    html += '<div style="padding:8px 0 4px;font-family:var(--font-mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);">Hosts</div>';
    mh.forEach(function(h) {
      html += '<div class="activity-item" style="cursor:pointer;padding:8px 4px;border-radius:var(--radius-sm);" onclick="WG.closeModal(\'searchModal\');WG.navigate(\'host\',{id:\'' + h.id + '\'})">' +
        '<div class="activity-icon host">&#9678;</div>' +
        '<div class="activity-text"><strong>' + esc(h.ip) + '</strong><p>' + esc(h.hostname || 'No hostname') + '</p></div></div>';
    });
  }
  if (mf.length) {
    html += '<div style="padding:8px 0 4px;font-family:var(--font-mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);">Findings</div>';
    mf.forEach(function(f) {
      html += '<div class="activity-item" style="cursor:pointer;padding:8px 4px;border-radius:var(--radius-sm);" onclick="WG.closeModal(\'searchModal\');WG.navigate(\'finding\',{id:\'' + f.id + '\'})">' +
        '<div class="activity-icon vuln">&#9888;</div>' +
        '<div class="activity-text"><strong>' + esc(f.title) + '</strong><p>' + esc(f.host_ip) + ':' + f.port + '</p></div>' +
        '<span class="sev-badge ' + f.severity + '" style="font-size:0.6rem;">' + f.severity + '</span></div>';
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
