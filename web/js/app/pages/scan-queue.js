/* Wire_Ghost — Scan Queue page */

WG.renderScanQueue = function() {
  var scans = WG.getCached('scans', '/scans/');
  var esc = WG.escHtml;

  var running = scans.filter(function(s) { return s.status === 'running'; });
  var pending = scans.filter(function(s) { return s.status === 'pending'; });
  var queue = pending.concat(running);

  // Background refresh
  WG.refreshAndRerender('scans', '/scans/', WG.renderScanQueue, 'scan-queue');
  // Start/stop live polling for running scan cards
  if (running.length) WG._startQueuePolling(); else WG._stopQueuePolling();

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Scan Queue</h1><p>' + queue.length + ' active &mdash; ' + running.length + ' running, ' + pending.length + ' pending</p></div>' +
    '<div class="page-header-actions">' +
      '<button class="btn btn-secondary btn-sm" onclick="WG.invalidateCache(\'scans\');WG.render()">&#8635; Refresh</button>' +
      (running.length ? '<button class="btn btn-danger btn-sm" onclick="WG._cancelAllRunning()">Cancel All</button>' : '') +
      '<button class="btn btn-primary" onclick="WG.navigate(\'new-scan\')"><span>+</span> New Scan</button>' +
    '</div></div>' +

    (queue.length === 0 ?
      '<div class="empty-state"><div class="icon">&#9776;</div><h3>Queue is empty</h3><p>No scans are running or pending.</p>' +
      '<button class="btn btn-primary" style="margin-top:16px;" onclick="WG.navigate(\'new-scan\')">Launch a Scan</button></div>'
    :
      '<div style="display:flex;flex-direction:column;gap:14px;">' +
        queue.map(function(s, i) {
          var isRunning = s.status === 'running';
          var phase = s.current_phase || 'discovery';
          var progress = isRunning ? WG.phaseProgress(s) : 0;
          var activeIdx = isRunning ? WG.PHASE_ORDER.indexOf(phase) : -1;
          if (activeIdx < 0) activeIdx = 0;

          return '<div class="panel">' +
            '<div class="panel-body">' +
              '<div style="display:flex;align-items:center;gap:16px;">' +
                /* Queue position */
                '<div style="width:36px;height:36px;border-radius:50%;background:var(--bg-card);border:1px solid var(--border-soft);display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-weight:700;font-size:0.85rem;color:var(--text-dim);flex-shrink:0;">' + (i + 1) + '</div>' +

                /* Scan info */
                '<div style="flex:1;min-width:0;">' +
                  '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">' +
                    '<span style="font-weight:700;color:var(--text-bright);">' + esc(s.name) + '</span>' +
                    '<span class="status-badge ' + s.status + '" style="font-size:0.6rem;"><span class="dot"></span> ' + s.status + '</span>' +
                  '</div>' +
                  '<div style="display:flex;align-items:center;gap:12px;">' +
                    '<span class="host-tag" style="font-size:0.75rem;">' + esc(s.target) + '</span>' +
                    '<span class="tag" style="font-size:0.6rem;">' + s.scan_type + '</span>' +
                    '<span class="mono" style="font-size:0.68rem;color:var(--text-dim);">Threads: ' + (s.parallelism || 10) + '</span>' +
                  '</div>' +

                  (isRunning ? '' +
                    '<div style="margin-top:10px;">' +
                      '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">' +
                        '<span class="elapsed-live mono" style="font-size:0.68rem;color:var(--text-dim);" data-started-at="' + (s.started_at || '') + '">' + WG.fmtDuration(s.elapsed_seconds || 0) + '</span>' +
                        '<span class="live-scan-pct mono" data-sid="' + s.id + '" style="font-size:0.68rem;color:var(--accent);">' + progress + '%</span>' +
                      '</div>' +
                      '<div class="progress-bar" style="margin-bottom:8px;"><div class="progress-fill live-scan-fill" data-sid="' + s.id + '" style="width:' + progress + '%;"></div></div>' +
                      '<div style="display:flex;gap:3px;">' +
                        WG.PHASE_ORDER.map(function(ph, pi) {
                          var done = pi < activeIdx;
                          var active = pi === activeIdx;
                          return '<div style="flex:1;text-align:center;padding:3px 0;border-radius:var(--radius-xs);font-size:0.58rem;font-family:var(--font-mono);' +
                            (done ? 'background:var(--success-dim);color:var(--success);' : active ? 'background:var(--accent-dim);color:var(--accent);' : 'background:var(--bg-card);color:var(--text-muted);') +
                          '">' + (done ? '&#10003; ' : '') + WG.PHASE_LABELS[ph] + '</div>';
                        }).join('') +
                      '</div>' +
                      '<div style="display:flex;gap:16px;margin-top:8px;font-family:var(--font-mono);font-size:0.65rem;color:var(--text-dim);">' +
                        '<span class="live-scan-count" data-sid="' + s.id + '" data-field="phase">Phase: ' + WG.phaseLabel(phase) + '</span>' +
                        '<span class="live-scan-count" data-sid="' + s.id + '" data-field="hosts_count">Hosts: ' + s.hosts_count + '</span>' +
                        '<span class="live-scan-count" data-sid="' + s.id + '" data-field="ports_count">Ports: ' + (s.ports_count || 0) + '</span>' +
                        '<span class="live-scan-count" data-sid="' + s.id + '" data-field="findings_count">Findings: ' + s.findings_count + '</span>' +
                        '<span class="live-scan-count" data-sid="' + s.id + '" data-field="critical_count" style="' + (s.critical_count ? 'color:var(--critical);' : '') + '">Critical: ' + (s.critical_count || 0) + '</span>' +
                      '</div>' +
                    '</div>'
                  : '<div style="margin-top:8px;font-size:0.78rem;color:var(--text-dim);">Waiting in queue...</div>') +
                '</div>' +

                /* Actions */
                '<div style="display:flex;flex-direction:column;gap:6px;flex-shrink:0;">' +
                  '<button class="btn btn-ghost btn-sm" onclick="WG.navigate(\'scan\',{id:\'' + s.id + '\'})">View</button>' +
                  (isRunning ? '<button class="btn btn-danger btn-sm" onclick="WG.cancelScan(\'' + s.id + '\')">Cancel</button>' : '') +
                  (s.status === 'pending' ? '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG._removeFromQueue(\'' + s.id + '\')">Remove</button>' : '') +
                '</div>' +
              '</div>' +
            '</div></div>';
        }).join('') +
      '</div>'
    );
};

WG._cancelAllRunning = function() {
  var scans = WG.getCached('scans', '/scans/');
  scans.forEach(function(s) {
    if (s.status === 'running') {
      WG.api('/scans/' + s.id + '/cancel/', { method: 'POST' });
      s.status = 'cancelled';
    }
  });
  WG.toast('All running scans cancelled', 'info');
  WG.invalidateCache('scans');
  WG.render();
};

WG._removeFromQueue = function(id) {
  WG.api('/scans/' + id + '/', { method: 'DELETE' });
  WG.invalidateCache('scans');
  WG.toast('Removed from queue', 'info');
  WG.render();
};

/* Live polling for scan queue page — same pattern as scans.js: update
   running scan card counts, progress, and phase label in-place every 3s. */
WG._startQueuePolling = function() {
  WG._stopQueuePolling();
  WG._queuePollTimer = setInterval(function() {
    if (WG.state.currentPage !== 'scan-queue') { WG._stopQueuePolling(); return; }
    WG.fetchData('/scans/').then(function(data) {
      if (!Array.isArray(data)) return;
      WG._cache['scans'] = data;
      WG._cacheTime['scans'] = Date.now();
      var hasRunning = false;
      data.forEach(function(s) {
        if (s.status !== 'running') return;
        hasRunning = true;
        var phase = s.current_phase || 'discovery';
        var progress = WG.phaseProgress(s);
        document.querySelectorAll('.live-scan-count[data-sid="' + s.id + '"]').forEach(function(el) {
          var f = el.dataset.field;
          var labels = {phase:'Phase: ',hosts_count:'Hosts: ',ports_count:'Ports: ',findings_count:'Findings: ',critical_count:'Critical: '};
          if (f === 'phase') el.textContent = labels[f] + WG.phaseLabel(phase);
          else {
            el.textContent = labels[f] + (s[f] || 0);
            if (f === 'critical_count') el.style.color = (s[f] || 0) > 0 ? 'var(--critical)' : '';
          }
        });
        var pct = document.querySelector('.live-scan-pct[data-sid="' + s.id + '"]');
        if (pct) pct.textContent = progress + '%';
        var fill = document.querySelector('.live-scan-fill[data-sid="' + s.id + '"]');
        if (fill) fill.style.width = progress + '%';
      });
      if (!hasRunning) WG._stopQueuePolling();
    });
  }, 3000);
};

WG._stopQueuePolling = function() {
  if (WG._queuePollTimer) { clearInterval(WG._queuePollTimer); WG._queuePollTimer = null; }
};
