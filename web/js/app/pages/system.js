/* Wire_Ghost — System Monitor page (Tier-1).
 *
 * Task-Manager-style live view of CPU / memory / disk / network usage for
 * the api container (cgroup-scoped — no /proc or /sys host mounts in
 * docker-compose.yml, so numbers reflect what this container sees, which
 * is what operators care about for capacity planning).
 *
 * Polls /api/system-stats/ every WG._sysTickMs ms, appends each sample to
 * a ring buffer (60 samples = ~90 s at 1500 ms), and redraws the Chart.js
 * sparkline with `animation: false` for smooth scrolling. The tick function
 * self-heals on navigate-away: if WG.state.currentPage !== 'system' it
 * clears its own interval, so we never leak a timer.
 *
 * No user-controlled data is rendered (only numbers and static labels),
 * so no escHtml() wrapping is needed — still follows the codebase rule of
 * never assigning to `innerHTML`; we use DOM APIs and textContent. */

WG._sysTickMs = 1500;
WG._sysBufSize = 60;

/* Ring buffers. Kept on WG so they survive re-mounts (nice if the user
 * tabs away for a moment and comes back — but reset to empty at page
 * render time so each visit starts with a clean window). */
WG._sysBuf = { cpu: [], mem: [], disk: [], netUp: [], netDown: [] };
WG._sysPrevNet = null;  /* last (ts, sent, recv) for rate delta */
WG._sysCharts = {};
WG._sysTimer = null;

WG._procTimer = null;
WG._procTickMs = 3000;
WG._procPrevNet = {};

WG._sysFmtBytes = function(n) {
  if (n == null || isNaN(n)) return '—';
  var u = ['B', 'KB', 'MB', 'GB', 'TB'];
  var i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
};

WG._sysFmtRate = function(bps) {
  if (bps == null || isNaN(bps) || bps < 0) return '0 B/s';
  return WG._sysFmtBytes(bps) + '/s';
};

WG._sysFmtUptime = function(s) {
  if (!s || s < 0) return '—';
  var d = Math.floor(s / 86400);
  var h = Math.floor((s % 86400) / 3600);
  var m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm ' + (s % 60) + 's';
};

WG.renderSystem = function() {
  /* Reset ring buffers every time the page mounts so sparklines start
   * fresh. Keeping old data across visits produces weird gaps. */
  WG._sysBuf = { cpu: [], mem: [], disk: [], netUp: [], netDown: [] };
  WG._sysPrevNet = null;

  /* Kick off the polling loop — setTimeout(0) so the HTML is in the DOM
   * before we reach for canvas elements. */
  setTimeout(function() {
    if (WG._sysTimer) { clearInterval(WG._sysTimer); WG._sysTimer = null; }
    if (WG._procTimer) { clearInterval(WG._procTimer); WG._procTimer = null; }
    WG._procPrevNet = {};
    WG._sysInitCharts();
    WG._sysTick();
    WG._sysTimer = setInterval(WG._sysTick, WG._sysTickMs);
    WG._procTick();
    WG._procTimer = setInterval(WG._procTick, WG._procTickMs);
  }, 0);

  return '' +
    '<div class="page-header">' +
      '<div class="page-header-left">' +
        '<h1>System Monitor</h1>' +
        '<p>Container resource usage — live, updates every ' + (WG._sysTickMs / 1000) + 's</p>' +
      '</div>' +
      '<div class="page-header-actions">' +
        '<div class="mono" style="font-size:0.82rem;color:var(--text-bright);letter-spacing:0.5px;" id="sysClock">—</div>' +
        '<div class="mono" style="font-size:0.72rem;color:var(--text-dim);margin-top:2px;">' +
          'Uptime: <span id="sysUptime">—</span> · CPUs: <span id="sysCpuCount">—</span>' +
        '</div>' +
      '</div>' +
    '</div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);gap:16px;">' +
      WG._sysCard('cpu',  'CPU Usage',    'var(--accent)') +
      WG._sysCard('mem',  'Memory Usage', 'var(--high)') +
      WG._sysCard('disk', 'Disk Usage',   'var(--medium)') +
      WG._sysCard('net',  'Network',      'var(--low)') +
    '</div>' +

    '<div class="panel" style="margin-top:20px;padding:16px;">' +
      '<div style="font-size:0.78rem;color:var(--text-dim);line-height:1.6;">' +
        '<strong style="color:var(--text-bright);">Note:</strong> Values reflect the <em>api container\'s</em> cgroup ' +
        'limits, not the host machine. Disk is measured at the container root filesystem. ' +
        'Network counters are cumulative; the rate shown is derived per sample.' +
      '</div>' +
    '</div>' +

    '<div class="panel" style="margin-top:20px;">' +
      '<div class="panel-header" style="padding:16px 16px 12px;">' +
        '<h3 style="font-size:0.95rem;font-weight:700;color:var(--text-bright);margin:0;">Container Processes</h3>' +
        '<span class="mono" style="font-size:0.72rem;color:var(--text-dim);">Updates every ' + (WG._procTickMs / 1000) + 's</span>' +
      '</div>' +
      '<div id="procTableWrap" style="overflow-x:auto;">' +
        '<table class="data-table" style="min-width:700px;">' +
          '<thead><tr>' +
            '<th>Container</th><th>State</th><th>CPU %</th>' +
            '<th>Memory</th><th>Net I/O</th><th>PIDs</th>' +
          '</tr></thead>' +
          '<tbody id="procTableBody">' +
            '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:24px;">Loading...</td></tr>' +
          '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
};

WG._sysCard = function(key, label, color) {
  return '' +
    '<div class="stat-card" style="padding:16px;">' +
      '<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;">' +
        '<div class="stat-label">' + label + '</div>' +
        '<div class="mono" id="sys' + key + 'Detail" style="font-size:0.7rem;color:var(--text-dim);">—</div>' +
      '</div>' +
      '<div class="stat-value" id="sys' + key + 'Value" style="color:' + color + ';">—</div>' +
      '<div style="height:48px;margin-top:8px;">' +
        '<canvas id="sys' + key + 'Chart"></canvas>' +
      '</div>' +
    '</div>';
};

WG._sysInitCharts = function() {
  if (typeof Chart === 'undefined') return;
  /* Destroy any leftover charts from a prior mount. */
  Object.keys(WG._sysCharts).forEach(function(k) {
    try { WG._sysCharts[k].destroy(); } catch (e) {}
  });
  WG._sysCharts = {};

  var labels = new Array(WG._sysBufSize).fill('');
  var mk = function(canvasId, color, dataKeys) {
    var el = document.getElementById(canvasId);
    if (!el) return null;
    var datasets = dataKeys.map(function(k, i) {
      return {
        data: new Array(WG._sysBufSize).fill(null),
        borderColor: Array.isArray(color) ? color[i] : color,
        backgroundColor: 'transparent',
        borderWidth: 1.5,
        tension: 0.25,
        pointRadius: 0,
        fill: false,
      };
    });
    return new Chart(el, {
      type: 'line',
      data: { labels: labels, datasets: datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: {
          x: { display: false },
          y: { display: false, beginAtZero: true, suggestedMax: 100 },
        },
        elements: { line: { borderJoinStyle: 'round' } },
      },
    });
  };

  var cssAccent  = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()  || '#00d4aa';
  var cssHigh    = getComputedStyle(document.documentElement).getPropertyValue('--high').trim()    || '#f97316';
  var cssMedium  = getComputedStyle(document.documentElement).getPropertyValue('--medium').trim()  || '#eab308';
  var cssLow     = getComputedStyle(document.documentElement).getPropertyValue('--low').trim()     || '#3b82f6';
  var cssLowDim  = getComputedStyle(document.documentElement).getPropertyValue('--text-dim').trim()|| '#94a3b8';

  WG._sysCharts.cpu  = mk('syscpuChart',  cssAccent, ['cpu']);
  WG._sysCharts.mem  = mk('sysmemChart',  cssHigh,   ['mem']);
  WG._sysCharts.disk = mk('sysdiskChart', cssMedium, ['disk']);
  WG._sysCharts.net  = mk('sysnetChart',  [cssLow, cssLowDim], ['up', 'down']);
  /* Net chart doesn't clamp to 100 like the percent charts. */
  if (WG._sysCharts.net) {
    WG._sysCharts.net.options.scales.y.suggestedMax = undefined;
    WG._sysCharts.net.options.scales.y.grace = '10%';
  }
};

WG._sysTick = function() {
  /* Self-clean: user navigated away → tear down timer + charts. */
  if (WG.state.currentPage !== 'system') {
    if (WG._sysTimer) { clearInterval(WG._sysTimer); WG._sysTimer = null; }
    if (WG._procTimer) { clearInterval(WG._procTimer); WG._procTimer = null; }
    Object.keys(WG._sysCharts).forEach(function(k) {
      try { WG._sysCharts[k].destroy(); } catch (e) {}
    });
    WG._sysCharts = {};
    return;
  }

  WG.api('/system-stats/').then(function(data) {
    if (!data) return;
    /* Check again — the fetch may land after nav-away. */
    if (WG.state.currentPage !== 'system') return;

    var cpu  = data.cpu  || {};
    var mem  = data.memory || {};
    var disk = data.disk || {};
    var net  = data.net  || {};

    /* Headline numbers */
    var set = function(id, text) {
      var el = document.getElementById(id);
      if (el) el.textContent = text;
    };
    set('syscpuValue',  (cpu.percent != null ? cpu.percent.toFixed(0) : '—') + '%');
    set('sysmemValue',  (mem.percent != null ? mem.percent.toFixed(0) : '—') + '%');
    set('sysdiskValue', (disk.percent != null ? disk.percent.toFixed(0) : '—') + '%');
    set('syscpuDetail',  (cpu.count || 0) + ' cores');
    set('sysmemDetail',  WG._sysFmtBytes(mem.used) + ' / ' + WG._sysFmtBytes(mem.total));
    set('sysdiskDetail', WG._sysFmtBytes(disk.used) + ' / ' + WG._sysFmtBytes(disk.total));
    set('sysUptime',     WG._sysFmtUptime(data.uptime));
    set('sysCpuCount',   (cpu.count || '—'));
    if (data.ts) {
      var dt = new Date(data.ts);
      set('sysClock', dt.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:true}) +
        '  ' + dt.toLocaleDateString([], {weekday:'short',month:'short',day:'numeric'}));
    }

    /* Net rate — bytes/sec = (current - prev) / elapsed seconds. */
    var up = 0, down = 0;
    if (WG._sysPrevNet && data.ts > WG._sysPrevNet.ts) {
      var dt = (data.ts - WG._sysPrevNet.ts) / 1000;
      if (dt > 0) {
        up   = Math.max(0, (net.bytes_sent - WG._sysPrevNet.sent) / dt);
        down = Math.max(0, (net.bytes_recv - WG._sysPrevNet.recv) / dt);
      }
    }
    WG._sysPrevNet = { ts: data.ts, sent: net.bytes_sent || 0, recv: net.bytes_recv || 0 };
    set('sysnetValue',  WG._sysFmtRate(up + down));
    set('sysnetDetail', '↑ ' + WG._sysFmtRate(up) + '  ↓ ' + WG._sysFmtRate(down));

    /* Ring-buffer push + Chart.js update('none') — no animation so the
     * scroll is smooth. */
    var push = function(buf, v) {
      buf.push(v);
      if (buf.length > WG._sysBufSize) buf.shift();
      return buf;
    };
    push(WG._sysBuf.cpu,  cpu.percent  || 0);
    push(WG._sysBuf.mem,  mem.percent  || 0);
    push(WG._sysBuf.disk, disk.percent || 0);
    push(WG._sysBuf.netUp,   up);
    push(WG._sysBuf.netDown, down);

    var copy = function(arr, size) {
      /* Pad the front with nulls so the line anchors on the right edge. */
      var pad = Math.max(0, size - arr.length);
      return new Array(pad).fill(null).concat(arr.slice());
    };
    if (WG._sysCharts.cpu)  { WG._sysCharts.cpu.data.datasets[0].data  = copy(WG._sysBuf.cpu,  WG._sysBufSize);  WG._sysCharts.cpu.update('none'); }
    if (WG._sysCharts.mem)  { WG._sysCharts.mem.data.datasets[0].data  = copy(WG._sysBuf.mem,  WG._sysBufSize);  WG._sysCharts.mem.update('none'); }
    if (WG._sysCharts.disk) { WG._sysCharts.disk.data.datasets[0].data = copy(WG._sysBuf.disk, WG._sysBufSize);  WG._sysCharts.disk.update('none'); }
    if (WG._sysCharts.net)  {
      WG._sysCharts.net.data.datasets[0].data = copy(WG._sysBuf.netUp,   WG._sysBufSize);
      WG._sysCharts.net.data.datasets[1].data = copy(WG._sysBuf.netDown, WG._sysBufSize);
      WG._sysCharts.net.update('none');
    }
  });
};

WG._procClear = function(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
};

WG._procTick = function() {
  if (WG.state.currentPage !== 'system') {
    if (WG._procTimer) { clearInterval(WG._procTimer); WG._procTimer = null; }
    return;
  }

  WG.api('/system-processes/').then(function(data) {
    if (!data) return;
    if (WG.state.currentPage !== 'system') return;

    var tbody = document.getElementById('procTableBody');
    if (!tbody) return;

    if (!data.available) {
      WG._procClear(tbody);
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.setAttribute('colspan', '6');
      td.style.cssText = 'text-align:center;color:var(--text-dim);padding:24px;';
      td.textContent = 'Docker proxy unavailable' + (data.error ? ' — ' + data.error : '');
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    var containers = data.containers || [];
    if (containers.length === 0) {
      WG._procClear(tbody);
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.setAttribute('colspan', '6');
      td.style.cssText = 'text-align:center;color:var(--text-dim);padding:24px;';
      td.textContent = 'No containers found';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    var ts = data.ts || Date.now();
    var frag = document.createDocumentFragment();

    containers.forEach(function(c) {
      var tr = document.createElement('tr');

      var tdName = document.createElement('td');
      var nameSpan = document.createElement('span');
      nameSpan.style.fontWeight = '600';
      nameSpan.style.color = 'var(--text-bright)';
      nameSpan.textContent = c.name;
      tdName.appendChild(nameSpan);
      var imgSpan = document.createElement('div');
      imgSpan.className = 'mono';
      imgSpan.style.cssText = 'font-size:0.7rem;color:var(--text-dim);margin-top:2px;';
      imgSpan.textContent = c.image;
      tdName.appendChild(imgSpan);
      tr.appendChild(tdName);

      var tdState = document.createElement('td');
      var badge = document.createElement('span');
      badge.className = 'status-badge ' + (c.state === 'running' ? 'running' : 'failed');
      badge.textContent = c.state;
      tdState.appendChild(badge);
      tr.appendChild(tdState);

      var tdCpu = document.createElement('td');
      tdCpu.className = 'mono';
      tdCpu.textContent = c.cpu_percent.toFixed(1) + '%';
      tr.appendChild(tdCpu);

      var tdMem = document.createElement('td');
      tdMem.className = 'mono';
      var mem = c.memory || {};
      tdMem.textContent = WG._sysFmtBytes(mem.used) + ' / ' + WG._sysFmtBytes(mem.limit);
      var memPct = document.createElement('div');
      memPct.style.cssText = 'font-size:0.7rem;color:var(--text-dim);';
      memPct.textContent = (mem.percent || 0).toFixed(1) + '%';
      tdMem.appendChild(memPct);
      tr.appendChild(tdMem);

      var tdNet = document.createElement('td');
      tdNet.className = 'mono';
      var net = c.network || {};
      var prev = WG._procPrevNet[c.id];
      var rxRate = 0, txRate = 0;
      if (prev && ts > prev.ts) {
        var dt = (ts - prev.ts) / 1000;
        if (dt > 0) {
          rxRate = Math.max(0, (net.rx_bytes - prev.rx) / dt);
          txRate = Math.max(0, (net.tx_bytes - prev.tx) / dt);
        }
      }
      WG._procPrevNet[c.id] = { ts: ts, rx: net.rx_bytes, tx: net.tx_bytes };
      tdNet.textContent = '↑ ' + WG._sysFmtRate(txRate) + '  ↓ ' + WG._sysFmtRate(rxRate);
      tr.appendChild(tdNet);

      var tdPids = document.createElement('td');
      tdPids.className = 'mono';
      tdPids.textContent = c.pids || '—';
      tr.appendChild(tdPids);

      frag.appendChild(tr);
    });

    WG._procClear(tbody);
    tbody.appendChild(frag);
  });
};
