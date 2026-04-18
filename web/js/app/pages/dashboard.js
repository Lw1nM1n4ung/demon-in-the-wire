/* Wire_Ghost — Attack Surface Management dashboard.
 *
 * Strategic view over every scan ever run: KPIs, severity trend, newly-
 * discovered assets, top exposures, top technologies, and a filterable
 * asset inventory. Backed by GET /api/dashboard/ and GET /api/assets/.
 * Chart instances are kept on WG._charts so they can be destroyed on nav. */

WG._charts = WG._charts || {};
WG._asmAssetsCache = null;
WG._asmAssetsParams = { search: '', status: '', min_risk: '', has_cve: '' };

/* Helper — safe HTML assignment. All inputs are already escaped via WG.escHtml. */
WG._setHtml = function(el, html) {
  if (!el) return;
  el.textContent = '';
  el.insertAdjacentHTML('beforeend', html);
};

/* ── Color helpers — resolve CSS tokens at runtime so charts inherit theme ── */
WG._cssVar = function(name) {
  var v = getComputedStyle(document.documentElement).getPropertyValue(name);
  return (v || '').trim() || '#888';
};

WG._sevColors = function() {
  return {
    critical: WG._cssVar('--critical'),
    high:     WG._cssVar('--high'),
    medium:   WG._cssVar('--medium'),
    low:      WG._cssVar('--low'),
    info:     WG._cssVar('--info'),
  };
};

/* ── Entry point — router calls this to render the page ──────────────── */
WG._dashboardCanViewAssets = function() {
  var u = WG.currentUser && WG.currentUser();
  var role = (u && u.role) || '';
  return role === 'owner' || role === 'engineer';
};

WG.renderDashboard = function() {
  WG._loadAsm();
  // Viewers lack host:read permission — skip the /api/assets/ call to avoid
  // a cosmetic 403 in the console on every dashboard visit.
  if (WG._dashboardCanViewAssets()) WG._loadAssetInventory();
  // After the router injects the HTML, initialize charts and filter bindings.
  // This covers cached revisits; fresh-data renders run the same code from
  // the async callback in _loadAsm (idempotent — _destroyCharts clears first).
  setTimeout(function() {
    if (WG.state.currentPage !== 'dashboard') return;
    WG._initAsmCharts();
    WG._bindAssetFilters();
    WG._renderAssetInventory();
  }, 0);
  return WG._buildAsm();
};

WG._updateSidebarBadges = function(data) {
  // Hide badges when empty, show value when non-zero.
  var kpis = (data && data.kpis) || {};
  var scans = kpis.new_assets_7d || 0;
  var findings = kpis.critical_exposures || 0;
  var sb = document.getElementById('sidebarScansBadge');
  var fb = document.getElementById('sidebarFindingsBadge');
  if (sb) { sb.textContent = scans > 0 ? String(scans) : ''; sb.style.display = scans > 0 ? '' : 'none'; }
  if (fb) { fb.textContent = findings > 0 ? String(findings) : ''; fb.style.display = findings > 0 ? '' : 'none'; }
};

WG._loadAsm = function() {
  WG.api('/dashboard/').then(function(data) {
    if (!data) return;
    WG._cache['asm'] = data;
    WG._cacheTime['asm'] = Date.now();
    WG._updateSidebarBadges(data);
    if (WG.state.currentPage !== 'dashboard') return;
    var main = document.getElementById('mainContent');
    if (main) {
      WG._setHtml(main, WG._buildAsm());
      WG._initAsmCharts();
      WG._bindAssetFilters();
      WG._renderAssetInventory();
    }
  });
};

WG._loadAssetInventory = function() {
  var q = new URLSearchParams();
  ['search', 'status', 'min_risk', 'has_cve'].forEach(function(k) {
    if (WG._asmAssetsParams[k]) q.set(k, WG._asmAssetsParams[k]);
  });
  var qs = q.toString();
  WG.api('/assets/' + (qs ? '?' + qs : '')).then(function(data) {
    WG._asmAssetsCache = data ? (data.results || data) : [];
    if (WG.state.currentPage === 'dashboard') WG._renderAssetInventory();
  });
};

/* ── Build the page markup (pure HTML; charts init after assignment) ── */
WG._buildAsm = function() {
  var data = WG._cache['asm'] || {};
  var kpis = data.kpis || {};
  var loaded = WG._cache['asm'] != null;
  var scoreColor = WG._scoreColor(kpis.attack_surface_score);

  return '' +
    '<div class="page-header">' +
      '<div class="page-header-left">' +
        '<h1>Attack Surface</h1>' +
        '<p>Continuous inventory of every asset seen across all scans</p>' +
      '</div>' +
      '<div class="page-header-actions">' +
        '<button class="btn btn-secondary btn-sm" onclick="WG.invalidateCache();WG.render()">&#8635; Refresh</button>' +
        (WG._dashboardCanViewAssets() ? '<button class="btn btn-primary" onclick="WG.openModal(\'scanModal\')"><span>+</span> New Scan</button>' : '') +
      '</div>' +
    '</div>' +

    /* ══ KPI band ══ */
    '<div class="asm-kpis">' +
      WG._kpiTile('Total Assets',        kpis.total_assets,        '--info',     'open ports observed', 'anim-reveal-1') +
      WG._kpiTile('Critical Exposures',  kpis.critical_exposures,  '--critical', 'open critical findings', 'anim-reveal-2') +
      WG._kpiTile('New (7d)',            kpis.new_assets_7d,       '--high',     'first seen in last 7 days', 'anim-reveal-3') +
      WG._kpiTile('With CVEs',           kpis.assets_with_cves,    '--medium',   'assets linked to known issues', 'anim-reveal-4') +
      WG._kpiScoreTile(kpis.attack_surface_score, scoreColor) +
    '</div>' +

    /* ══ Row 2 — severity trend + newly discovered ══ */
    '<div class="asm-row-2">' +
      '<div class="panel anim-reveal" style="animation-delay:0.30s;">' +
        '<div class="panel-header">' +
          '<div class="panel-title">Severity Trend <span class="count">30d</span></div>' +
          '<div style="display:flex;gap:10px;font-size:0.68rem;color:var(--text-dim);">' +
            '<span><span class="dot" style="background:var(--critical);"></span> Critical</span>' +
            '<span><span class="dot" style="background:var(--high);"></span> High</span>' +
            '<span><span class="dot" style="background:var(--medium);"></span> Medium</span>' +
            '<span><span class="dot" style="background:var(--low);"></span> Low</span>' +
            '<span><span class="dot" style="background:var(--info);"></span> Info</span>' +
          '</div>' +
        '</div>' +
        '<div class="panel-body" style="padding:14px 10px 18px;">' +
          '<div style="position:relative;height:220px;"><canvas id="chartSeverityTrend"></canvas></div>' +
        '</div>' +
      '</div>' +

      '<div class="panel anim-reveal" style="animation-delay:0.35s;">' +
        '<div class="panel-header">' +
          '<div class="panel-title">Newly Discovered <span class="count">' + (data.newly_discovered || []).length + '</span></div>' +
          '<span style="font-size:0.68rem;color:var(--text-dim);">last 7 days</span>' +
        '</div>' +
        '<div class="panel-body asm-discovery-list" style="padding:6px 0;">' +
          WG._newlyDiscoveredHtml(data.newly_discovered || [], loaded) +
        '</div>' +
      '</div>' +
    '</div>' +

    /* ══ Row 3 — risk source donut + top exposures ══ */
    '<div class="asm-row-3">' +
      '<div class="panel anim-reveal" style="animation-delay:0.40s;">' +
        '<div class="panel-header"><div class="panel-title">Risk by Source</div></div>' +
        '<div class="panel-body" style="padding:14px 10px 18px;">' +
          '<div class="asm-donut-wrap"><canvas id="chartRiskBySource"></canvas>' +
            '<div class="asm-donut-center">' +
              '<div class="asm-donut-total" id="asmDonutTotal">0</div>' +
              '<div class="asm-donut-label">findings</div>' +
            '</div>' +
          '</div>' +
          '<div class="asm-donut-legend" id="asmDonutLegend"></div>' +
        '</div>' +
      '</div>' +

      '<div class="panel anim-reveal" style="animation-delay:0.45s;">' +
        '<div class="panel-header">' +
          '<div class="panel-title">Top Exposures</div>' +
          '<button class="btn btn-ghost btn-sm" onclick="WG.navigate(\'findings\')">View all</button>' +
        '</div>' +
        WG._topExposuresHtml(data.top_exposures || [], loaded) +
      '</div>' +
    '</div>' +

    /* ══ Row 4 — technology bars ══ */
    '<div class="panel anim-reveal" style="animation-delay:0.50s;margin-bottom:18px;">' +
      '<div class="panel-header"><div class="panel-title">Top Technologies</div></div>' +
      '<div class="panel-body">' + WG._topTechHtml(data.top_technologies || [], loaded) + '</div>' +
    '</div>' +

    /* ══ Asset inventory table — hidden for Viewers who lack host:read ══ */
    (WG._dashboardCanViewAssets() ?
    '<div class="panel anim-reveal" style="animation-delay:0.55s;">' +
      '<div class="panel-header">' +
        '<div class="panel-title">Asset Inventory</div>' +
        '<button class="btn btn-ghost btn-sm" onclick="WG.navigate(\'hosts\')">Hosts view</button>' +
      '</div>' +
      '<div class="filters-bar" style="padding:10px 16px;border-bottom:1px solid var(--border-dim);">' +
        '<input class="form-input" id="asmSearch" placeholder="Search ip / hostname / service" style="flex:2;">' +
        '<select class="form-select" id="asmStatus" style="flex:1;">' +
          '<option value="">All statuses</option>' +
          '<option value="open">Open</option>' +
          '<option value="closed">Closed</option>' +
          '<option value="filtered">Filtered</option>' +
          '<option value="inactive">Inactive</option>' +
        '</select>' +
        '<select class="form-select" id="asmMinRisk" style="flex:1;">' +
          '<option value="">Any risk</option>' +
          '<option value="80">\u2265 80 (Critical)</option>' +
          '<option value="50">\u2265 50 (High)</option>' +
          '<option value="20">\u2265 20 (Medium)</option>' +
        '</select>' +
        '<select class="form-select" id="asmHasCve" style="flex:1;">' +
          '<option value="">With or without CVEs</option>' +
          '<option value="1">Only with findings</option>' +
        '</select>' +
      '</div>' +
      '<div id="asmAssetTableWrap">' + WG._assetInventoryHtml() + '</div>' +
    '</div>' : '');
};

/* ── KPI tiles ───────────────────────────────────────────────────────── */
WG._kpiTile = function(label, value, colorVar, caption, animClass) {
  var display = (value === undefined || value === null) ? '\u2014' : WG._kNumber(value);
  return '<div class="asm-kpi anim-reveal ' + animClass + '" style="--kpi-accent:var(' + colorVar + ');">' +
    '<div class="asm-kpi-label">' + WG.escHtml(label) + '</div>' +
    '<div class="asm-kpi-value">' + display + '</div>' +
    '<div class="asm-kpi-caption">' + WG.escHtml(caption) + '</div>' +
  '</div>';
};

WG._kpiScoreTile = function(score, color) {
  var isEmpty = (score === undefined || score === null);
  var displayScore = isEmpty ? 0 : score;
  var angle = Math.max(0, Math.min(100, displayScore)) * 3.6;
  var grade = isEmpty
    ? 'N/A'
    : displayScore >= 80 ? 'Strong'
    : displayScore >= 60 ? 'Moderate'
    : displayScore >= 40 ? 'Weak'
    : 'Critical';
  var inner = isEmpty ? '<span>\u2014</span>' : '<span>' + displayScore + '</span><small>/100</small>';
  return '<div class="asm-kpi asm-kpi-score anim-reveal anim-reveal-5" style="--kpi-accent:' + color + ';">' +
    '<div class="asm-kpi-label">Attack Surface Score</div>' +
    '<div class="asm-kpi-score-wrap">' +
      '<div class="asm-score-ring" style="background:conic-gradient(' + color + ' ' + angle + 'deg, var(--border-soft) 0);">' +
        '<div class="asm-score-inner">' + inner + '</div>' +
      '</div>' +
      '<div class="asm-kpi-grade" style="color:' + color + ';">' + grade + '</div>' +
    '</div>' +
  '</div>';
};

WG._scoreColor = function(score) {
  if (score == null) return WG._cssVar('--info');
  if (score >= 80) return WG._cssVar('--low');
  if (score >= 60) return WG._cssVar('--info');
  if (score >= 40) return WG._cssVar('--medium');
  if (score >= 20) return WG._cssVar('--high');
  return WG._cssVar('--critical');
};

/* ── Newly discovered list ───────────────────────────────────────────── */
WG._newlyDiscoveredHtml = function(items, loaded) {
  var esc = WG.escHtml;
  if (!loaded) {
    return '<div class="panel-empty" style="padding:24px;color:var(--text-muted);"><div class="spinner"></div></div>';
  }
  if (!items.length) {
    return '<div class="panel-empty" style="padding:24px;"><div class="icon">&#10003;</div>No new assets in the last 7 days.</div>';
  }
  return items.map(function(a) {
    var risk = a.risk_score || 0;
    var ring = risk >= 50 ? 'var(--critical)' : risk >= 20 ? 'var(--high)' : 'var(--low)';
    var svc = a.service ? esc(a.service) : 'unknown';
    var detail = a.product ? esc(a.product) + (a.version ? ' ' + esc(a.version) : '') : svc;
    return '<div class="asm-disc-item">' +
      '<div class="asm-disc-dot" style="background:' + ring + '"></div>' +
      '<div class="asm-disc-main">' +
        '<div class="mono asm-disc-addr">' + esc(a.ip) + (a.port ? ':' + a.port : '') + '</div>' +
        '<div class="asm-disc-detail">' + detail + '</div>' +
      '</div>' +
      '<div class="asm-disc-time" title="' + esc(a.first_seen || '') + '">' + WG.timeAgo(a.first_seen) + '</div>' +
    '</div>';
  }).join('');
};

/* ── Top exposures ──────────────────────────────────────────────────── */
WG._topExposuresHtml = function(items, loaded) {
  var esc = WG.escHtml;
  if (!loaded) {
    return '<div class="panel-body panel-empty" style="padding:36px;"><div class="spinner"></div></div>';
  }
  if (!items.length) {
    return '<div class="panel-body panel-empty" style="padding:36px;"><div class="icon">&#128737;</div>No exposures recorded yet.</div>';
  }
  return '<table class="data-table"><thead><tr>' +
    '<th style="width:120px;">CVE</th><th style="width:70px;">CVSS</th><th>Title</th>' +
    '<th style="width:70px;text-align:right;">Hosts</th><th style="width:80px;">Severity</th>' +
    '</tr></thead><tbody>' +
    items.map(function(f) {
      var cvssNum = parseFloat(String(f.cvss || '').split(' ')[0]) || 0;
      var barPct = Math.min(100, cvssNum * 10);
      var barColor = cvssNum >= 9 ? 'var(--critical)' : cvssNum >= 7 ? 'var(--high)' : cvssNum >= 4 ? 'var(--medium)' : 'var(--low)';
      return '<tr>' +
        '<td class="mono" style="color:var(--accent);">' + esc(f.cve) + '</td>' +
        '<td>' +
          '<div class="asm-cvss-bar"><div class="asm-cvss-fill" style="width:' + barPct + '%;background:' + barColor + ';"></div></div>' +
          '<div class="mono" style="font-size:0.66rem;color:var(--text-dim);margin-top:2px;">' + (cvssNum ? cvssNum.toFixed(1) : '\u2014') + '</div>' +
        '</td>' +
        '<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(f.title) + '">' + esc(f.title) + '</td>' +
        '<td class="mono" style="text-align:right;font-weight:600;">' + (f.affected || 1) + '</td>' +
        '<td><span class="sev-badge ' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
};

/* ── Top technologies horizontal bars ────────────────────────────────── */
WG._topTechHtml = function(items, loaded) {
  var esc = WG.escHtml;
  if (!loaded) return '<div class="panel-empty" style="padding:24px;"><div class="spinner"></div></div>';
  if (!items.length) return '<div class="panel-empty" style="padding:24px;">No technology data detected yet.</div>';
  var max = items.reduce(function(m, t) { return Math.max(m, t.count); }, 1);
  return '<div class="asm-tech-grid">' + items.map(function(t) {
    var pct = (t.count / max) * 100;
    return '<div class="asm-tech-item">' +
      '<div class="asm-tech-name">' + esc(t.name) + '</div>' +
      '<div class="asm-tech-bar"><div class="asm-tech-fill" style="width:' + pct + '%;"></div></div>' +
      '<div class="mono asm-tech-count">' + t.count + '</div>' +
    '</div>';
  }).join('') + '</div>';
};

/* ── Asset inventory table ───────────────────────────────────────────── */
WG._renderAssetInventory = function() {
  var wrap = document.getElementById('asmAssetTableWrap');
  if (!wrap) return;
  WG._setHtml(wrap, WG._assetInventoryHtml());
};

WG._assetInventoryHtml = function() {
  var esc = WG.escHtml;
  var assets = WG._asmAssetsCache;
  if (assets == null) {
    return '<div class="panel-empty" style="padding:40px;"><div class="spinner"></div></div>';
  }
  if (!assets.length) {
    return '<div class="panel-empty" style="padding:40px;"><div class="icon">&#128269;</div>No assets match the current filters.</div>';
  }
  return '<table class="data-table"><thead><tr>' +
    '<th>IP</th><th style="width:80px;">Port</th><th>Service</th><th>Product / Version</th>' +
    '<th style="width:100px;">Risk</th><th style="width:80px;text-align:right;">Findings</th>' +
    '<th style="width:120px;">First seen</th><th style="width:120px;">Last seen</th><th style="width:90px;">Status</th>' +
    '</tr></thead><tbody>' +
    assets.map(function(a) {
      var risk = a.risk_score || 0;
      var riskColor = risk >= 50 ? 'var(--critical)' : risk >= 20 ? 'var(--high)' : risk > 0 ? 'var(--medium)' : 'var(--low)';
      var riskPct = Math.min(100, risk);
      var product = a.service_product ? esc(a.service_product) + (a.service_version ? ' ' + esc(a.service_version) : '') : '<span style="color:var(--text-muted);">\u2014</span>';
      return '<tr>' +
        '<td class="mono"><span class="host-tag">' + esc(a.ip) + '</span>' +
          (a.hostname ? '<div style="font-size:0.68rem;color:var(--text-dim);margin-top:2px;">' + esc(a.hostname) + '</div>' : '') + '</td>' +
        '<td class="mono">' + (a.port == null ? '\u2014' : a.port) + (a.protocol ? '/' + esc(a.protocol) : '') + '</td>' +
        '<td>' + (a.service_name ? '<span class="tag">' + esc(a.service_name) + '</span>' : '<span style="color:var(--text-muted);">\u2014</span>') + '</td>' +
        '<td class="mono" style="font-size:0.76rem;">' + product + '</td>' +
        '<td>' +
          '<div class="asm-risk-bar"><div class="asm-risk-fill" style="width:' + riskPct + '%;background:' + riskColor + ';"></div></div>' +
          '<div class="mono" style="font-size:0.66rem;color:var(--text-dim);margin-top:2px;">' + risk + ' / 100</div>' +
        '</td>' +
        '<td class="mono" style="text-align:right;">' + (a.findings_count || 0) +
          (a.critical_count ? ' <span class="sev-badge critical" style="font-size:0.6rem;padding:1px 4px;">' + a.critical_count + 'C</span>' : '') +
          (a.high_count ? ' <span class="sev-badge high" style="font-size:0.6rem;padding:1px 4px;">' + a.high_count + 'H</span>' : '') +
        '</td>' +
        '<td class="mono" title="' + esc(a.first_seen || '') + '">' + WG.timeAgo(a.first_seen) + '</td>' +
        '<td class="mono" title="' + esc(a.last_seen || '') + '">' + WG.timeAgo(a.last_seen) + '</td>' +
        '<td><span class="status-badge ' + (a.status === 'open' ? 'completed' : 'cancelled') + '"><span class="dot"></span> ' + esc(a.status) + '</span></td>' +
      '</tr>';
    }).join('') +
    '</tbody></table>';
};

WG._bindAssetFilters = function() {
  var debounce;
  function trigger() {
    WG._asmAssetsParams.search   = (document.getElementById('asmSearch') || {}).value || '';
    WG._asmAssetsParams.status   = (document.getElementById('asmStatus') || {}).value || '';
    WG._asmAssetsParams.min_risk = (document.getElementById('asmMinRisk') || {}).value || '';
    WG._asmAssetsParams.has_cve  = (document.getElementById('asmHasCve') || {}).value || '';
    WG._asmAssetsCache = null;
    WG._renderAssetInventory();
    WG._loadAssetInventory();
  }
  var input = document.getElementById('asmSearch');
  if (input) input.addEventListener('input', function() {
    clearTimeout(debounce); debounce = setTimeout(trigger, 250);
  });
  ['asmStatus', 'asmMinRisk', 'asmHasCve'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', trigger);
  });
};

/* ── Chart.js init ───────────────────────────────────────────────────── */
WG._destroyCharts = function() {
  if (!WG._charts) { WG._charts = {}; return; }
  Object.keys(WG._charts).forEach(function(k) {
    try { WG._charts[k].destroy(); } catch (e) {}
  });
  WG._charts = {};
};

WG._initAsmCharts = function() {
  if (typeof Chart === 'undefined') return;
  WG._destroyCharts();
  var data = WG._cache['asm'] || {};
  WG._renderSeverityTrend(data.severity_trend || []);
  WG._renderRiskBySource(data.risk_by_source || []);
};

WG._renderSeverityTrend = function(trend) {
  var el = document.getElementById('chartSeverityTrend');
  if (!el) return;
  var colors = WG._sevColors();
  var labels = trend.map(function(r) { return r.date; });
  var mkDs = function(name, color) {
    return {
      label: name.charAt(0).toUpperCase() + name.slice(1),
      data: trend.map(function(r) { return r[name] || 0; }),
      borderColor: color,
      backgroundColor: color + '22',
      borderWidth: 1.5,
      fill: 'origin',
      tension: 0.32,
      pointRadius: 0,
      pointHoverRadius: 3,
    };
  };
  var datasets = [
    mkDs('info',     colors.info),
    mkDs('low',      colors.low),
    mkDs('medium',   colors.medium),
    mkDs('high',     colors.high),
    mkDs('critical', colors.critical),
  ];
  WG._charts.severityTrend = new Chart(el.getContext('2d'), {
    type: 'line',
    data: { labels: labels, datasets: datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: WG._cssVar('--bg-elevated'),
          titleColor: WG._cssVar('--text-bright'),
          bodyColor: WG._cssVar('--text-primary'),
          borderColor: WG._cssVar('--border-soft'),
          borderWidth: 1,
        },
      },
      scales: {
        x: {
          grid: { color: WG._cssVar('--border-dim'), drawBorder: false },
          ticks: { color: WG._cssVar('--text-dim'), maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
        },
        y: {
          stacked: true, beginAtZero: true,
          grid: { color: WG._cssVar('--border-dim'), drawBorder: false },
          ticks: { color: WG._cssVar('--text-dim'), precision: 0 },
        },
      },
    },
  });
};

WG._renderRiskBySource = function(sources) {
  var el = document.getElementById('chartRiskBySource');
  if (!el) return;
  var palette = [
    WG._cssVar('--critical'), WG._cssVar('--high'),
    WG._cssVar('--medium'), WG._cssVar('--low'),
    WG._cssVar('--info'), WG._cssVar('--accent'),
  ];
  var labels = sources.map(function(s) { return s.source || 'unknown'; });
  var values = sources.map(function(s) { return s.count || 0; });
  var total = values.reduce(function(a, b) { return a + b; }, 0);
  var totalEl = document.getElementById('asmDonutTotal');
  if (totalEl) totalEl.textContent = WG._kNumber(total);

  WG._charts.riskBySource = new Chart(el.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: labels.map(function(_, i) { return palette[i % palette.length]; }),
        borderWidth: 0,
        spacing: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: WG._cssVar('--bg-elevated'),
          titleColor: WG._cssVar('--text-bright'),
          bodyColor: WG._cssVar('--text-primary'),
          borderColor: WG._cssVar('--border-soft'),
          borderWidth: 1,
        },
      },
    },
  });

  var legend = document.getElementById('asmDonutLegend');
  if (legend) {
    WG._setHtml(legend, labels.map(function(label, i) {
      return '<div class="asm-donut-item">' +
        '<span class="dot" style="background:' + palette[i % palette.length] + ';"></span>' +
        '<span>' + WG.escHtml(label) + '</span>' +
        '<span class="mono" style="margin-left:auto;color:var(--text-dim);">' + values[i] + '</span>' +
      '</div>';
    }).join(''));
  }
};

/* ── Utility: compact number display (1234 → "1.2k") ────────────────── */
WG._kNumber = function(n) {
  n = Number(n || 0);
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (Math.abs(n) >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(Math.round(n));
};
