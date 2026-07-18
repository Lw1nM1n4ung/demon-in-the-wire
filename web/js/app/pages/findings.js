/* Wire_Ghost — Global findings page */

// Pagination state
WG._findingsPage = WG._findingsPage || 1;
WG._findingsTotal = WG._findingsTotal || 0;

// Build API path for findings with current filters and page
WG._findingsPath = function() {
  var params = [];
  var page = WG._findingsPage || 1;
  params.push('page=' + page);
  // Preserve filters if set
  var sev = document.getElementById('findingSevFilter');
  var source = document.getElementById('findingSourceFilter');
  var search = document.getElementById('findingSearch');
  if (sev && sev.value) params.push('severity=' + encodeURIComponent(sev.value));
  if (source && source.value) params.push('source=' + encodeURIComponent(source.value));
  if (search && search.value) params.push('search=' + encodeURIComponent(search.value));
  return '/findings/?' + params.join('&');
};

// Render pagination controls
WG._renderPagination = function() {
  var page = WG._findingsPage;
  var total = WG._findingsTotal;
  var pageSize = findings.length || WG._findingsPageSize || 100;
  var totalPages = Math.ceil(total / pageSize);
  if (totalPages <= 1) return '';

  var html = '<div class="pagination-bar" style="display:flex;align-items:center;justify-content:center;gap:8px;padding:12px 0;flex-wrap:wrap;">';

  // Previous
  html += '<button class="btn btn-sm" onclick="WG.goFindingsPage(' + (page - 1) + ')"' + (page <= 1 ? ' disabled' : '') + ' style="padding:6px 12px;">&laquo; Prev</button>';

  // Page numbers
  var startPage = Math.max(1, page - 2);
  var endPage = Math.min(totalPages, page + 2);
  if (startPage > 1) {
    html += '<button class="btn btn-sm" onclick="WG.goFindingsPage(1)" style="padding:6px 10px;">1</button>';
    if (startPage > 2) html += '<span style="color:var(--text-dim);padding:0 4px;">…</span>';
  }
  for (var p = startPage; p <= endPage; p++) {
    html += '<button class="btn btn-sm' + (p === page ? ' active' : '') + '" onclick="WG.goFindingsPage(' + p + ')" style="padding:6px 10px;' + (p === page ? 'background:var(--accent);color:#fff;' : '') + '">' + p + '</button>';
  }
  if (endPage < totalPages) {
    if (endPage < totalPages - 1) html += '<span style="color:var(--text-dim);padding:0 4px;">…</span>';
    html += '<button class="btn btn-sm" onclick="WG.goFindingsPage(' + totalPages + ')" style="padding:6px 10px;">' + totalPages + '</button>';
  }

  // Next
  html += '<button class="btn btn-sm" onclick="WG.goFindingsPage(' + (page + 1) + ')"' + (page >= totalPages ? ' disabled' : '') + ' style="padding:6px 12px;">Next &raquo;</button>';

  html += '</div>';
  return html;
};

// Navigate to a specific findings page
WG.goFindingsPage = function(page) {
  var total = WG._findingsTotal;
  var results = WG._cache['findings'] || [];
  var pageSize = results.length || 100;
  var totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (page < 1 || page > totalPages) return;
  WG._findingsPage = page;
  WG.invalidateCache('findings');
  WG._fetchAndRenderFindings();
};

// Fetch findings from API and render
WG._fetchAndRenderFindings = function() {
  var apiPath = WG._findingsPath();
  WG.api(apiPath).then(function(data) {
    if (!data || WG.state.currentPage !== 'findings') return;
    if (document.querySelector('.modal-overlay.active')) return;
    var results = data.results || data;
    WG._findingsTotal = data.count || results.length;
    WG._cache['findings'] = results;
    WG._cacheTime['findings'] = Date.now();
    var main = document.getElementById('mainContent');
    if (main) {
      main.textContent = '';
      main.insertAdjacentHTML('beforeend', WG.renderFindings());
    }
  });
};

WG.renderFindings = function() {
  var findings = WG.getCached('findings', '/findings/');
  var total = WG._findingsTotal;

  // If cache is empty, trigger a fetch
  if (!findings || findings.length === 0) {
    if (!WG._findingsFetching) {
      WG._findingsFetching = true;
      WG._fetchAndRenderFindings().finally(function() { WG._findingsFetching = false; });
    }
    return '<div class="empty-state"><div class="icon">&#8862;</div><h3>Loading findings...</h3><div class="spinner" style="margin:16px auto;"></div></div>';
  }

  // Refresh in background
  WG.refreshAndRerender('findings', WG._findingsPath(), WG.renderFindings, 'findings');

  var sevCounts = {};
  findings.forEach(function(f) { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });

  var page = WG._findingsPage;
  var pageSize = findings.length;
  var totalPages = Math.ceil(total / pageSize);
  var showing = total > 0 ? ((page - 1) * pageSize + 1) + '\u2013' + Math.min(page * pageSize, total) + ' of ' + total : '0';

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Findings</h1><p>' + showing + ' vulnerabilities across all scans</p></div></div>' +
    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:20px;">' +
      ['critical','high','medium','low','info'].map(function(sev) {
        return '<div class="stat-card ' + sev + ' anim-reveal"><div class="stat-label">' + sev + '</div><div class="stat-value">' + (sevCounts[sev] || 0) + '</div></div>';
      }).join('') +
    '</div>' +
    '<div class="filters-bar">' +
      '<input class="filter-input" placeholder="Search findings..." id="findingSearch" oninput="WG.filterFindings()">' +
      '<select class="filter-select" id="findingSevFilter" onchange="WG.filterFindings()"><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>' +
      '<select class="filter-select" id="findingSourceFilter" onchange="WG.filterFindings()"><option value="">All Sources</option><option value="nuclei">Nuclei</option><option value="nuclei_external">Nuclei (External)</option><option value="nmap_vuln">Nmap Vuln</option><option value="service_enum">Service Enum</option><option value="searchsploit">Searchsploit</option><option value="getsploit">Getsploit</option><option value="nikto">Nikto</option><option value="netexec">NetExec</option><option value="wpscan">WPScan</option><option value="sslscan">SSLScan</option><option value="snmp_enum">SNMP Enum</option><option value="nfs_enum">NFS Enum</option><option value="ldap_enum">LDAP Enum</option><option value="katana">Katana</option><option value="msf_scan">MSF Scan</option><option value="enum4linux">Enum4Linux</option></select>' +
    '</div>' +
    WG._renderPagination() +
    '<div class="panel"><table class="data-table" id="findingsTable"><thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>Source</th><th>CVE</th><th>CVSS</th></tr></thead><tbody>' +
    findings.sort(function(a, b) { return WG.sevOrder(a.severity) - WG.sevOrder(b.severity); }).map(function(f) {
      var esc = WG.escHtml;
      var cvssColor = f.cvss >= 9 ? 'var(--critical)' : f.cvss >= 7 ? 'var(--high)' : f.cvss >= 4 ? 'var(--medium)' : 'var(--text-dim)';
      return '<tr onclick="WG.navigate(\'finding\',{id:\'' + f.id + '\'})" data-sev="' + esc(f.severity) + '" data-source="' + esc(f.source) + '" data-search="' + esc((f.title + ' ' + f.host_ip + ' ' + (f.cve || '')).toLowerCase()) + '">' +
        '<td><span class="sev-badge ' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>' +
        '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(f.title) + '</td>' +
        '<td><span class="host-tag">' + esc(f.host_ip) + '</span></td>' +
        '<td class="mono">' + esc(f.port || '\u2014') + '</td>' +
        '<td><span class="tag">' + esc(f.source) + '</span>' + (f.source === 'nuclei_external' ? '<span class="tag" style="background:var(--medium-bg,#f59e0b22);color:var(--medium,#f59e0b);font-size:0.6rem;margin-left:4px;" title="External template \u2014 may be a false positive">FP?</span>' : '') + '</td>' +
        '<td class="mono" style="color:var(--accent);">' + esc(f.cve || '\u2014') + '</td>' +
        '<td class="mono" style="color:' + cvssColor + ';">' + esc(f.cvss || '\u2014') + '</td></tr>';
    }).join('') +
    '</tbody></table></div>' +
    WG._renderPagination();
};

WG.filterFindings = function() {
  // Reset to page 1 when filters change
  WG._findingsPage = 1;

  var search = (document.getElementById('findingSearch').value || '').toLowerCase();
  var sev = document.getElementById('findingSevFilter').value;
  var source = document.getElementById('findingSourceFilter').value;

  // Local filter for immediate response
  document.querySelectorAll('#findingsTable tbody tr').forEach(function(tr) {
    var ok = (!search || tr.dataset.search.includes(search)) &&
             (!sev || tr.dataset.sev === sev) &&
             (!source || tr.dataset.source === source);
    tr.style.display = ok ? '' : 'none';
  });

  // Fetch the real filtered first page from API (debounced)
  clearTimeout(WG._findingsFilterTimer);
  WG._findingsFilterTimer = setTimeout(function() {
    WG.invalidateCache('findings');
    WG._fetchAndRenderFindings();
  }, 500);
};
