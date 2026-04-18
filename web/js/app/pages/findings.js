/* Wire_Ghost — Global findings page */

WG.renderFindings = function() {
  var findings = WG.getCached('findings', '/findings/');
  WG.fetchData('/findings/', 'findings').then(function(data) {
    if (data && data.length && WG.state.currentPage === 'findings') {
      WG._cache['findings'] = data; WG._cacheTime['findings'] = Date.now();
      var main = document.getElementById('mainContent');
      if (main && !document.querySelector(".modal-overlay.active")) main.innerHTML = WG.renderFindings();
    }
  });
  var sevCounts = {};
  findings.forEach(function(f) { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Findings</h1><p>' + findings.length + ' vulnerabilities across all scans</p></div></div>' +
    '<div class="stats-grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:20px;">' +
      ['critical','high','medium','low','info'].map(function(sev) {
        return '<div class="stat-card ' + sev + ' anim-reveal"><div class="stat-label">' + sev + '</div><div class="stat-value">' + (sevCounts[sev] || 0) + '</div></div>';
      }).join('') +
    '</div>' +
    '<div class="filters-bar">' +
      '<input class="filter-input" placeholder="Search findings..." id="findingSearch" oninput="WG.filterFindings()">' +
      '<select class="filter-select" id="findingSevFilter" onchange="WG.filterFindings()"><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select>' +
      '<select class="filter-select" id="findingSourceFilter" onchange="WG.filterFindings()"><option value="">All Sources</option><option value="nuclei">Nuclei</option><option value="nuclei_external">Nuclei (External)</option><option value="nmap_vuln">Nmap Vuln</option><option value="service_enum">Service Enum</option><option value="searchsploit">Searchsploit</option></select>' +
    '</div>' +
    '<div class="panel"><table class="data-table" id="findingsTable"><thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>Source</th><th>CVE</th><th>CVSS</th></tr></thead><tbody>' +
    findings.sort(function(a, b) { return WG.sevOrder(a.severity) - WG.sevOrder(b.severity); }).map(function(f) {
      var esc = WG.escHtml;
      var cvssColor = f.cvss >= 9 ? 'var(--critical)' : f.cvss >= 7 ? 'var(--high)' : f.cvss >= 4 ? 'var(--medium)' : 'var(--text-dim)';
      return '<tr onclick="WG.navigate(\'finding\',{id:\'' + f.id + '\'})" data-sev="' + esc(f.severity) + '" data-source="' + esc(f.source) + '" data-search="' + esc((f.title + ' ' + f.host_ip + ' ' + (f.cve || '')).toLowerCase()) + '">' +
        '<td><span class="sev-badge ' + f.severity + '">' + f.severity + '</span></td>' +
        '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(f.title) + '</td>' +
        '<td><span class="host-tag">' + esc(f.host_ip) + '</span></td>' +
        '<td class="mono">' + (f.port || '\u2014') + '</td>' +
        '<td><span class="tag">' + esc(f.source) + '</span>' + (f.source === 'nuclei_external' ? '<span class="tag" style="background:var(--medium-bg,#f59e0b22);color:var(--medium,#f59e0b);font-size:0.6rem;margin-left:4px;" title="External template \u2014 may be a false positive">FP?</span>' : '') + '</td>' +
        '<td class="mono" style="color:var(--accent);">' + esc(f.cve || '\u2014') + '</td>' +
        '<td class="mono" style="color:' + cvssColor + ';">' + (f.cvss || '\u2014') + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG.filterFindings = function() {
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

  // Also fetch filtered from API if connected (debounced)
  clearTimeout(WG._findingsFilterTimer);
  WG._findingsFilterTimer = setTimeout(function() {
    var params = [];
    if (sev) params.push('severity=' + sev);
    if (source) params.push('source=' + source);
    if (search) params.push('search=' + search);
    var query = params.length ? '?' + params.join('&') : '';
    WG.fetchData('/findings/' + query, 'findings').then(function(data) {
      if (data && WG.state.currentPage === 'findings') {
        WG._cache['findings'] = data;
        WG._cacheTime['findings'] = Date.now();
        var main = document.getElementById('mainContent');
        if (main && !document.querySelector(".modal-overlay.active")) main.innerHTML = WG.renderFindings();
      }
    });
  }, 500);
};
