/* Wire_Ghost — Hosts list page */

WG.renderHosts = function() {
  var hosts = WG.getCached('hosts', '/hosts/');
  var scans = WG.getCached('scans', '/scans/');
  WG.fetchData('/hosts/', 'hosts').then(function(data) {
    if (data && data.length && WG.state.currentPage === 'hosts') {
      WG._cache['hosts'] = data; WG._cacheTime['hosts'] = Date.now();
      var main = document.getElementById('mainContent');
      if (main) main.innerHTML = WG.renderHosts();
    }
  });
  var esc = WG.escHtml;
  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Hosts</h1><p>' + hosts.length + ' discovered hosts across all scans</p></div></div>' +
    '<div class="filters-bar"><input class="filter-input" placeholder="Search hosts..." id="hostSearch" oninput="WG.filterHosts()"></div>' +
    '<div class="panel"><table class="data-table" id="hostsTable"><thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Scan</th><th>Ports</th><th>Findings</th></tr></thead><tbody>' +
    hosts.map(function(h) {
      var scan = scans.find(function(s) { return s.id === h.scan; });
      return '<tr onclick="WG.navigate(\'host\',{id:\'' + h.id + '\'})" data-search="' + esc((h.ip + ' ' + (h.hostname || '') + ' ' + (h.os || '')).toLowerCase()) + '">' +
        '<td><span class="host-tag">' + esc(h.ip) + '</span></td>' +
        '<td>' + (esc(h.hostname) || '<span style="color:var(--text-dim)">\u2014</span>') + '</td>' +
        '<td><span class="tag">' + (esc(h.os) || '\u2014') + '</span></td>' +
        '<td><a onclick="event.stopPropagation();WG.navigate(\'scan\',{id:\'' + h.scan + '\'})" style="font-size:0.8rem;">' + esc(scan ? scan.name : '') + '</a></td>' +
        '<td class="mono">' + h.ports_count + '</td>' +
        '<td class="mono">' + h.findings_count + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG.filterHosts = function() {
  var search = (document.getElementById('hostSearch').value || '').toLowerCase();
  document.querySelectorAll('#hostsTable tbody tr').forEach(function(tr) {
    tr.style.display = (!search || tr.dataset.search.includes(search)) ? '' : 'none';
  });
};
