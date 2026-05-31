/* Wire_Ghost — Hosts list page */

WG.renderHosts = function() {
  var hosts = WG.getCached('hosts', '/hosts/');
  var scans = WG.getCached('scans', '/scans/');
  WG.refreshAndRerender('hosts', '/hosts/', WG.renderHosts, 'hosts');
  var esc = WG.escHtml;
  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Hosts</h1><p>' + hosts.length + ' discovered hosts across all scans</p></div></div>' +
    '<div class="filters-bar"><input class="filter-input" placeholder="Search hosts..." id="hostSearch" oninput="WG.filterHosts()"></div>' +
    '<div class="panel"><table class="data-table" id="hostsTable"><thead><tr><th>IP Address</th><th>Method</th><th>Hostname</th><th>OS</th><th>Scan</th><th>Ports</th><th>Findings</th><th>Screenshots</th></tr></thead><tbody>' +
    hosts.map(function(h) {
      var scan = scans.find(function(s) { return s.id === h.scan; });
      var ssCell = '';
      if (h.thumbnail_url) {
        ssCell = '<div class="screenshot-thumbs"><img class="screenshot-thumb" src="' + esc(h.thumbnail_url) + '" loading="lazy" alt="screenshot" onclick="event.stopPropagation();WG.navigate(\'host\',{id:\'' + h.id + '\'})">';
        if ((h.screenshot_count || 0) > 1) ssCell += '<span class="screenshot-more">+' + (h.screenshot_count - 1) + ' more</span>';
        ssCell += '</div>';
      }
      var method = h.discovery_method || '';
      var methodBadge = '';
      if (method === 'nmap') methodBadge = '<span style="font-size:0.6rem;padding:1px 6px;border-radius:3px;background:rgba(59,130,246,0.15);color:#60a5fa;">nmap</span>';
      else if (method === 'fping') methodBadge = '<span style="font-size:0.6rem;padding:1px 6px;border-radius:3px;background:rgba(52,211,153,0.15);color:#34d399;">fping</span>';
      else if (method === 'fping_unreachable') methodBadge = '<span style="font-size:0.6rem;padding:1px 6px;border-radius:3px;background:rgba(251,191,36,0.15);color:#fbbf24;">unreachable</span>';
      else if (method === 'arp') methodBadge = '<span style="font-size:0.6rem;padding:1px 6px;border-radius:3px;background:rgba(168,85,247,0.15);color:#a855f7;">ARP</span>';
      return '<tr onclick="WG.navigate(\'host\',{id:\'' + h.id + '\'})" data-search="' + esc((h.ip + ' ' + (h.hostname || '') + ' ' + (h.os || '') + ' ' + method).toLowerCase()) + '">' +
        '<td><span class="host-tag">' + esc(h.ip) + '</span></td>' +
        '<td>' + (methodBadge || '<span style="color:var(--text-dim);font-size:0.7rem;">\u2014</span>') + '</td>' +
        '<td>' + (esc(h.hostname) || '<span style="color:var(--text-dim)">\u2014</span>') + '</td>' +
        '<td><span class="tag">' + (esc(h.os) || '\u2014') + '</span></td>' +
        '<td><a onclick="event.stopPropagation();WG.navigate(\'scan\',{id:\'' + h.scan + '\'})" style="font-size:0.8rem;">' + esc(scan ? scan.name : '') + '</a></td>' +
        '<td class="mono">' + h.ports_count + '</td>' +
        '<td class="mono">' + h.findings_count + '</td>' +
        '<td>' + ssCell + '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG.filterHosts = function() {
  var search = (document.getElementById('hostSearch').value || '').toLowerCase();
  document.querySelectorAll('#hostsTable tbody tr').forEach(function(tr) {
    tr.style.display = (!search || tr.dataset.search.includes(search)) ? '' : 'none';
  });
};
