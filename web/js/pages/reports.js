/* Wire_Ghost — Reports page */

WG.renderReports = function() {
  var reports = [];
  var scans = WG.getCached('scans', '/scans/');
  // Collect reports from scans that have nested reports
  if (!reports.length && scans.length) {
    scans.forEach(function(s) { if (s.reports) reports = reports.concat(s.reports.map(function(r) { r.scan = s.id; return r; })); });
  }
  var esc = WG.escHtml;
  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Reports</h1><p>' + reports.length + ' generated reports</p></div></div>' +
    '<div class="panel"><table class="data-table"><thead><tr><th>Scan</th><th>Format</th><th>File</th><th>Size</th><th>Generated</th><th></th></tr></thead><tbody>' +
    reports.map(function(r) {
      var scan = scans.find(function(s) { return s.id === r.scan; });
      return '<tr>' +
        '<td><a onclick="WG.navigate(\'scan\',{id:\'' + r.scan + '\'})">' + esc(scan ? scan.name : 'Scan ' + r.scan) + '</a></td>' +
        '<td><span class="tag">' + esc(r.format.toUpperCase()) + '</span></td>' +
        '<td class="mono" style="font-size:0.75rem;">' + esc(r.file_path.split('/').pop()) + '</td>' +
        '<td class="mono">' + WG.fmtBytes(r.file_size) + '</td>' +
        '<td class="mono">' + WG.fmtDate(r.created_at) + '</td>' +
        '<td><button class="btn btn-ghost btn-sm" onclick="WG.downloadReport(\'' + r.id + '\')">Download</button></td></tr>';
    }).join('') +
    '</tbody></table></div>';
};
