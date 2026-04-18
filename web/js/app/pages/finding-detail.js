/* Wire_Ghost — Finding detail page */

WG.renderFindingDetail = function(id) {
  if (!WG._cache['finding_' + id]) {
    WG.api('/findings/' + id + '/').then(function(data) {
      if (data && WG.state.currentPage === 'finding') {
        WG._cache['finding_' + id] = data;
        WG._cacheTime['finding_' + id] = Date.now();
        var main = document.getElementById('mainContent');
        if (main) main.innerHTML = WG.renderFindingDetail(id);
      }
    });
  }

  var f = WG._cache['finding_' + id] || WG.getCached('findings', '/findings/').find(function(x) { return x.id === id; });
  if (!f) return '<div class="empty-state"><div class="icon">&#9888;</div><h3>Loading finding...</h3><div class="spinner" style="margin:16px auto;"></div></div>';

  var esc = WG.escHtml;
  var scan = null;
  var refs = [];
  try { refs = JSON.parse(f.references || '[]'); } catch (e) {}
  var safeHref = function(r) { return /^https?:\/\//i.test(r) ? esc(r) : '#'; };

  return '' +
    '<div class="breadcrumbs">' +
      '<a onclick="WG.navigate(\'scans\')">Scans</a><span class="sep">/</span>' +
      '<a onclick="WG.navigate(\'scan\',{id:\'' + f.scan + '\'})">' + esc(scan ? scan.name : 'Scan') + '</a><span class="sep">/</span>' +
      '<a onclick="WG.navigate(\'findings\')">Findings</a><span class="sep">/</span>' +
      '<span>' + esc(f.title).substring(0, 40) + '...</span>' +
    '</div>' +

    '<div class="page-header"><div class="page-header-left">' +
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:4px;">' +
        '<span class="sev-badge ' + f.severity + '" style="font-size:0.8rem;padding:4px 12px;">' + f.severity + '</span>' +
        (f.cvss ? '<span class="mono" style="color:' + (f.cvss >= 9 ? 'var(--critical)' : f.cvss >= 7 ? 'var(--high)' : 'var(--medium)') + ';font-weight:700;">CVSS ' + f.cvss + '</span>' : '') +
      '</div>' +
      '<h1 style="font-size:1.3rem;">' + esc(f.title) + '</h1>' +
    '</div></div>' +

    '<div class="info-grid" style="margin-bottom:24px;">' +
      '<div class="info-item"><div class="info-label">Host</div><div class="info-value"><a onclick="WG.navigate(\'host\',{id:\'' + f.host + '\'})" class="host-tag">' + esc(f.host_ip) + '</a></div></div>' +
      '<div class="info-item"><div class="info-label">Port</div><div class="info-value mono">' + (f.port || '\u2014') + '/' + (f.protocol || 'tcp') + '</div></div>' +
      '<div class="info-item"><div class="info-label">Source</div><div class="info-value"><span class="tag">' + esc(f.source) + '</span>' + (f.source === 'nuclei_external' ? '<span class="tag" style="background:var(--medium-bg,#f59e0b22);color:var(--medium,#f59e0b);font-size:0.6rem;margin-left:4px;" title="External template \u2014 may be a false positive">FP?</span>' : '') + '</div></div>' +
      (f.cve ? '<div class="info-item"><div class="info-label">CVE</div><div class="info-value mono" style="color:var(--accent);">' + esc(f.cve) + '</div></div>' : '') +
      (f.cwe ? '<div class="info-item"><div class="info-label">CWE</div><div class="info-value mono">' + esc(f.cwe) + '</div></div>' : '') +
      (f.template_id ? '<div class="info-item"><div class="info-label">Template</div><div class="info-value mono" style="font-size:0.75rem;">' + esc(f.template_id) + '</div></div>' : '') +
      (f.full_url ? '<div class="info-item"><div class="info-label">URL</div><div class="info-value mono" style="font-size:0.75rem;word-break:break-all;">' + esc(f.full_url) + '</div></div>' : '') +
    '</div>' +

    (f.description ?
      '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">Description</div></div><div class="panel-body" style="font-size:0.85rem;line-height:1.7;color:var(--text-secondary);">' + esc(f.description) + '</div></div>' : '') +

    (f.request ?
      '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">HTTP Request</div></div><div class="panel-body" style="padding:0;"><div class="code-block">' + esc(f.request) + '</div></div></div>' : '') +

    (f.response ?
      '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">HTTP Response</div></div><div class="panel-body" style="padding:0;"><div class="code-block">' + esc(f.response) + '</div></div></div>' : '') +

    (f.curl_command ?
      '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">Reproduce</div><button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText(' + JSON.stringify(f.curl_command) + ');WG.toast(\'Copied\',\'success\');">Copy</button></div><div class="panel-body" style="padding:0;"><div class="code-block" style="color:var(--accent);">' + esc(f.curl_command) + '</div></div></div>' : '') +

    (refs.length ?
      '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">References</div></div><div class="panel-body">' +
      refs.map(function(r) { return '<div style="margin-bottom:6px;"><a href="' + safeHref(r) + '" target="_blank" rel="noopener" style="font-size:0.82rem;word-break:break-all;">' + esc(r) + '</a></div>'; }).join('') +
      '</div></div>' : '') +

    (f.tags ?
      '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;">' +
      f.tags.split(',').map(function(t) { return '<span class="tag">' + esc(t.trim()) + '</span>'; }).join('') +
      '</div>' : '');
};
