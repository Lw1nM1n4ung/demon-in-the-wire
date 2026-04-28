/* Wire_Ghost — Report Builder / Customization page */

WG.renderReportBuilder = function() {
  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Report Engine</h1><p>Customize report branding, sections, and output formats</p></div></div>' +
    '<div class="tabs" id="reportTabs">' +
      '<div class="tab active" data-tab="branding" onclick="WG.switchReportTab(\'branding\')">Branding</div>' +
      '<div class="tab" data-tab="sections" onclick="WG.switchReportTab(\'sections\')">Sections</div>' +
      '<div class="tab" data-tab="formats" onclick="WG.switchReportTab(\'formats\')">Formats</div>' +
      '<div class="tab" data-tab="generate" onclick="WG.switchReportTab(\'generate\')">Generate</div>' +
    '</div>' +
    '<div id="reportTabContent">' + WG._reportBranding() + '</div>';
};

WG._reportConfig = null;
WG._reportConfigLoaded = false;

WG._loadReportConfig = function(callback) {
  WG.api('/report-config/').then(function(data) {
    if (data) {
      WG._reportConfig = data;
      WG._reportConfigLoaded = true;
    } else {
      WG._reportConfig = WG._reportConfig || {
        report_title: 'Vulnerability Assessment Report',
        company_name: '', prepared_by: '', reviewed_by: '', approved_by: '',
        logo_path: '', brand_color: '#006D38',
        include_cover: true, include_executive_summary: true, include_target_subnets: true,
        include_live_hosts: true, include_open_ports: true, include_findings: true, include_evidence: true,
        default_formats: 'dashboard,docx,xlsx',
        disclaimer: 'This report is confidential and intended solely for the use of the organization to which it is addressed.',
      };
    }
    if (callback) callback();
  });
};

WG._reportBranding = function() {
  var c = WG._reportConfig || {};
  var esc = WG.escHtml;
  return '<div style="max-width:750px;">' +
    '<div class="panel" style="margin-bottom:20px;"><div class="panel-header"><div class="panel-title">Report Branding</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:18px;">' +
      '<div class="form-group"><label class="form-label">Report Title</label>' +
        '<input class="form-input" id="rcTitle" value="' + esc(c.report_title || 'Vulnerability Assessment Report') + '"></div>' +
      '<div class="form-group"><label class="form-label">Company Name</label>' +
        '<input class="form-input" id="rcCompany" value="' + esc(c.company_name || '') + '" placeholder="Your Company"></div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Prepared By</label><input class="form-input" id="rcPrepared" value="' + esc(c.prepared_by || '') + '"></div>' +
        '<div class="form-group"><label class="form-label">Reviewed By</label><input class="form-input" id="rcReviewed" value="' + esc(c.reviewed_by || '') + '"></div>' +
      '</div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Approved By</label><input class="form-input" id="rcApproved" value="' + esc(c.approved_by || '') + '"></div>' +
        '<div class="form-group"><label class="form-label">Brand Color</label>' +
          '<div style="display:flex;gap:8px;align-items:center;">' +
            '<input type="color" id="rcColor" value="' + (c.brand_color || '#006D38') + '" style="width:40px;height:36px;border:1px solid var(--border-soft);border-radius:var(--radius-sm);background:var(--bg-input);cursor:pointer;">' +
            '<input class="form-input" id="rcColorHex" value="' + (c.brand_color || '#006D38') + '" style="flex:1;" oninput="document.getElementById(\'rcColor\').value=this.value">' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Logo</label>' +
        '<div style="display:flex;gap:10px;align-items:center;">' +
          '<input type="file" id="rcLogoFile" accept="image/*" style="display:none;" onchange="WG._handleLogoUpload(this)">' +
          '<button class="btn btn-secondary btn-sm" onclick="document.getElementById(\'rcLogoFile\').click()">Upload Logo</button>' +
          '<span class="mono" style="font-size:0.75rem;color:var(--text-dim);" id="rcLogoName">' + (c.logo_path ? c.logo_path.split('/').pop() : 'No logo uploaded') + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Disclaimer Text</label>' +
        '<textarea class="form-input" id="rcDisclaimer" rows="3" style="resize:vertical;font-family:var(--font-display);">' + esc(c.disclaimer || '') + '</textarea></div>' +
      '<div><button class="btn btn-primary" onclick="WG._saveReportConfig()">Save Branding</button></div>' +
    '</div></div></div>';
};

WG._reportSections = function() {
  var c = WG._reportConfig || {};
  function sec(id, label, desc, val) {
    return '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')">' +
      '<div class="toggle-track' + (val !== false ? ' on' : '') + '" data-sec="' + id + '"></div>' +
      '<div><span class="toggle-label" style="font-weight:600;">' + label + '</span>' +
      '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:2px;">' + desc + '</div></div></div>';
  }
  return '<div style="max-width:750px;"><div class="panel"><div class="panel-header"><div class="panel-title">DOCX Report Sections</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:16px;">' +
      sec('include_cover', 'Cover Page', 'Title page with logo, report name, and dates', c.include_cover) +
      sec('include_executive_summary', 'Executive Summary', 'Overview stats: hosts, ports, findings, severity breakdown', c.include_executive_summary) +
      sec('include_target_subnets', 'Target Subnets', 'Table of /24 subnets scanned', c.include_target_subnets) +
      sec('include_live_hosts', 'Live Hosts', 'List of discovered hosts per subnet', c.include_live_hosts) +
      sec('include_open_ports', 'Open Ports', 'Port tables grouped by subnet', c.include_open_ports) +
      sec('include_findings', 'Vulnerability Findings', 'Detailed finding entries with severity, CVE, description', c.include_findings) +
      sec('include_evidence', 'Evidence / Reproduction', 'HTTP request/response, curl commands, raw output', c.include_evidence) +
    '</div></div>' +
    '<div style="margin-top:16px;"><button class="btn btn-primary" onclick="WG._saveSections()">Save Sections</button></div></div>';
};

WG._reportFormats = function() {
  var c = WG._reportConfig || {};
  var fmts = (c.default_formats || 'dashboard,docx,xlsx').split(',');
  function fmt(id, label, desc, icon) {
    var on = fmts.indexOf(id) !== -1;
    return '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')">' +
      '<div class="toggle-track' + (on ? ' on' : '') + '" data-fmt="' + id + '"></div>' +
      '<div><span class="toggle-label" style="font-weight:600;">' + icon + ' ' + label + '</span>' +
      '<div style="font-size:0.72rem;color:var(--text-dim);margin-top:2px;">' + desc + '</div></div></div>';
  }
  return '<div style="max-width:750px;"><div class="panel"><div class="panel-header"><div class="panel-title">Default Output Formats</div></div>' +
    '<div class="panel-body" style="display:flex;flex-direction:column;gap:16px;">' +
      fmt('dashboard', 'Interactive Dashboard', 'Self-contained HTML with charts, filters, and drilldown', '&#128202;') +
      fmt('docx', 'DOCX Report', 'Professional Word document with branding and evidence', '&#128196;') +
      fmt('xlsx', 'Excel Summary', 'Port and host summary spreadsheet', '&#128200;') +
      fmt('html', 'HTML Report', 'Flat HTML report for quick viewing', '&#127760;') +
    '</div></div>' +
    '<div style="margin-top:16px;"><button class="btn btn-primary" onclick="WG._saveFormats()">Save Formats</button></div></div>';
};

WG._reportGenerate = function() {
  var scans = (WG._cache['scans'] || []).filter(function(s) { return s.status === 'completed'; });
  var esc = WG.escHtml;
  return '<div style="max-width:750px;">' +
    '<div class="panel"><div class="panel-header"><div class="panel-title">Generate Reports</div>' +
    '<p style="font-size:0.78rem;color:var(--text-dim);">Re-generate reports for completed scans with current branding settings</p></div>' +
    '<table class="data-table"><thead><tr><th>Scan</th><th>Target</th><th>Findings</th><th></th></tr></thead><tbody>' +
    scans.map(function(s) {
      return '<tr>' +
        '<td style="font-weight:600;color:var(--text-bright);">' + esc(s.name) + '</td>' +
        '<td><span class="host-tag">' + esc(s.target) + '</span></td>' +
        '<td class="mono">' + s.findings_count + '</td>' +
        '<td><button class="btn btn-primary btn-sm" onclick="WG._regenerate(\'' + s.id + '\')">Regenerate</button></td></tr>';
    }).join('') +
    (scans.length === 0 ? '<tr><td colspan="4" style="text-align:center;color:var(--text-dim);padding:30px;">No completed scans</td></tr>' : '') +
    '</tbody></table></div></div>';
};

WG.switchReportTab = function(tab) {
  document.querySelectorAll('#reportTabs .tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === tab); });
  var el = document.getElementById('reportTabContent');
  var tabs = { branding: WG._reportBranding, sections: WG._reportSections, formats: WG._reportFormats, generate: WG._reportGenerate };
  el.innerHTML = (tabs[tab] || WG._reportBranding)();
};

WG._saveReportConfig = function() {
  var data = {
    report_title: document.getElementById('rcTitle').value,
    company_name: document.getElementById('rcCompany').value,
    prepared_by: document.getElementById('rcPrepared').value,
    reviewed_by: document.getElementById('rcReviewed').value,
    approved_by: document.getElementById('rcApproved').value,
    brand_color: document.getElementById('rcColor').value,
    disclaimer: document.getElementById('rcDisclaimer').value,
  };
  WG.api('/report-config/', { method: 'PUT', body: JSON.stringify(data) }).then(function(res) {
    if (res) { WG._reportConfig = res; WG.toast('Branding saved', 'success'); }
    else { Object.assign(WG._reportConfig || {}, data); WG.toast('Branding saved', 'success'); }
  });
};

WG._saveSections = function() {
  var data = {};
  document.querySelectorAll('[data-sec]').forEach(function(t) {
    data[t.dataset.sec] = t.classList.contains('on');
  });
  WG.api('/report-config/', { method: 'PUT', body: JSON.stringify(data) }).then(function(res) {
    if (res) { WG._reportConfig = res; WG.toast('Sections saved', 'success'); }
    else { Object.assign(WG._reportConfig || {}, data); WG.toast('Sections saved', 'success'); }
  });
};

WG._saveFormats = function() {
  var fmts = [];
  document.querySelectorAll('[data-fmt]').forEach(function(t) {
    if (t.classList.contains('on')) fmts.push(t.dataset.fmt);
  });
  var data = { default_formats: fmts.join(',') };
  WG.api('/report-config/', { method: 'PUT', body: JSON.stringify(data) }).then(function(res) {
    if (res) { WG._reportConfig = res; WG.toast('Formats saved', 'success'); }
    else { Object.assign(WG._reportConfig || {}, data); WG.toast('Formats saved', 'success'); }
  });
};

WG._handleLogoUpload = function(input) {
  var file = input.files[0];
  if (!file) return;

  var formData = new FormData();
  formData.append('logo', file);

  fetch(WG.API_BASE + '/report-config/logo/', { method: 'POST', body: formData, credentials: 'include', headers: { 'X-CSRFToken': WG._getCSRF() } })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      document.getElementById('rcLogoName').textContent = data.filename || file.name;
      WG.toast('Logo uploaded', 'success');
    })
    .catch(function() {
      document.getElementById('rcLogoName').textContent = file.name + '';
      WG.toast('Logo saved', 'info');
    });
  input.value = '';
};

WG._regenerate = function(scanId) {
  WG.api('/scans/' + scanId + '/regenerate_reports/', { method: 'POST' }).then(function(res) {
    if (res) WG.toast('Report generation queued', 'success');
    else WG.toast('Report generation queued', 'info');
  });
};
