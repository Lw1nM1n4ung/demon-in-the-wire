/* Wire_Ghost — Scan Policies (API-backed with mock fallback) */

WG.MOCK_POLICIES = [
  { id: '0196aaab-0001-7000-8000-000000000001', name: 'Full Assessment', description: 'All scanners enabled — maximum depth and coverage', scan_type: 'full', parallelism: 10, timeout: 3600, port_range: '1-65535', tools: { nmap: true, nuclei: true, dirsearch: true, searchsploit: true, wpscan: true, service_enum: true, openvas: false }, version_detect: true, os_detect: true, severity_filter: 'all', report_formats: 'dashboard,docx,xlsx', is_default: true, created_at: '2026-03-15T10:00:00Z' },
  { id: '0196aaab-0001-7000-8000-000000000002', name: 'Quick Recon', description: 'Fast port scan + nuclei critical/high only for rapid triage', scan_type: 'quick', parallelism: 20, timeout: 1800, port_range: '1-10000', tools: { nmap: true, nuclei: true, dirsearch: false, searchsploit: false, wpscan: false, service_enum: false, openvas: false }, version_detect: true, os_detect: false, severity_filter: 'critical,high', report_formats: 'dashboard', is_default: false, created_at: '2026-03-20T14:00:00Z' },
  { id: '0196aaab-0001-7000-8000-000000000003', name: 'Web Application', description: 'Web-focused scanning with directory brute force and CMS detection', scan_type: 'web', parallelism: 10, timeout: 5400, port_range: '80,443,8080,8443,8000,3000', tools: { nmap: true, nuclei: true, dirsearch: true, searchsploit: false, wpscan: true, service_enum: false, openvas: false }, version_detect: true, os_detect: false, severity_filter: 'all', report_formats: 'dashboard,docx', is_default: false, created_at: '2026-04-01T09:00:00Z' },
  { id: '0196aaab-0001-7000-8000-000000000004', name: 'Service Audit', description: 'Service enumeration — check default creds, banners, misconfigs', scan_type: 'service', parallelism: 5, timeout: 2400, port_range: '1-65535', tools: { nmap: true, nuclei: false, dirsearch: false, searchsploit: true, wpscan: false, service_enum: true, openvas: false }, version_detect: true, os_detect: true, severity_filter: 'all', report_formats: 'dashboard,xlsx', is_default: false, created_at: '2026-04-05T11:00:00Z' },
  { id: '0196aaab-0001-7000-8000-000000000005', name: 'Stealth Scan', description: 'SYN scan only, no scripts, low parallelism for quiet recon', scan_type: 'port', parallelism: 2, timeout: 7200, port_range: '1-10000', tools: { nmap: true, nuclei: false, dirsearch: false, searchsploit: false, wpscan: false, service_enum: false, openvas: false }, version_detect: false, os_detect: false, severity_filter: 'all', report_formats: 'xlsx', is_default: false, created_at: '2026-04-08T16:00:00Z' },
];

WG._getPolicies = function() {
  var data = WG.getCached('policies', '/policies/', 'policies');
  return (data && data.length) ? data : WG.MOCK_POLICIES;
};

WG.renderPolicies = function() {
  var policies = WG._getPolicies();
  // Background refresh from API
  WG.fetchData('/policies/', 'policies').then(function(data) {
    if (data && data.length && WG.state.currentPage === 'policies') {
      WG._cache['policies'] = data; WG._cacheTime['policies'] = Date.now();
      var main = document.getElementById('mainContent');
      if (main) main.innerHTML = WG.renderPolicies();
    }
  });
  var esc = WG.escHtml;
  var toolNames = ['nmap','nuclei','dirsearch','searchsploit','wpscan','service_enum','openvas'];

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Scan Policies</h1><p>' + policies.length + ' policy templates</p></div>' +
    '<div class="page-header-actions"><button class="btn btn-primary" onclick="WG.openPolicyEditor()"><span>+</span> New Policy</button></div></div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px;">' +
      '<div class="stat-card"><div class="stat-label">Total Policies</div><div class="stat-value">' + policies.length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Full Scans</div><div class="stat-value">' + policies.filter(function(p) { return p.scan_type === 'full'; }).length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Web Scans</div><div class="stat-value">' + policies.filter(function(p) { return p.scan_type === 'web'; }).length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Quick Scans</div><div class="stat-value">' + policies.filter(function(p) { return p.scan_type === 'quick'; }).length + '</div></div>' +
    '</div>' +

    '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px;">' +
    policies.map(function(p) {
      var tools = p.tools || {};
      var enabledTools = toolNames.filter(function(t) { return tools[t]; });
      return '<div class="panel policy-card">' +
        '<div class="panel-body">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">' +
            '<div style="flex:1;">' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">' +
                '<span style="font-weight:700;color:var(--text-bright);font-size:0.95rem;">' + esc(p.name) + '</span>' +
                (p.is_default ? '<span class="tag" style="font-size:0.55rem;background:var(--accent-dim);color:var(--accent);border-color:var(--border-active);">DEFAULT</span>' : '') +
              '</div>' +
              '<div style="font-size:0.78rem;color:var(--text-dim);line-height:1.5;">' + esc(p.description || '') + '</div>' +
            '</div>' +
            '<span class="tag" style="flex-shrink:0;margin-left:10px;">' + esc(p.scan_type) + '</span>' +
          '</div>' +
          '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">' +
            enabledTools.map(function(t) { return '<span class="tag" style="font-size:0.62rem;">' + esc(t) + '</span>'; }).join('') +
          '</div>' +
          '<div style="display:flex;gap:16px;font-family:var(--font-mono);font-size:0.68rem;color:var(--text-dim);margin-bottom:14px;">' +
            '<span>Threads: ' + parseInt(p.parallelism) + '</span>' +
            '<span>Timeout: ' + WG.fmtDuration(p.timeout) + '</span>' +
            '<span>Ports: ' + esc((p.port_range || '').length > 15 ? p.port_range.substring(0, 15) + '...' : (p.port_range || '')) + '</span>' +
          '</div>' +
          '<div style="display:flex;gap:8px;border-top:1px solid var(--border-dim);padding-top:12px;">' +
            '<button class="btn btn-secondary btn-sm" style="flex:1;" onclick="WG._launchWithPolicy(\'' + p.id + '\')">Use Policy</button>' +
            '<button class="btn btn-ghost btn-sm" onclick="WG.openPolicyEditor(\'' + p.id + '\')">Edit</button>' +
            '<button class="btn btn-ghost btn-sm" onclick="WG._clonePolicy(\'' + p.id + '\')">Clone</button>' +
            (!p.is_default ? '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG._deletePolicy(\'' + p.id + '\')">Del</button>' : '') +
          '</div>' +
        '</div></div>';
    }).join('') +
    '</div>' +

    /* Policy editor modal — all values set via JS, no user content in template */
    '<div class="modal-overlay" id="policyModal"><div class="modal" style="width:620px;"><div class="modal-header"><h2 id="policyModalTitle">New Policy</h2><p id="policyModalDesc">Create a scan policy template</p></div>' +
    '<div class="modal-body">' +
      '<input type="hidden" id="policyEditId" value="">' +
      '<div class="form-row"><div class="form-group"><label class="form-label">Policy Name</label><input class="form-input" id="policyName" placeholder="My Policy"></div>' +
      '<div class="form-group"><label class="form-label">Scan Type</label><select class="form-select" id="policyScanType"><option value="full">Full Scan</option><option value="quick">Quick Scan</option><option value="port">Port Scan</option><option value="web">Web App</option><option value="service">Service Enum</option></select></div></div>' +
      '<div class="form-group"><label class="form-label">Description</label><input class="form-input" id="policyDesc" placeholder="What this policy does"></div>' +
      '<div class="form-row"><div class="form-group"><label class="form-label">Parallelism</label><input class="form-input" id="policyParallel" type="number" value="10"></div>' +
      '<div class="form-group"><label class="form-label">Timeout (sec)</label><input class="form-input" id="policyTimeout" type="number" value="3600"></div></div>' +
      '<div class="form-group"><label class="form-label">Port Range</label><input class="form-input" id="policyPorts" value="1-65535" placeholder="1-65535 or 80,443,8080"></div>' +
      '<div class="form-group"><label class="form-label">Severity Filter</label><select class="form-select" id="policySevFilter"><option value="all">All Severities</option><option value="critical,high">Critical + High only</option><option value="critical,high,medium">Critical + High + Medium</option></select></div>' +
      '<div class="form-group"><label class="form-label" style="margin-bottom:10px;">Tools</label>' +
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;" id="policyTools">' +
          ['nmap','nuclei','dirsearch','searchsploit','wpscan','service_enum','openvas'].map(function(t) {
            return '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on" data-tool="' + t + '"></div><span class="toggle-label">' + t + '</span></div>';
          }).join('') +
        '</div></div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">' +
        '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on" id="policyVersionDetect"></div><span class="toggle-label">Version Detection</span></div>' +
        '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on" id="policyOsDetect"></div><span class="toggle-label">OS Detection</span></div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">Report Formats</label><input class="form-input" id="policyReportFmt" value="dashboard,docx,xlsx" placeholder="dashboard,docx,xlsx"></div>' +
      '<div class="form-group"><label class="form-label">Nuclei External Templates (optional)</label><input class="form-input" id="policyNucleiTemplates" placeholder="/opt/nuclei-templates/custom/" style="font-family:var(--font-mono);font-size:0.82rem;"></div>' +
      '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on" id="policyNucleiDefaults"></div><span class="toggle-label">Include default nuclei templates</span></div>' +
    '</div>' +
    '<div class="modal-footer"><button class="btn btn-secondary" onclick="WG.closeModal(\'policyModal\')">Cancel</button><button class="btn btn-primary" onclick="WG._savePolicy()">Save Policy</button></div></div></div>';
};

WG.openPolicyEditor = function(id) {
  var title = document.getElementById('policyModalTitle');
  var desc = document.getElementById('policyModalDesc');
  if (id) {
    var policies = WG._getPolicies();
    var p = policies.find(function(x) { return x.id === id; });
    if (!p) return;
    title.textContent = 'Edit Policy';
    desc.textContent = 'Modify policy settings';
    document.getElementById('policyEditId').value = id;
    document.getElementById('policyName').value = p.name;
    document.getElementById('policyScanType').value = p.scan_type;
    document.getElementById('policyDesc').value = p.description || '';
    document.getElementById('policyParallel').value = p.parallelism;
    document.getElementById('policyTimeout').value = p.timeout;
    document.getElementById('policyPorts').value = p.port_range || '1-65535';
    document.getElementById('policySevFilter').value = p.severity_filter || 'all';
    document.getElementById('policyReportFmt').value = p.report_formats || 'dashboard,docx,xlsx';
    document.getElementById('policyVersionDetect').classList.toggle('on', p.version_detect);
    document.getElementById('policyOsDetect').classList.toggle('on', p.os_detect);
    var tools = p.tools || {};
    document.querySelectorAll('#policyTools [data-tool]').forEach(function(t) {
      t.classList.toggle('on', !!tools[t.dataset.tool]);
    });
    document.getElementById('policyNucleiTemplates').value = (tools.nuclei_templates) || '';
    document.getElementById('policyNucleiDefaults').classList.toggle('on', tools.nuclei_default_templates !== false);
  } else {
    title.textContent = 'New Policy';
    desc.textContent = 'Create a scan policy template';
    document.getElementById('policyEditId').value = '';
    document.getElementById('policyName').value = '';
    document.getElementById('policyDesc').value = '';
    document.getElementById('policyParallel').value = '10';
    document.getElementById('policyTimeout').value = '3600';
    document.getElementById('policyPorts').value = '1-65535';
    document.getElementById('policySevFilter').value = 'all';
    document.getElementById('policyReportFmt').value = 'dashboard,docx,xlsx';
    document.getElementById('policyVersionDetect').classList.add('on');
    document.getElementById('policyOsDetect').classList.add('on');
    document.querySelectorAll('#policyTools [data-tool]').forEach(function(t) { t.classList.add('on'); });
    document.getElementById('policyNucleiTemplates').value = '';
    document.getElementById('policyNucleiDefaults').classList.add('on');
  }
  WG.openModal('policyModal');
};

WG._savePolicy = function() {
  var editId = document.getElementById('policyEditId').value;
  var name = document.getElementById('policyName').value.trim();
  if (!name) { WG.toast('Policy name required', 'error'); return; }

  var tools = {};
  document.querySelectorAll('#policyTools [data-tool]').forEach(function(t) { tools[t.dataset.tool] = t.classList.contains('on'); });
  tools.nuclei_templates = (document.getElementById('policyNucleiTemplates').value || '').trim();
  tools.nuclei_default_templates = document.getElementById('policyNucleiDefaults').classList.contains('on');

  var data = {
    name: name,
    description: document.getElementById('policyDesc').value.trim(),
    scan_type: document.getElementById('policyScanType').value,
    parallelism: parseInt(document.getElementById('policyParallel').value) || 10,
    timeout: parseInt(document.getElementById('policyTimeout').value) || 3600,
    port_range: document.getElementById('policyPorts').value.trim() || '1-65535',
    tools: tools,
    version_detect: document.getElementById('policyVersionDetect').classList.contains('on'),
    os_detect: document.getElementById('policyOsDetect').classList.contains('on'),
    severity_filter: document.getElementById('policySevFilter').value,
    report_formats: document.getElementById('policyReportFmt').value.trim(),
  };

  if (editId) {
    WG.api('/policies/' + editId + '/', { method: 'PUT', body: JSON.stringify(data) }).then(function(res) {
      if (res && !res.error) {
        WG.invalidateCache('policies');
        WG.toast('Policy updated: ' + name, 'success');
        WG.closeModal('policyModal');
        WG.render();
      } else {
        WG.toast('Failed to update policy', 'error');
      }
    });
  } else {
    WG.api('/policies/', { method: 'POST', body: JSON.stringify(data) }).then(function(res) {
      if (res && res.id) {
        WG.invalidateCache('policies');
        WG.toast('Policy created: ' + name, 'success');
        WG.closeModal('policyModal');
        WG.render();
      } else {
        WG.toast('Failed to create policy', 'error');
      }
    });
  }
};

WG._clonePolicy = function(id) {
  WG.api('/policies/' + id + '/clone/', { method: 'POST' }).then(function(res) {
    if (res && res.id) {
      WG.invalidateCache('policies');
      WG.toast('Cloned: ' + res.name, 'success');
      WG.render();
    } else {
      WG.toast('Failed to clone policy', 'error');
    }
  });
};

WG._deletePolicy = function(id) {
  WG.api('/policies/' + id + '/', { method: 'DELETE' }).then(function() {
    WG.invalidateCache('policies');
    WG.toast('Policy deleted', 'info');
    WG.render();
  });
};

WG._launchWithPolicy = function(id) {
  var policies = WG._getPolicies();
  var p = policies.find(function(x) { return x.id === id; });
  if (!p) return;
  WG.navigate('new-scan');
  setTimeout(function() {
    var el = document.getElementById('nsScanType');
    if (el) { el.value = p.scan_type; WG._nsUpdateType(p.scan_type); }
    var par = document.getElementById('nsParallelism');
    if (par) par.value = p.parallelism;
    var to = document.getElementById('nsTimeout');
    if (to) to.value = p.timeout;
    var pr = document.getElementById('nsPortRange');
    if (pr) pr.value = p.port_range || '1-65535';
    var rf = document.getElementById('nsReportFmt');
    if (rf) rf.value = p.report_formats || 'dashboard,docx,xlsx';
    document.getElementById('nsVersionDetect').classList.toggle('on', p.version_detect);
    document.getElementById('nsOsDetect').classList.toggle('on', p.os_detect);
    var tools = p.tools || {};
    document.querySelectorAll('#nsTools [data-tool]').forEach(function(t) {
      t.classList.toggle('on', !!tools[t.dataset.tool]);
    });
    var nt = document.getElementById('nsNucleiTemplates');
    if (nt) nt.value = (tools.nuclei_templates) || '';
    var nd = document.getElementById('nsNucleiDefaults');
    if (nd) nd.classList.toggle('on', tools.nuclei_default_templates !== false);
    WG.toast('Applied policy: ' + p.name, 'success');
  }, 150);
};
