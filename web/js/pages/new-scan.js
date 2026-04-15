/* Wire_Ghost — New Scan (full page) */

WG.renderNewScan = function() {
  var policies = (typeof WG.MOCK_POLICIES !== 'undefined') ? WG.MOCK_POLICIES : [];
  var esc = WG.escHtml;

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>New Scan</h1><p>Configure and launch a vulnerability assessment</p></div></div>' +

    '<div style="display:grid;grid-template-columns:1fr 340px;gap:20px;">' +

      /* Left column — scan config */
      '<div>' +
        /* Target */
        '<div class="panel" style="margin-bottom:16px;">' +
          '<div class="panel-header"><div class="panel-title">Target</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:14px;">' +
            '<div class="form-group"><label class="form-label">Target (IP, CIDR, or hostname)</label>' +
              '<input class="form-input" id="nsScanTarget" placeholder="192.168.1.0/24 or domain.com" style="font-size:1rem;padding:12px;" oninput="WG._nsCheckPartition(this.value)">' +
              '<div id="nsPartitionInfo" style="font-size:0.72rem;margin-top:4px;color:var(--text-dim);"></div></div>' +
            '<div class="form-group"><label class="form-label">Scan Name</label>' +
              '<input class="form-input" id="nsScanName" placeholder="Internal Network Assessment"></div>' +
            '<div class="form-group"><label class="form-label">Target List (one per line, optional)</label>' +
              '<textarea class="form-input" id="nsTargetList" rows="4" style="resize:vertical;font-family:var(--font-mono);font-size:0.78rem;" placeholder="192.168.1.0/24&#10;10.20.150.0/24&#10;app.example.com"></textarea>' +
              '<div style="font-size:0.68rem;color:var(--text-dim);margin-top:4px;">If provided, each line is scanned separately as a batch.</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        /* Scan Type & Options */
        '<div class="panel" style="margin-bottom:16px;">' +
          '<div class="panel-header"><div class="panel-title">Scan Configuration</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:14px;">' +
            '<div class="form-row">' +
              '<div class="form-group"><label class="form-label">Scan Type</label>' +
                '<select class="form-select" id="nsScanType" onchange="WG._nsUpdateType(this.value)"><option value="full">Full Scan (All Tools)</option><option value="quick">Quick Scan (Nmap + Nuclei)</option><option value="port">Port Scan Only</option><option value="web">Web Application Scan</option><option value="service">Service Enumeration</option></select></div>' +
              '<div class="form-group"><label class="form-label">Port Range</label>' +
                '<input class="form-input" id="nsPortRange" value="1-65535" placeholder="1-65535"></div>' +
            '</div>' +
            '<div class="form-row">' +
              '<div class="form-group"><label class="form-label">Parallelism</label>' +
                '<input class="form-input" id="nsParallelism" type="number" value="10" min="1" max="100"></div>' +
              '<div class="form-group"><label class="form-label">Timeout (seconds)</label>' +
                '<input class="form-input" id="nsTimeout" type="number" value="3600"></div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        /* Tools */
        '<div class="panel" style="margin-bottom:16px;">' +
          '<div class="panel-header"><div class="panel-title">Tools</div></div>' +
          '<div class="panel-body">' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;" id="nsTools">' +
              WG._nsToolToggle('nmap', 'Nmap', 'Port scanner & service detection', true) +
              WG._nsToolToggle('nuclei', 'Nuclei', 'Template-based vuln scanner', true) +
              WG._nsToolToggle('dirsearch', 'Dirsearch', 'Directory brute-force', true) +
              WG._nsToolToggle('searchsploit', 'Searchsploit', 'Exploit DB search', true) +
              WG._nsToolToggle('wpscan', 'WPScan', 'WordPress scanner', false) +
              WG._nsToolToggle('service_enum', 'Service Enum', 'Default cred checks', true) +
              WG._nsToolToggle('openvas', 'OpenVAS', 'Full vulnerability assessment', false) +
            '</div>' +
          '</div>' +
        '</div>' +

        /* Detection */
        '<div class="panel" style="margin-bottom:16px;">' +
          '<div class="panel-header"><div class="panel-title">Detection & Reporting</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:10px;">' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">' +
              '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on" id="nsVersionDetect"></div><span class="toggle-label">Version Detection (-sV)</span></div>' +
              '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')"><div class="toggle-track on" id="nsOsDetect"></div><span class="toggle-label">OS Detection (-O)</span></div>' +
            '</div>' +
            '<div class="form-row" style="margin-top:8px;">' +
              '<div class="form-group"><label class="form-label">Report Formats</label>' +
                '<select class="form-select" id="nsReportFmt"><option value="dashboard,docx,xlsx">Dashboard + DOCX + XLSX</option><option value="dashboard">Dashboard Only</option><option value="docx">DOCX Only</option><option value="dashboard,docx,xlsx,html">All Formats</option></select></div>' +
              '<div class="form-group"><label class="form-label">Severity Filter</label>' +
                '<select class="form-select" id="nsSevFilter"><option value="all">All Severities</option><option value="critical,high">Critical + High only</option><option value="critical,high,medium">Critical + High + Medium</option></select></div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      /* Right column — policy quick-select & launch */
      '<div>' +
        '<div class="panel" style="margin-bottom:16px;">' +
          '<div class="panel-header"><div class="panel-title">Quick Start — Policy</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:8px;">' +
            policies.map(function(p) {
              return '<div class="ns-policy-card" onclick="WG._nsApplyPolicy(\'' + p.id + '\')" style="cursor:pointer;padding:10px 12px;border:1px solid var(--border-dim);border-radius:var(--radius-md);transition:all 0.15s;">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;">' +
                  '<span style="font-weight:600;font-size:0.85rem;color:var(--text-bright);">' + esc(p.name) + '</span>' +
                  '<span class="tag" style="font-size:0.6rem;">' + p.scan_type + '</span>' +
                '</div>' +
                '<div style="font-size:0.7rem;color:var(--text-dim);margin-top:3px;">' + esc(p.description).substring(0, 60) + '</div>' +
              '</div>';
            }).join('') +
            (!policies.length ? '<div style="color:var(--text-dim);font-size:0.82rem;text-align:center;padding:16px;">No policies yet</div>' : '') +
          '</div>' +
        '</div>' +

        /* Schedule option */
        '<div class="panel" style="margin-bottom:16px;">' +
          '<div class="panel-header"><div class="panel-title">Schedule (optional)</div></div>' +
          '<div class="panel-body" style="display:flex;flex-direction:column;gap:10px;">' +
            '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\');WG._nsToggleSchedule()">' +
              '<div class="toggle-track" id="nsScheduleEnabled"></div><span class="toggle-label">Enable recurring scan</span></div>' +
            '<div id="nsScheduleOpts" style="display:none;">' +
              '<div class="form-group"><label class="form-label">Frequency</label>' +
                '<select class="form-select" id="nsScheduleFreq"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="biweekly">Every 2 Weeks</option><option value="monthly">Monthly</option></select></div>' +
              '<div class="form-group"><label class="form-label">Start Time</label>' +
                '<input class="form-input" id="nsScheduleTime" type="time" value="02:00"></div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        /* Launch button */
        '<button class="btn btn-primary" style="width:100%;padding:14px;font-size:0.95rem;justify-content:center;" onclick="WG._nsLaunch()">' +
          '<span>&#9654;</span> Launch Scan' +
        '</button>' +
        '<div id="nsLaunchStatus" style="margin-top:10px;text-align:center;"></div>' +
      '</div>' +
    '</div>';
};

WG._nsToolToggle = function(id, name, desc, on) {
  return '<div class="form-toggle" onclick="this.querySelector(\'.toggle-track\').classList.toggle(\'on\')" style="padding:8px 0;">' +
    '<div class="toggle-track' + (on ? ' on' : '') + '" data-tool="' + id + '"></div>' +
    '<div><span class="toggle-label" style="font-weight:600;">' + name + '</span>' +
    '<div style="font-size:0.65rem;color:var(--text-dim);">' + desc + '</div></div></div>';
};

WG._nsToggleSchedule = function() {
  var el = document.getElementById('nsScheduleOpts');
  var on = document.getElementById('nsScheduleEnabled').classList.contains('on');
  if (el) el.style.display = on ? 'flex' : 'none';
  if (el) el.style.flexDirection = 'column';
  if (el) el.style.gap = '10px';
};

WG._nsCheckPartition = function(val) {
  var el = document.getElementById('nsPartitionInfo');
  if (!el) return;
  val = (val || '').trim();
  var m = val.match(/\/(\d+)$/);
  if (m) {
    var prefix = parseInt(m[1]);
    if (prefix <= 23 && prefix >= 8) {
      var count = Math.pow(2, 24 - prefix);
      el.textContent = '\u26A1 Large target — will be auto-split into ' + count + ' /24 subnets and scanned in parallel';
      el.style.color = 'var(--accent)';
      return;
    }
  }
  el.textContent = '';
};

WG._nsUpdateType = function(type) {
  var presets = {
    full: { ports: '1-65535', parallel: 10, tools: ['nmap','nuclei','dirsearch','searchsploit','service_enum'] },
    quick: { ports: '1-10000', parallel: 20, tools: ['nmap','nuclei'] },
    port: { ports: '1-65535', parallel: 10, tools: ['nmap'] },
    web: { ports: '80,443,8080,8443,8000,3000', parallel: 10, tools: ['nmap','nuclei','dirsearch','wpscan'] },
    service: { ports: '1-65535', parallel: 5, tools: ['nmap','searchsploit','service_enum'] },
  };
  var p = presets[type] || presets.full;
  document.getElementById('nsPortRange').value = p.ports;
  document.getElementById('nsParallelism').value = p.parallel;
  document.querySelectorAll('#nsTools [data-tool]').forEach(function(t) {
    t.classList.toggle('on', p.tools.indexOf(t.dataset.tool) !== -1);
  });
};

WG._nsApplyPolicy = function(id) {
  var p = (typeof WG.MOCK_POLICIES !== 'undefined') ? WG.MOCK_POLICIES.find(function(x) { return x.id === id; }) : null;
  if (!p) return;
  document.getElementById('nsScanType').value = p.scan_type;
  document.getElementById('nsPortRange').value = p.port_range;
  document.getElementById('nsParallelism').value = p.parallelism;
  document.getElementById('nsTimeout').value = p.timeout;
  document.getElementById('nsReportFmt').value = p.report_formats;
  document.getElementById('nsVersionDetect').classList.toggle('on', p.version_detect);
  document.getElementById('nsOsDetect').classList.toggle('on', p.os_detect);
  document.querySelectorAll('#nsTools [data-tool]').forEach(function(t) {
    t.classList.toggle('on', !!p.tools[t.dataset.tool]);
  });
  WG.toast('Applied policy: ' + p.name, 'success');
};

WG._nsLaunch = function() {
  var target = (document.getElementById('nsScanTarget').value || '').trim();
  var targetList = (document.getElementById('nsTargetList').value || '').trim();
  var name = (document.getElementById('nsScanName').value || '').trim();

  // Collect targets
  var targets = [];
  if (target) targets.push(target);
  if (targetList) {
    targetList.split('\n').forEach(function(line) {
      line = line.trim();
      if (line && targets.indexOf(line) === -1) targets.push(line);
    });
  }
  if (!targets.length) { WG.toast('Enter at least one target', 'error'); return; }

  var scanData = {
    scan_type: document.getElementById('nsScanType').value,
    parallelism: parseInt(document.getElementById('nsParallelism').value) || 10,
    timeout: parseInt(document.getElementById('nsTimeout').value) || 3600,
    report_formats: document.getElementById('nsReportFmt').value,
    version_detect: document.getElementById('nsVersionDetect').classList.contains('on'),
    os_detect: document.getElementById('nsOsDetect').classList.contains('on'),
    service_enum: !!document.querySelector('#nsTools [data-tool="service_enum"].on'),
    skip_nuclei: !document.querySelector('#nsTools [data-tool="nuclei"].on'),
  };

  // Check if scheduled
  var scheduled = document.getElementById('nsScheduleEnabled').classList.contains('on');
  if (scheduled) {
    var freq = document.getElementById('nsScheduleFreq').value;
    var time = document.getElementById('nsScheduleTime').value;
    targets.forEach(function(t) {
      WG.MOCK_SCHEDULES.push({
        id: WG.MOCK_SCHEDULES.length + 1,
        name: name || 'Scheduled: ' + t,
        target: t,
        frequency: freq,
        time: time,
        scan_type: scanData.scan_type,
        enabled: true,
        last_run: null,
        next_run: WG._calcNextRun(freq, time),
        created_at: new Date().toISOString(),
      });
    });
    WG.toast(targets.length + ' scheduled scan(s) created', 'success');
    WG.navigate('scheduled');
    return;
  }

  // Launch scan(s)
  var status = document.getElementById('nsLaunchStatus');
  status.innerHTML = '<div class="spinner" style="width:18px;height:18px;margin:0 auto;"></div>';

  var launched = 0;
  targets.forEach(function(t) {
    var data = Object.assign({}, scanData, { target: t, name: name || t });
    WG.api('/scans/', { method: 'POST', body: JSON.stringify(data) }).then(function(res) {
      launched++;
      if (launched === targets.length) {
        WG.invalidateCache('scans');
        WG.toast(targets.length + ' scan(s) launched', 'success');
        WG.navigate('scans');
      }
    });
  });

  // Also add to mock for demo mode
  if (WG.USE_MOCK) {
    targets.forEach(function(t) {
      WG.MOCK.scans.unshift({
        id: WG.MOCK.scans.length + 1, name: name || t, target: t,
        scan_type: scanData.scan_type, status: 'running', hosts_count: 0, ports_count: 0,
        findings_count: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0,
        duration_seconds: 0, created_at: new Date().toISOString(), started_at: new Date().toISOString(),
        completed_at: null, parallelism: scanData.parallelism, report_formats: scanData.report_formats,
      });
    });
    WG.toast(targets.length + ' scan(s) launched (demo)', 'success');
    WG.navigate('scans');
  }
};
