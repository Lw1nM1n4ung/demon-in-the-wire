/* Wire_Ghost — Reports page */

WG._demoReports = function() {
  var now = Date.now();
  var d1 = new Date(now - 2 * 86400000).toISOString();
  var d2 = new Date(now - 5 * 86400000).toISOString();
  var d3 = new Date(now - 12 * 86400000).toISOString();
  return [
    { id: 'demo-r1', _scanName: 'Corporate Network Assessment', format: 'docx', _file: 'corporate-network_report.docx', file_size: 2457600, created_at: d1, _demo: true },
    { id: 'demo-r2', _scanName: 'Corporate Network Assessment', format: 'xlsx', _file: 'corporate-network_findings.xlsx', file_size: 845312, created_at: d1, _demo: true },
    { id: 'demo-r3', _scanName: 'Corporate Network Assessment', format: 'html', _file: 'corporate-network_report.html', file_size: 1536000, created_at: d1, _demo: true },
    { id: 'demo-r4', _scanName: 'Web App Pentest — api.acme.com', format: 'docx', _file: 'webapp-pentest_report.docx', file_size: 3145728, created_at: d2, _demo: true },
    { id: 'demo-r5', _scanName: 'Web App Pentest — api.acme.com', format: 'html', _file: 'webapp-pentest_report.html', file_size: 2097152, created_at: d2, _demo: true },
    { id: 'demo-r6', _scanName: 'DMZ Perimeter Scan', format: 'docx', _file: 'dmz-perimeter_report.docx', file_size: 1835008, created_at: d3, _demo: true },
    { id: 'demo-r7', _scanName: 'DMZ Perimeter Scan', format: 'xlsx', _file: 'dmz-perimeter_findings.xlsx', file_size: 524288, created_at: d3, _demo: true },
  ];
};

WG._demoFindings = function(scanName) {
  var sets = {
    'Corporate Network Assessment': [
      { sev: 'Critical', title: 'MS17-010 EternalBlue SMB RCE', host: '10.0.1.15', port: 445, cve: 'CVE-2017-0144', desc: 'Remote code execution via SMBv1. Allows unauthenticated attacker to execute arbitrary code on the target system.' },
      { sev: 'Critical', title: 'Apache Log4j RCE (Log4Shell)', host: '10.0.1.22', port: 8080, cve: 'CVE-2021-44228', desc: 'JNDI injection via Log4j allows remote code execution through crafted log messages.' },
      { sev: 'High', title: 'OpenSSH Pre-Auth Double Free', host: '10.0.1.10', port: 22, cve: 'CVE-2023-25136', desc: 'Double free vulnerability in OpenSSH server pre-authentication.' },
      { sev: 'High', title: 'Default SNMP Community String', host: '10.0.1.30', port: 161, cve: '', desc: 'SNMP service responds to "public" community string, exposing system information.' },
      { sev: 'High', title: 'SMB Signing Not Required', host: '10.0.1.15', port: 445, cve: '', desc: 'SMB signing is not enforced, enabling man-in-the-middle relay attacks.' },
      { sev: 'Medium', title: 'SSL/TLS Certificate Expired', host: '10.0.1.22', port: 443, cve: '', desc: 'The SSL certificate has expired, browsers will show security warnings.' },
      { sev: 'Medium', title: 'SSH Weak Key Exchange Algorithms', host: '10.0.1.10', port: 22, cve: '', desc: 'Server supports diffie-hellman-group1-sha1 which is considered weak.' },
      { sev: 'Low', title: 'ICMP Timestamp Response', host: '10.0.1.30', port: 0, cve: '', desc: 'Host responds to ICMP timestamp requests, disclosing system time.' },
    ],
    'Web App Pentest — api.acme.com': [
      { sev: 'Critical', title: 'SQL Injection in /api/users?id=', host: 'api.acme.com', port: 443, cve: 'CWE-89', desc: 'Unsanitized user input in query parameter allows UNION-based SQL injection with full database extraction.' },
      { sev: 'High', title: 'Broken Access Control — IDOR', host: 'api.acme.com', port: 443, cve: 'CWE-639', desc: 'Authenticated users can access other users\' records by changing the ID parameter.' },
      { sev: 'High', title: 'JWT Secret Weak (brute-forceable)', host: 'api.acme.com', port: 443, cve: 'CWE-347', desc: 'JWT tokens signed with a weak secret that can be brute-forced using hashcat.' },
      { sev: 'Medium', title: 'Missing Rate Limiting on Login', host: 'api.acme.com', port: 443, cve: 'CWE-307', desc: 'No rate limiting on /api/auth/login endpoint, enabling credential stuffing.' },
      { sev: 'Medium', title: 'Verbose Error Messages', host: 'api.acme.com', port: 443, cve: 'CWE-209', desc: 'Stack traces and internal paths disclosed in 500 error responses.' },
      { sev: 'Low', title: 'Missing X-Content-Type-Options', host: 'api.acme.com', port: 443, cve: '', desc: 'Response headers missing X-Content-Type-Options: nosniff.' },
    ],
    'DMZ Perimeter Scan': [
      { sev: 'High', title: 'Fortinet FortiOS Path Traversal', host: '203.0.113.1', port: 443, cve: 'CVE-2022-41328', desc: 'Path traversal in FortiOS allows reading arbitrary files on the firewall.' },
      { sev: 'High', title: 'DNS Zone Transfer Enabled', host: '203.0.113.10', port: 53, cve: '', desc: 'DNS server allows zone transfers (AXFR), exposing all DNS records.' },
      { sev: 'Medium', title: 'TLS 1.0 Supported', host: '203.0.113.5', port: 443, cve: '', desc: 'Server supports TLS 1.0 which has known cryptographic weaknesses.' },
      { sev: 'Medium', title: 'HTTP TRACE Method Enabled', host: '203.0.113.5', port: 80, cve: 'CWE-693', desc: 'TRACE method enabled on web server, potential for cross-site tracing.' },
      { sev: 'Low', title: 'HSTS Not Set', host: '203.0.113.5', port: 443, cve: '', desc: 'Strict-Transport-Security header not present in HTTPS responses.' },
    ],
  };
  return sets[scanName] || sets['Corporate Network Assessment'];
};

WG._demoPortSheet = function(scanName) {
  var sheets = {
    'Corporate Network Assessment': [
      { host: '10.0.1.5',  hostname: 'dc01.corp.local',     os: 'Windows Server 2019', ports: '53/tcp (dns), 88/tcp (kerberos), 135/tcp (msrpc), 389/tcp (ldap), 445/tcp (smb), 464/tcp (kpasswd), 636/tcp (ldaps), 3268/tcp (globalcatalog), 3389/tcp (rdp)' },
      { host: '10.0.1.10', hostname: 'dev-ssh.corp.local',  os: 'Ubuntu 22.04',        ports: '22/tcp (ssh), 80/tcp (http)' },
      { host: '10.0.1.15', hostname: 'filesvr.corp.local',  os: 'Windows Server 2016', ports: '135/tcp (msrpc), 139/tcp (netbios), 445/tcp (smb), 3389/tcp (rdp), 5985/tcp (winrm)' },
      { host: '10.0.1.20', hostname: 'mail.corp.local',     os: 'CentOS 7',            ports: '22/tcp (ssh), 25/tcp (smtp), 110/tcp (pop3), 143/tcp (imap), 993/tcp (imaps)' },
      { host: '10.0.1.22', hostname: 'app01.corp.local',    os: 'Ubuntu 20.04',        ports: '22/tcp (ssh), 80/tcp (http), 443/tcp (https), 8080/tcp (http-proxy), 8443/tcp (https-alt), 9090/tcp (prometheus)' },
      { host: '10.0.1.25', hostname: 'jenkins.corp.local',  os: 'Debian 11',           ports: '22/tcp (ssh), 8080/tcp (http-proxy), 50000/tcp (jenkins-agent)' },
      { host: '10.0.1.30', hostname: 'switch-mgmt',         os: 'Cisco IOS 15.2',      ports: '22/tcp (ssh), 161/udp (snmp), 443/tcp (https)' },
      { host: '10.0.1.40', hostname: 'db01.corp.local',     os: 'Ubuntu 22.04',        ports: '22/tcp (ssh), 3306/tcp (mysql), 33060/tcp (mysqlx)' },
      { host: '10.0.1.41', hostname: 'db02.corp.local',     os: 'Ubuntu 22.04',        ports: '22/tcp (ssh), 5432/tcp (postgresql)' },
      { host: '10.0.1.50', hostname: 'printer-floor3',      os: 'HP LaserJet FW',      ports: '80/tcp (http), 443/tcp (https), 515/tcp (lpd), 631/tcp (ipp), 9100/tcp (jetdirect)' },
      { host: '10.0.1.60', hostname: 'nas01.corp.local',    os: 'Synology DSM 7.1',    ports: '22/tcp (ssh), 80/tcp (http), 443/tcp (https), 445/tcp (smb), 5000/tcp (dsm), 5001/tcp (dsm-ssl)' },
    ],
    'Web App Pentest — api.acme.com': [
      { host: 'api.acme.com',   hostname: 'api.acme.com',   os: 'Linux (Nginx 1.24)',  ports: '80/tcp (http), 443/tcp (https), 8443/tcp (https-alt)' },
      { host: 'cdn.acme.com',   hostname: 'cdn.acme.com',   os: 'Cloudflare',          ports: '80/tcp (http), 443/tcp (https)' },
      { host: 'admin.acme.com', hostname: 'admin.acme.com', os: 'Linux (Nginx 1.24)',  ports: '443/tcp (https)' },
    ],
    'DMZ Perimeter Scan': [
      { host: '203.0.113.1',  hostname: 'fw01.dmz',    os: 'FortiOS 7.2',        ports: '22/tcp (ssh), 443/tcp (https), 541/tcp (fortigate)' },
      { host: '203.0.113.2',  hostname: 'fw02.dmz',    os: 'FortiOS 7.2',        ports: '22/tcp (ssh), 443/tcp (https), 541/tcp (fortigate)' },
      { host: '203.0.113.5',  hostname: 'web01.dmz',   os: 'Ubuntu 22.04',       ports: '22/tcp (ssh), 80/tcp (http), 443/tcp (https), 8080/tcp (http-proxy)' },
      { host: '203.0.113.6',  hostname: 'web02.dmz',   os: 'Ubuntu 22.04',       ports: '22/tcp (ssh), 80/tcp (http), 443/tcp (https)' },
      { host: '203.0.113.10', hostname: 'ns1.dmz',     os: 'Debian 12',          ports: '22/tcp (ssh), 53/tcp (dns), 53/udp (dns)' },
      { host: '203.0.113.11', hostname: 'ns2.dmz',     os: 'Debian 12',          ports: '22/tcp (ssh), 53/tcp (dns), 53/udp (dns)' },
      { host: '203.0.113.20', hostname: 'vpn.dmz',     os: 'OpenVPN AS 2.12',    ports: '22/tcp (ssh), 443/tcp (https), 1194/udp (openvpn)' },
      { host: '203.0.113.25', hostname: 'monitor.dmz', os: 'Debian 11',          ports: '22/tcp (ssh), 443/tcp (https), 3000/tcp (grafana), 9090/tcp (prometheus)' },
    ],
  };
  return sheets[scanName] || sheets['Corporate Network Assessment'];
};

WG._demoReportHtml = function(scanName, findings, date, forWord) {
  var esc = WG.escHtml;
  var portSheet = WG._demoPortSheet(scanName);
  var sevColor = { Critical: '#dc2626', High: '#ea580c', Medium: '#d97706', Low: '#2563eb' };
  var sevBg = { Critical: '#fef2f2', High: '#fff7ed', Medium: '#fffbeb', Low: '#eff6ff' };
  var counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(function(f) { counts[f.sev] = (counts[f.sev] || 0) + 1; });

  var wordMeta = forWord
    ? ' xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml"'
    : '';
  var wordXml = forWord
    ? '<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View><w:Zoom>100</w:Zoom><w:DoNotOptimizeForBrowser/></w:WordDocument></xml><![endif]-->'
    : '';

  var css = forWord
    ? 'body{font-family:Calibri,Arial,sans-serif;color:#1a1a1a;margin:0;padding:40px 60px;font-size:11pt}' +
      'h1{font-size:24pt;color:#1e3a5f;margin:0 0 4px}h2{font-size:14pt;color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:4px;margin-top:28px}' +
      'h3{font-size:12pt;color:#1a1a1a;margin:16px 0 4px}' +
      '.subtitle{font-size:14pt;color:#3b82f6;margin:0 0 24px}' +
      '.meta-info{color:#6b7280;font-size:10pt;line-height:1.8;margin-bottom:40px}' +
      '.summary-table{width:100%;border-collapse:collapse;margin:12px 0}' +
      '.summary-table td{border:1px solid #e5e7eb;padding:12px 16px;text-align:center;width:25%}' +
      '.summary-table .num{font-size:22pt;font-weight:700}.summary-table .lbl{font-size:8pt;color:#6b7280;text-transform:uppercase}' +
      'table.findings{width:100%;border-collapse:collapse;margin:12px 0;font-size:10pt}' +
      'table.findings th{background:#f3f4f6;color:#374151;text-align:left;padding:8px 10px;border:1px solid #e5e7eb;font-size:9pt}' +
      'table.findings td{padding:8px 10px;border:1px solid #e5e7eb;vertical-align:top}' +
      '.sev-badge{padding:2px 8px;font-size:9pt;font-weight:600;color:#fff;display:inline-block}' +
      '.detail-box{border:1px solid #e5e7eb;padding:14px 18px;margin:10px 0;page-break-inside:avoid}' +
      '.detail-meta{font-size:9pt;color:#6b7280;margin:4px 0 10px}.detail-desc{font-size:10pt;line-height:1.6}' +
      '.footer-line{text-align:center;color:#9ca3af;font-size:8pt;border-top:1px solid #e5e7eb;padding-top:20px;margin-top:40px}' +
      '@page{size:A4;margin:2cm}'
    : 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:0}' +
      '.cover{background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#1a1f2e 100%);padding:80px 60px;min-height:400px;display:flex;flex-direction:column;justify-content:center;border-bottom:3px solid #3b82f6}' +
      '.cover h1{font-size:36px;color:#fff;margin:0 0 8px}.subtitle{font-size:20px;color:#3b82f6;margin:0 0 40px;font-weight:400}' +
      '.meta-info{color:#8b949e;font-size:14px;line-height:2}' +
      '.container{max-width:900px;margin:0 auto;padding:40px 60px}' +
      'h2{color:#3b82f6;border-bottom:1px solid #21262d;padding-bottom:8px;margin-top:40px}' +
      '.summary-table{width:100%;border-collapse:collapse;margin:16px 0}.summary-table td{background:#161b22;border:8px solid #0d1117;padding:20px;text-align:center;width:25%}' +
      '.summary-table .num{font-size:28px;font-weight:700}.summary-table .lbl{font-size:12px;color:#8b949e;text-transform:uppercase;margin-top:4px}' +
      'table.findings{width:100%;border-collapse:collapse;margin:16px 0;font-size:14px}' +
      'table.findings th{background:#161b22;color:#8b949e;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;border-bottom:2px solid #21262d}' +
      'table.findings td{padding:10px 12px;border-bottom:1px solid #21262d}' +
      '.sev-badge{padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600;color:#fff;display:inline-block}' +
      '.detail-box{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin:16px 0}' +
      '.detail-box h3{margin:0 0 8px;font-size:16px;color:#fff}' +
      '.detail-meta{font-size:13px;color:#8b949e;margin-bottom:12px}.detail-desc{font-size:14px;line-height:1.6;color:#c9d1d9}' +
      '.footer-line{text-align:center;color:#484f58;font-size:12px;padding:40px 0;border-top:1px solid #21262d;margin-top:60px}';

  var head = '<html' + wordMeta + '><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">' +
    wordXml + '<title>' + esc(scanName) + '</title><style>' + css + '</style></head><body>';

  var coverOpen = forWord ? '' : '<div class="cover">';
  var coverClose = forWord ? '<hr style="border:2px solid #1e3a5f;margin:20px 0 30px">' : '</div><div class="container">';

  var body = coverOpen +
    '<h1>' + esc(scanName) + '</h1>' +
    '<div class="subtitle">Vulnerability Assessment Report</div>' +
    '<div class="meta-info">Prepared by: Wire_Ghost Automated Scanner<br>' +
    'Date: ' + date + '<br>Classification: CONFIDENTIAL</div>' +
    coverClose +
    '<h2>Executive Summary</h2>' +
    '<table class="summary-table"><tr>' +
    '<td><div class="num" style="color:#dc2626">' + counts.Critical + '</div><div class="lbl">Critical</div></td>' +
    '<td><div class="num" style="color:#ea580c">' + counts.High + '</div><div class="lbl">High</div></td>' +
    '<td><div class="num" style="color:#d97706">' + counts.Medium + '</div><div class="lbl">Medium</div></td>' +
    '<td><div class="num" style="color:#2563eb">' + counts.Low + '</div><div class="lbl">Low</div></td>' +
    '</tr></table>' +
    '<p style="' + (forWord ? 'font-size:10pt;' : 'font-size:14px;') + 'line-height:1.6">' +
    'This assessment identified <b>' + findings.length + ' findings</b> across the target scope. ' +
    (counts.Critical ? counts.Critical + ' critical-severity issues require immediate remediation. ' : '') +
    (counts.High ? counts.High + ' high-severity issues should be addressed within 30 days.' : '') +
    '</p>' +
    '<h2>Findings Overview</h2>' +
    '<table class="findings"><thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>CVE</th></tr></thead><tbody>' +
    findings.map(function(f) {
      return '<tr><td><span class="sev-badge" style="background:' + sevColor[f.sev] + '">' + f.sev + '</span></td>' +
        '<td>' + esc(f.title) + '</td><td>' + esc(f.host) + '</td><td>' + f.port + '</td>' +
        '<td>' + (f.cve || '—') + '</td></tr>';
    }).join('') + '</tbody></table>' +
    '<h2>Port Sheet</h2>' +
    '<table class="findings"><thead><tr><th style="width:40px">No</th><th>Host</th><th>Hostname</th><th>OS / Device</th><th>Open Ports</th></tr></thead><tbody>' +
    portSheet.map(function(p, i) {
      return '<tr><td>' + (i + 1) + '</td><td style="font-family:monospace;white-space:nowrap">' + esc(p.host) + '</td>' +
        '<td>' + esc(p.hostname) + '</td><td>' + esc(p.os) + '</td>' +
        '<td style="font-family:monospace;' + (forWord ? 'font-size:9pt' : 'font-size:12px') + '">' + esc(p.ports) + '</td></tr>';
    }).join('') + '</tbody></table>' +
    '<h2>Detailed Findings</h2>' +
    findings.map(function(f, i) {
      var bg = forWord ? ' style="background:' + sevBg[f.sev] + '"' : '';
      return '<div class="detail-box"' + bg + '><h3>' + (i + 1) + '. ' + esc(f.title) + '</h3>' +
        '<div class="detail-meta"><span class="sev-badge" style="background:' + sevColor[f.sev] + '">' + f.sev + '</span> &nbsp; ' +
        esc(f.host) + ':' + f.port + (f.cve ? ' &nbsp; ' + f.cve : '') + '</div>' +
        '<div class="detail-desc">' + esc(f.desc) + '</div></div>';
    }).join('') +
    '<div class="footer-line">Generated by Wire_Ghost Vulnerability Assessment Platform — ' + date + '</div>' +
    (forWord ? '' : '</div>');

  return head + body + '</body></html>';
};

WG._downloadDemoReport = function(scanName, format, filename) {
  var findings = WG._demoFindings(scanName);
  var date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  var blob, mime;

  if (format === 'docx') {
    var html = WG._demoReportHtml(scanName, findings, date, true);
    mime = 'application/msword';
    blob = new Blob(['﻿' + html], { type: mime });
    filename = filename.replace('.docx', '.doc');
  } else if (format === 'html') {
    var html = WG._demoReportHtml(scanName, findings, date, false);
    mime = 'text/html';
    blob = new Blob([html], { type: mime });
  } else if (format === 'xlsx') {
    var portSheet = WG._demoPortSheet(scanName);
    var q = function(c) { return '"' + String(c).replace(/"/g, '""') + '"'; };
    var rows = [['=== FINDINGS ===','','','','','']];
    rows.push(['Severity', 'Title', 'Host', 'Port', 'CVE/CWE', 'Description']);
    findings.forEach(function(f) {
      rows.push([f.sev, f.title, f.host, String(f.port), f.cve, f.desc]);
    });
    rows.push(['','','','','','']);
    rows.push(['=== PORT SHEET ===','','','','','']);
    rows.push(['No', 'Host', 'Hostname', 'OS / Device', 'Open Ports', '']);
    portSheet.forEach(function(p, i) {
      rows.push([String(i + 1), p.host, p.hostname, p.os, p.ports, '']);
    });
    var csv = rows.map(function(r) {
      return r.map(q).join(',');
    }).join('\r\n');
    blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' });
    filename = filename.replace('.xlsx', '.csv');
  }

  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  WG.toast('Downloaded ' + filename, 'success');
};

WG.renderReports = function() {
  var reports = [];
  var scans = WG.getCached('scans', '/scans/');
  if (scans.length) {
    scans.forEach(function(s) {
      if (s.reports) reports = reports.concat(s.reports.map(function(r) {
        r._scanName = s.name; r._scanId = s.id; return r;
      }));
    });
  }
  var isDemo = !reports.length;
  if (isDemo) reports = WG._demoReports();
  var esc = WG.escHtml;

  var fmtColors = { docx: '--accent', xlsx: '--success', html: '--info', dashboard: '--medium', csv: '--text-dim', json: '--low' };

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Reports</h1><p>' + reports.length + ' generated reports' +
      (isDemo ? ' &nbsp;<span class="tag" style="background:var(--accent-dim);color:var(--accent);font-size:0.7rem;">Demo Data</span>' : '') +
    '</p></div></div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px;">' +
      '<div class="stat-card"><div class="stat-label">Total Reports</div><div class="stat-value">' + reports.length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Scans Covered</div><div class="stat-value">' +
        Object.keys(reports.reduce(function(m, r) { m[r._scanName] = 1; return m; }, {})).length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Formats</div><div class="stat-value">' +
        Object.keys(reports.reduce(function(m, r) { m[r.format] = 1; return m; }, {})).length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Total Size</div><div class="stat-value">' +
        WG.fmtBytes(reports.reduce(function(s, r) { return s + (r.file_size || 0); }, 0)) + '</div></div>' +
    '</div>' +

    '<div class="filters-bar">' +
      '<input class="filter-input" placeholder="Search reports..." id="reportSearch" oninput="WG.filterReports()">' +
      '<select class="filter-select" id="reportFmtFilter" onchange="WG.filterReports()">' +
        '<option value="">All Formats</option>' +
        Object.keys(reports.reduce(function(m, r) { m[r.format] = 1; return m; }, {})).sort().map(function(f) {
          return '<option value="' + esc(f) + '">' + esc(f.toUpperCase()) + '</option>';
        }).join('') +
      '</select>' +
      '<select class="filter-select" id="reportScanFilter" onchange="WG.filterReports()">' +
        '<option value="">All Scans</option>' +
        Object.keys(reports.reduce(function(m, r) { m[r._scanName] = 1; return m; }, {})).sort().map(function(s) {
          return '<option value="' + esc(s) + '">' + esc(s) + '</option>';
        }).join('') +
      '</select>' +
    '</div>' +

    '<div class="panel"><table class="data-table" id="reportsTable"><thead><tr><th>Scan</th><th>Format</th><th>File</th><th>Size</th><th>Generated</th><th></th></tr></thead><tbody>' +
    reports.map(function(r) {
      var fname = r._file || (r.file_path ? r.file_path.split('/').pop() : r.format);
      var fcolor = fmtColors[r.format] || '--text-dim';
      return '<tr data-search="' + esc((r._scanName + ' ' + r.format + ' ' + fname).toLowerCase()) + '" data-fmt="' + esc(r.format) + '" data-scan="' + esc(r._scanName) + '">' +
        '<td>' + (r._demo
          ? esc(r._scanName)
          : '<a onclick="WG.navigate(\'scan\',{id:\'' + esc(r._scanId) + '\'})">' + esc(r._scanName) + '</a>') +
        '</td>' +
        '<td><span class="tag" style="background:var(' + fcolor + ');color:#fff;font-size:0.68rem;padding:2px 8px;">' + esc(r.format.toUpperCase()) + '</span></td>' +
        '<td class="mono" style="font-size:0.75rem;">' + esc(fname) + '</td>' +
        '<td class="mono">' + WG.fmtBytes(r.file_size) + '</td>' +
        '<td class="mono">' + WG.fmtDate(r.created_at) + '</td>' +
        '<td>' + (r._demo
          ? '<button class="btn btn-ghost btn-sm" onclick="WG._downloadDemoReport(\'' + esc(r._scanName) + '\',\'' + esc(r.format) + '\',\'' + esc(fname) + '\')">Download</button>'
          : '<button class="btn btn-ghost btn-sm" onclick="WG.downloadReport(\'' + esc(r.id) + '\')">Download</button>') +
        '</td></tr>';
    }).join('') +
    '</tbody></table></div>';
};

WG.filterReports = function() {
  var search = (document.getElementById('reportSearch').value || '').toLowerCase();
  var fmt = document.getElementById('reportFmtFilter').value;
  var scan = document.getElementById('reportScanFilter').value;
  document.querySelectorAll('#reportsTable tbody tr').forEach(function(tr) {
    var ok = (!search || tr.dataset.search.includes(search)) &&
             (!fmt || tr.dataset.fmt === fmt) &&
             (!scan || tr.dataset.scan === scan);
    tr.style.display = ok ? '' : 'none';
  });
};
