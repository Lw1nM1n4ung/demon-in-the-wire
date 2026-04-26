/* Wire_Ghost — Scheduled / Recurring Scans (API-backed with mock fallback)
   Note: All user-supplied values are escaped via WG.escHtml() before rendering.
   innerHTML is used for the SPA rendering pattern consistent with the rest of the app. */

WG._getSchedules = function() {
  var data = WG.getCached('schedules', '/schedules/');
  return data || [];
};

WG._calcNextRun = function(freq, time) {
  var now = new Date();
  var next = new Date(now);
  var parts = (time || '02:00').split(':');
  next.setHours(parseInt(parts[0]) || 2, parseInt(parts[1]) || 0, 0, 0);
  if (next <= now) {
    if (freq === 'daily') next.setDate(next.getDate() + 1);
    else if (freq === 'weekly') next.setDate(next.getDate() + 7);
    else if (freq === 'biweekly') next.setDate(next.getDate() + 14);
    else if (freq === 'monthly') next.setMonth(next.getMonth() + 1);
  }
  return next.toISOString();
};

WG.renderScheduled = function() {
  var schedules = WG._getSchedules();
  // Background refresh from API
  WG.refreshAndRerender('schedules', '/schedules/', WG.renderScheduled, 'scheduled');
  var esc = WG.escHtml;
  var enabled = schedules.filter(function(s) { return s.enabled; }).length;

  var freqLabels = { daily: 'Daily', weekly: 'Weekly', biweekly: 'Every 2 Weeks', monthly: 'Monthly' };

  // Fetch policies for the dropdown
  var policies = WG._getPolicies ? WG._getPolicies() : [];

  return '' +
    '<div class="page-header"><div class="page-header-left"><h1>Scheduled Scans</h1><p>' + schedules.length + ' schedules &mdash; ' + enabled + ' active</p></div>' +
    '<div class="page-header-actions"><button class="btn btn-primary" onclick="WG._openScheduleEditor()"><span>+</span> New Schedule</button></div></div>' +

    '<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px;">' +
      '<div class="stat-card"><div class="stat-label">Total Schedules</div><div class="stat-value">' + schedules.length + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Active</div><div class="stat-value" style="color:var(--success);">' + enabled + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Paused</div><div class="stat-value" style="color:var(--medium);">' + (schedules.length - enabled) + '</div></div>' +
      '<div class="stat-card"><div class="stat-label">Next Run</div><div class="stat-value" style="font-size:1rem;">' +
        (enabled ? WG.timeAgo(schedules.filter(function(s) { return s.enabled; }).sort(function(a, b) { return new Date(a.next_run) - new Date(b.next_run); })[0].next_run) : '\u2014') +
      '</div></div>' +
    '</div>' +

    (schedules.length === 0 ?
      '<div class="empty-state"><div class="icon">&#8635;</div><h3>No scheduled scans</h3><p>Set up recurring vulnerability assessments.</p>' +
      '<button class="btn btn-primary" style="margin-top:16px;" onclick="WG._openScheduleEditor()">Create Schedule</button></div>'
    :
      '<div class="panel"><table class="data-table"><thead><tr><th>Name</th><th>Target</th><th>Frequency</th><th>Time</th><th>Stop By</th><th>Type</th><th>Policy</th><th>Status</th><th>Last Run</th><th>Next Run</th><th></th></tr></thead><tbody>' +
      schedules.map(function(s) {
        var timeStr = s.time || '';
        if (typeof timeStr === 'string' && timeStr.length > 5) timeStr = timeStr.substring(0, 5);
        return '<tr>' +
          '<td style="font-weight:600;color:var(--text-bright);">' + esc(s.name) + '</td>' +
          '<td><span class="host-tag">' + esc(s.target) + '</span></td>' +
          '<td><span class="tag">' + esc(freqLabels[s.frequency] || s.frequency) + '</span></td>' +
          '<td class="mono">' + esc(timeStr) + '</td>' +
          '<td class="mono">' + (s.stop_time ? esc(s.stop_time.substring(0, 5)) : '<span style="color:var(--text-dim);">—</span>') + '</td>' +
          '<td><span class="tag">' + esc(s.scan_type) + '</span></td>' +
          '<td>' + (s.policy_name ? '<span class="tag">' + esc(s.policy_name) + '</span>' : '<span style="color:var(--text-dim);">None</span>') + '</td>' +
          '<td>' +
            '<div class="form-toggle" onclick="WG._toggleSchedule(\'' + s.id + '\')" style="margin:0;">' +
              '<div class="toggle-track' + (s.enabled ? ' on' : '') + '" style="width:32px;height:18px;"></div>' +
            '</div>' +
          '</td>' +
          '<td class="mono">' + (s.last_run ? WG.timeAgo(s.last_run) : 'Never') + '</td>' +
          '<td class="mono">' + (s.enabled && s.next_run ? WG.timeAgo(s.next_run) : '\u2014') + '</td>' +
          '<td style="text-align:right;">' +
            '<button class="btn btn-ghost btn-sm" onclick="WG._runScheduleNow(\'' + s.id + '\')">Run Now</button> ' +
            '<button class="btn btn-ghost btn-sm" onclick="WG._openScheduleEditor(\'' + s.id + '\')">Edit</button> ' +
            '<button class="btn btn-ghost btn-sm" style="color:var(--critical);" onclick="WG._deleteSchedule(\'' + s.id + '\')">Del</button>' +
          '</td></tr>';
      }).join('') +
      '</tbody></table></div>'
    ) +

    /* Schedule editor modal — form values set via JS in _openScheduleEditor */
    '<div class="modal-overlay" id="scheduleModal"><div class="modal"><div class="modal-header"><h2 id="schedModalTitle">New Schedule</h2><p>Set up a recurring scan</p></div>' +
    '<div class="modal-body">' +
      '<input type="hidden" id="schedEditId" value="">' +
      '<div class="form-group"><label class="form-label">Schedule Name</label><input class="form-input" id="schedName" placeholder="Weekly Internal Audit"></div>' +
      '<div class="form-group"><label class="form-label">Target</label><input class="form-input" id="schedTarget" placeholder="192.168.1.0/24"></div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Frequency</label><select class="form-select" id="schedFreq"><option value="daily">Daily</option><option value="weekly" selected>Weekly</option><option value="biweekly">Every 2 Weeks</option><option value="monthly">Monthly</option></select></div>' +
        '<div class="form-group"><label class="form-label">Run At</label><input class="form-input" id="schedTime" type="time" value="02:00"></div>' +
        '<div class="form-group"><label class="form-label">Stop By <span style="color:var(--text-dim);font-weight:normal;">(optional)</span></label><input class="form-input" id="schedStopTime" type="time" value=""></div>' +
      '</div>' +
      '<div class="form-row">' +
        '<div class="form-group"><label class="form-label">Scan Type</label><select class="form-select" id="schedScanType"><option value="full">Full Scan</option><option value="quick">Quick Scan</option><option value="port">Port Scan</option><option value="web">Web App</option><option value="service">Service Enum</option></select></div>' +
        '<div class="form-group"><label class="form-label">Policy (optional)</label><select class="form-select" id="schedPolicy"><option value="">No policy</option>' +
          policies.map(function(p) { return '<option value="' + p.id + '">' + esc(p.name) + '</option>'; }).join('') +
        '</select></div>' +
      '</div>' +
    '</div>' +
    '<div class="modal-footer"><button class="btn btn-secondary" onclick="WG.closeModal(\'scheduleModal\')">Cancel</button><button class="btn btn-primary" onclick="WG._saveSchedule()">Save Schedule</button></div></div></div>';
};

WG._openScheduleEditor = function(id) {
  var title = document.getElementById('schedModalTitle');
  if (id) {
    var schedules = WG._getSchedules();
    var s = schedules.find(function(x) { return x.id === id; });
    if (!s) return;
    title.textContent = 'Edit Schedule';
    document.getElementById('schedEditId').value = id;
    document.getElementById('schedName').value = s.name;
    document.getElementById('schedTarget').value = s.target;
    document.getElementById('schedFreq').value = s.frequency;
    var timeStr = s.time || '02:00';
    if (typeof timeStr === 'string' && timeStr.length > 5) timeStr = timeStr.substring(0, 5);
    document.getElementById('schedTime').value = timeStr;
    var stopStr = s.stop_time || '';
    if (typeof stopStr === 'string' && stopStr.length > 5) stopStr = stopStr.substring(0, 5);
    document.getElementById('schedStopTime').value = stopStr;
    document.getElementById('schedScanType').value = s.scan_type;
    var policyEl = document.getElementById('schedPolicy');
    if (policyEl) policyEl.value = s.policy || '';
  } else {
    title.textContent = 'New Schedule';
    document.getElementById('schedEditId').value = '';
    document.getElementById('schedName').value = '';
    document.getElementById('schedTarget').value = '';
    document.getElementById('schedFreq').value = 'weekly';
    document.getElementById('schedTime').value = '02:00';
    document.getElementById('schedStopTime').value = '';
    document.getElementById('schedScanType').value = 'full';
    var policyEl = document.getElementById('schedPolicy');
    if (policyEl) policyEl.value = '';
  }
  WG.openModal('scheduleModal');
};

WG._saveSchedule = function() {
  var editId = document.getElementById('schedEditId').value;
  var name = document.getElementById('schedName').value.trim();
  var target = document.getElementById('schedTarget').value.trim();
  if (!name || !target) { WG.toast('Name and target required', 'error'); return; }

  var freq = document.getElementById('schedFreq').value;
  var time = document.getElementById('schedTime').value;
  var policyId = document.getElementById('schedPolicy').value;

  var stopTime = document.getElementById('schedStopTime').value;
  var data = {
    name: name,
    target: target,
    frequency: freq,
    time: time,
    stop_time: stopTime || null,
    scan_type: document.getElementById('schedScanType').value,
    policy: policyId || null,
    enabled: true,
    next_run: WG._calcNextRun(freq, time),
  };

  if (editId) {
    WG.api('/schedules/' + editId + '/', { method: 'PUT', body: JSON.stringify(data) }).then(function(res) {
      if (res && !res.error) {
        WG.invalidateCache('schedules');
        WG.toast('Schedule updated', 'success');
        WG.closeModal('scheduleModal');
        WG.render();
      } else {
        WG.toast('Failed to update schedule', 'error');
      }
    });
  } else {
    WG.api('/schedules/', { method: 'POST', body: JSON.stringify(data) }).then(function(res) {
      if (res && res.id) {
        WG.invalidateCache('schedules');
        WG.toast('Schedule created: ' + name, 'success');
        WG.closeModal('scheduleModal');
        WG.render();
      } else {
        WG.toast('Failed to create schedule', 'error');
      }
    });
  }
};

WG._toggleSchedule = function(id) {
  WG.api('/schedules/' + id + '/toggle/', { method: 'POST' }).then(function(res) {
    if (res && res.id) {
      WG.invalidateCache('schedules');
      WG.toast(res.name + (res.enabled ? ' enabled' : ' paused'), 'info');
      WG.render();
    }
  });
};

WG._runScheduleNow = function(id) {
  WG.api('/schedules/' + id + '/run_now/', { method: 'POST' }).then(function(res) {
    if (res && res.id) {
      WG.invalidateCache('schedules');
      WG.invalidateCache('scans');
      WG.toast('Scan launched from schedule', 'success');
      WG.render();
    } else {
      WG.toast('Failed to launch scan', 'error');
    }
  });
};

WG._deleteSchedule = function(id) {
  WG.api('/schedules/' + id + '/', { method: 'DELETE' }).then(function() {
    WG.invalidateCache('schedules');
    WG.toast('Schedule deleted', 'info');
    WG.render();
  });
};
