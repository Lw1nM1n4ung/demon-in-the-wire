WG._topo = WG._topo || {};

WG._topoContextMenu = function(event, d) {
  event.preventDefault();
  event.stopPropagation();
  WG._topoContextDismiss();

  var esc = WG.escHtml;
  var expanded = WG._topo.state.expandedHosts.indexOf(d.id) !== -1;

  var menu = document.createElement('div');
  menu.id = 'topoContextMenu';
  menu.style.cssText = 'position:fixed;z-index:1100;background:var(--bg-card);' +
    'border:1px solid var(--border-soft);border-radius:var(--radius-md);' +
    'padding:4px;box-shadow:var(--shadow-lg);min-width:180px;font-size:0.8rem;';
  menu.style.left = event.clientX + 'px';
  menu.style.top = event.clientY + 'px';

  var items = [
    { label: 'View Scan', icon: '\u{1f50d}', action: function() { WG.navigate('scans'); } },
    { label: 'View Details', icon: '\u{1f4cb}', action: function() { WG._topoShowDetail(d); } },
    { label: 'Copy IP', icon: '\u{1f4cb}', action: function() {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(d.ip).then(function() { WG.toast('IP copied', 'success'); });
      }
    }},
    { label: expanded ? 'Collapse Ports' : 'Expand Ports', icon: expanded ? '\u{2796}' : '\u{2795}',
      action: function() { WG._topoExpandHost(d); } },
    { label: 'Rescan Host', icon: '\u{1f504}', action: function() {
      if (confirm('Start a new scan targeting ' + d.ip + '?')) {
        WG.api('/scans/', { method: 'POST', body: JSON.stringify({ target: d.ip, name: 'Rescan ' + d.ip }) });
        WG.toast('Scan queued for ' + d.ip, 'success');
      }
    }}
  ];

  items.forEach(function(item) {
    var btn = document.createElement('button');
    btn.style.cssText = 'display:flex;align-items:center;gap:8px;width:100%;padding:6px 10px;' +
      'background:none;border:none;color:var(--text-primary);cursor:pointer;border-radius:var(--radius-xs);' +
      'font-size:0.8rem;font-family:inherit;text-align:left;';
    btn.onmouseenter = function() { btn.style.background = 'var(--bg-hover)'; };
    btn.onmouseleave = function() { btn.style.background = 'none'; };
    btn.textContent = item.label;
    btn.onclick = function() {
      WG._topoContextDismiss();
      item.action();
    };
    menu.appendChild(btn);
  });

  document.body.appendChild(menu);

  var rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth) menu.style.left = (window.innerWidth - rect.width - 8) + 'px';
  if (rect.bottom > window.innerHeight) menu.style.top = (window.innerHeight - rect.height - 8) + 'px';

  WG._topo._ctxDismiss = function(e) {
    if (e && menu.contains(e.target)) return;
    WG._topoContextDismiss();
  };
  setTimeout(function() { document.addEventListener('click', WG._topo._ctxDismiss); }, 0);
  document.addEventListener('keydown', WG._topo._ctxEsc = function(e) {
    if (e.key === 'Escape') WG._topoContextDismiss();
  });
};

WG._topoContextDismiss = function() {
  var menu = document.getElementById('topoContextMenu');
  if (menu) menu.remove();
  if (WG._topo._ctxDismiss) {
    document.removeEventListener('click', WG._topo._ctxDismiss);
    WG._topo._ctxDismiss = null;
  }
  if (WG._topo._ctxEsc) {
    document.removeEventListener('keydown', WG._topo._ctxEsc);
    WG._topo._ctxEsc = null;
  }
};
