/* Wire_Ghost — Utility functions */

WG.escHtml = function(str) {
  if (!str) return '';
  var d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
};

WG.timeAgo = function(dateStr) {
  if (!dateStr) return '\u2014';
  var diff = Date.now() - new Date(dateStr).getTime();
  var mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return mins + 'm ago';
  var hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  var days = Math.floor(hrs / 24);
  return days + 'd ago';
};

WG.fmtDuration = function(secs) {
  if (secs == null || secs < 0) return '\u2014';
  if (secs === 0) return '0s';
  if (secs < 60) return secs + 's';
  var m = Math.floor(secs / 60);
  var s = secs % 60;
  if (m < 60) return m + 'm ' + s + 's';
  var h = Math.floor(m / 60);
  return h + 'h ' + (m % 60) + 'm';
};

WG.fmtBytes = function(bytes) {
  if (!bytes) return '\u2014';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
};

WG.fmtDate = function(dateStr) {
  if (!dateStr) return '\u2014';
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
};

WG.sevOrder = function(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] || 5;
};

WG.toast = function(msg, type) {
  type = type || 'info';
  var el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(function() {
    el.classList.add('removing');
    setTimeout(function() { el.remove(); }, 300);
  }, 3500);
};

WG.openModal = function(id) {
  document.getElementById(id).classList.add('active');
  if (id === 'scanModal') {
    var t = document.getElementById('scanTarget');
    if (t) t.focus();
  }
  if (id === 'searchModal') {
    setTimeout(function() {
      var s = document.getElementById('globalSearch');
      if (s) s.focus();
    }, 100);
  }
};

WG.closeModal = function(id) {
  document.getElementById(id).classList.remove('active');
};

/* User profile dropdown */
WG.toggleUserMenu = function(e) {
  if (e) e.stopPropagation();
  var menu = document.getElementById('userMenu');
  menu.classList.toggle('open');

  // Update dropdown info from session
  var user = WG.currentUser ? WG.currentUser() : null;
  if (user) {
    var da = document.getElementById('dropdownAvatar');
    var de = document.getElementById('topbarUserEmail');
    if (da) da.textContent = user.avatar || 'U';
    if (de) de.textContent = user.email || '';
  }

  // Update theme label
  var prefs = WG.getThemePrefs ? WG.getThemePrefs() : {};
  WG._updateThemeLabel(prefs.mode || 'dark');
};

WG._toggleThemeQuick = function() {
  var prefs = WG.getThemePrefs ? WG.getThemePrefs() : {};
  var current = prefs.mode || 'dark';
  var cycle = { dark: 'light', light: 'cyberpunk', cyberpunk: 'dark' };
  var newMode = cycle[current] || 'dark';
  WG.setThemeMode(newMode);
  WG._updateThemeLabel(newMode);
};

WG._updateThemeLabel = function(mode) {
  var svgIcons = {
    dark: '<svg class="udrop-icon" viewBox="0 0 24 24"><use href="#i-moon"/></svg>',
    light: '<svg class="udrop-icon" viewBox="0 0 24 24"><use href="#i-sun"/></svg>',
    cyberpunk: '<svg class="udrop-icon" viewBox="0 0 24 24"><use href="#i-zap"/></svg>'
  };
  var labels = { dark: 'Dark Mode', light: 'Light Mode', cyberpunk: 'Cyberpunk' };
  var icon = document.getElementById('themeIcon');
  var label = document.getElementById('themeLabel');
  var badge = document.getElementById('themeBadge');
  if (icon) icon.innerHTML = svgIcons[mode] || svgIcons.dark;
  if (label) label.textContent = labels[mode] || labels.dark;
  if (badge) { badge.textContent = mode.toUpperCase(); badge.style.color = mode === 'cyberpunk' ? '#ff2d95' : ''; badge.style.background = mode === 'cyberpunk' ? 'rgba(255,45,149,0.15)' : ''; }
};

WG._dropNav = function(page) {
  document.getElementById('userMenu').classList.remove('open');
  WG.navigate(page);
};

/* ── Mobile navigation drawer ── */
WG.toggleMobileNav = function() {
  var sidebar = document.querySelector('.sidebar');
  if (sidebar.classList.contains('open')) WG.closeMobileNav();
  else WG.openMobileNav();
};

WG.openMobileNav = function() {
  var sidebar = document.querySelector('.sidebar');
  var backdrop = document.getElementById('sidebarBackdrop');
  var btn = document.getElementById('hamburger');
  sidebar.classList.add('open');
  backdrop.classList.add('visible');
  btn.setAttribute('aria-expanded', 'true');
  btn.setAttribute('aria-label', 'Close navigation');
  document.body.style.overflow = 'hidden';
};

WG.closeMobileNav = function() {
  var sidebar = document.querySelector('.sidebar');
  var backdrop = document.getElementById('sidebarBackdrop');
  var btn = document.getElementById('hamburger');
  if (!sidebar || !sidebar.classList.contains('open')) return;
  sidebar.classList.remove('open');
  backdrop.classList.remove('visible');
  btn.setAttribute('aria-expanded', 'false');
  btn.setAttribute('aria-label', 'Open navigation');
  document.body.style.overflow = '';
};

/* Close dropdown on outside click */
document.addEventListener('click', function(e) {
  var menu = document.getElementById('userMenu');
  if (menu && !menu.contains(e.target)) {
    menu.classList.remove('open');
  }
});
