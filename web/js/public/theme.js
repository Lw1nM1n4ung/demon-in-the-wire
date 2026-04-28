/* Wire_Ghost — Theme engine with localStorage persistence (Tier 0).
 *
 * This file is served to unauthenticated visitors (login.html, setup.html)
 * as well as the full SPA, so it must not assume any other script has run.
 * The WG init below matches the same self-sufficiency pattern as state.js,
 * login-boot.js, and setup-boot.js. */
window.WG = window.WG || {};

WG.THEMES = {
  dark: {
    '--bg-void': '#06080d',
    '--bg-primary': '#0a0e17',
    '--bg-panel': '#0f1420',
    '--bg-card': '#141a28',
    '--bg-hover': '#1a2235',
    '--bg-input': '#111827',
    '--bg-elevated': '#1e2538',
    '--border-dim': 'rgba(255,255,255,0.04)',
    '--border-soft': 'rgba(255,255,255,0.08)',
    '--text-primary': '#e8ecf4',
    '--text-secondary': '#8892a4',
    '--text-dim': '#5a6478',
    '--text-bright': '#ffffff',
    '--text-muted': '#3d4654',
  },
  light: {
    '--bg-void': '#f4f6f9',
    '--bg-primary': '#ffffff',
    '--bg-panel': '#ffffff',
    '--bg-card': '#f8f9fb',
    '--bg-hover': '#eef1f6',
    '--bg-input': '#f4f6f9',
    '--bg-elevated': '#ffffff',
    '--border-dim': 'rgba(0,0,0,0.05)',
    '--border-soft': 'rgba(0,0,0,0.09)',
    '--text-primary': '#1e2330',
    '--text-secondary': '#4d5568',
    '--text-dim': '#7c869a',
    '--text-bright': '#0d1117',
    '--text-muted': '#bcc5d3',
  },
  cyberpunk: {
    '--bg-void': '#05000d',
    '--bg-primary': '#08001a',
    '--bg-panel': '#0c0020',
    '--bg-card': '#10002a',
    '--bg-hover': '#180038',
    '--bg-input': '#0a001c',
    '--bg-elevated': '#140030',
    '--border-dim': 'rgba(0,240,255,0.05)',
    '--border-soft': 'rgba(0,240,255,0.1)',
    '--text-primary': '#dce8f0',
    '--text-secondary': '#8ea4b8',
    '--text-dim': '#5a7088',
    '--text-bright': '#f0f6ff',
    '--text-muted': '#3a4e60',
  },
  onepiece: {
    '--bg-void': '#04081a',
    '--bg-primary': '#081028',
    '--bg-panel': '#0c1530',
    '--bg-card': '#0f1d36',
    '--bg-hover': '#152848',
    '--bg-input': '#0a1225',
    '--bg-elevated': '#132240',
    '--border-dim': 'rgba(245,197,24,0.05)',
    '--border-soft': 'rgba(245,197,24,0.1)',
    '--text-primary': '#e8ecf4',
    '--text-secondary': '#8892a4',
    '--text-dim': '#5a6478',
    '--text-bright': '#fff5e0',
    '--text-muted': '#3d4654',
  },
};

/* Cyberpunk mode forces its own accent */
WG.CYBERPUNK_ACCENT = {
  '--accent': '#ff2d95',
  '--accent-solid': '#e6006e',
  '--accent-dim': 'rgba(255,45,149,0.15)',
  '--accent-glow': 'rgba(255,45,149,0.4)',
  '--border-active': 'rgba(255,45,149,0.5)',
  '--border-accent': 'rgba(255,45,149,0.3)',
  /* Extra cyberpunk vars */
  '--cyber-cyan': '#00f0ff',
  '--cyber-pink': '#ff2d95',
  '--cyber-yellow': '#ffe600',
  '--critical': '#ff1744',
  '--critical-dim': 'rgba(255,23,68,0.15)',
  '--high': '#ff6d00',
  '--high-dim': 'rgba(255,109,0,0.15)',
  '--medium': '#ffe600',
  '--medium-dim': 'rgba(255,230,0,0.15)',
  '--low': '#00f0ff',
  '--low-dim': 'rgba(0,240,255,0.15)',
  '--info': '#b388ff',
  '--info-dim': 'rgba(179,136,255,0.15)',
  '--success': '#00e676',
  '--success-dim': 'rgba(0,230,118,0.15)',
};

WG.ONEPIECE_ACCENT = {
  '--accent': '#F5C518',
  '--accent-solid': '#d4a017',
  '--accent-dim': 'rgba(245,197,24,0.15)',
  '--accent-glow': 'rgba(245,197,24,0.4)',
  '--border-active': 'rgba(245,197,24,0.5)',
  '--border-accent': 'rgba(245,197,24,0.3)',
  '--op-gold': '#F5C518',
  '--op-red': '#E53935',
  '--op-sea': '#29B6F6',
  '--critical': '#E53935',
  '--critical-dim': 'rgba(229,57,53,0.15)',
  '--high': '#FF8F00',
  '--high-dim': 'rgba(255,143,0,0.15)',
  '--medium': '#F5C518',
  '--medium-dim': 'rgba(245,197,24,0.15)',
  '--low': '#29B6F6',
  '--low-dim': 'rgba(41,182,246,0.15)',
  '--info': '#66BB6A',
  '--info-dim': 'rgba(102,187,106,0.15)',
  '--success': '#66BB6A',
  '--success-dim': 'rgba(102,187,106,0.15)',
};

WG.ACCENT_COLORS = {
  blue:   { '--accent': '#3b82f6', '--accent-solid': '#2563eb', '--accent-dim': 'rgba(59,130,246,0.12)', '--accent-glow': 'rgba(59,130,246,0.3)', '--border-active': 'rgba(59,130,246,0.4)', '--border-accent': 'rgba(59,130,246,0.25)' },
  green:  { '--accent': '#22c55e', '--accent-solid': '#16a34a', '--accent-dim': 'rgba(34,197,94,0.12)', '--accent-glow': 'rgba(34,197,94,0.3)', '--border-active': 'rgba(34,197,94,0.4)', '--border-accent': 'rgba(34,197,94,0.25)' },
  purple: { '--accent': '#a855f7', '--accent-solid': '#9333ea', '--accent-dim': 'rgba(168,85,247,0.12)', '--accent-glow': 'rgba(168,85,247,0.3)', '--border-active': 'rgba(168,85,247,0.4)', '--border-accent': 'rgba(168,85,247,0.25)' },
  red:    { '--accent': '#ef4444', '--accent-solid': '#dc2626', '--accent-dim': 'rgba(239,68,68,0.12)', '--accent-glow': 'rgba(239,68,68,0.3)', '--border-active': 'rgba(239,68,68,0.4)', '--border-accent': 'rgba(239,68,68,0.25)' },
  orange: { '--accent': '#f97316', '--accent-solid': '#ea580c', '--accent-dim': 'rgba(249,115,22,0.12)', '--accent-glow': 'rgba(249,115,22,0.3)', '--border-active': 'rgba(249,115,22,0.4)', '--border-accent': 'rgba(249,115,22,0.25)' },
  cyan:   { '--accent': '#06b6d4', '--accent-solid': '#0891b2', '--accent-dim': 'rgba(6,182,212,0.12)', '--accent-glow': 'rgba(6,182,212,0.3)', '--border-active': 'rgba(6,182,212,0.4)', '--border-accent': 'rgba(6,182,212,0.25)' },
  rose:   { '--accent': '#f43f5e', '--accent-solid': '#e11d48', '--accent-dim': 'rgba(244,63,94,0.12)', '--accent-glow': 'rgba(244,63,94,0.3)', '--border-active': 'rgba(244,63,94,0.4)', '--border-accent': 'rgba(244,63,94,0.25)' },
};

WG.FONT_SIZES = {
  small:   '13px',
  default: '14px',
  large:   '15px',
  xlarge:  '16px',
};

/* Load saved preferences — localStorage as cache, API as source of truth */
WG.getThemePrefs = function() {
  try {
    return JSON.parse(localStorage.getItem('wg_theme')) || {};
  } catch (e) { return {}; }
};

WG.saveThemePrefs = function(prefs) {
  var current = WG.getThemePrefs();
  var merged = Object.assign(current, prefs);
  localStorage.setItem('wg_theme', JSON.stringify(merged));

  // Sync to server if logged in (fire and forget)
  if (WG.isLoggedIn && WG.isLoggedIn()) {
    WG.api('/preferences/', {
      method: 'PUT',
      body: JSON.stringify({ theme_mode: merged.mode, accent_color: merged.accent, font_size: merged.fontSize }),
    }).catch(function() {});
  }
};

/* Load preferences from server on login */
WG.loadPrefsFromServer = function() {
  WG.api('/preferences/').then(function(data) {
    if (data && data.theme_mode) {
      var prefs = { mode: data.theme_mode, accent: data.accent_color, fontSize: data.font_size };
      localStorage.setItem('wg_theme', JSON.stringify(prefs));
      WG.applyTheme(prefs);

      // Also cache notifications
      if (data.notifications) {
        localStorage.setItem('wg_notifs', JSON.stringify(data.notifications));
      }
    }
  });
};

/* Apply theme to DOM */
WG.applyTheme = function(prefs) {
  prefs = prefs || WG.getThemePrefs();
  var root = document.documentElement.style;

  // Mode
  var mode = prefs.mode || 'dark';
  var vars = WG.THEMES[mode] || WG.THEMES.dark;
  Object.keys(vars).forEach(function(k) { root.setProperty(k, vars[k]); });
  document.body.dataset.theme = mode;

  document.body.classList.remove('cyberpunk', 'onepiece');

  if (mode === 'cyberpunk') {
    Object.keys(WG.CYBERPUNK_ACCENT).forEach(function(k) { root.setProperty(k, WG.CYBERPUNK_ACCENT[k]); });
    document.body.classList.add('cyberpunk');
  } else if (mode === 'onepiece') {
    Object.keys(WG.ONEPIECE_ACCENT).forEach(function(k) { root.setProperty(k, WG.ONEPIECE_ACCENT[k]); });
    document.body.classList.add('onepiece');
  } else {
    root.setProperty('--critical', '#ff3b5c');
    root.setProperty('--critical-dim', 'rgba(255,59,92,0.12)');
    root.setProperty('--high', '#ff6b35');
    root.setProperty('--high-dim', 'rgba(255,107,53,0.12)');
    root.setProperty('--medium', '#ffb800');
    root.setProperty('--medium-dim', 'rgba(255,184,0,0.12)');
    root.setProperty('--low', '#38bdf8');
    root.setProperty('--low-dim', 'rgba(56,189,248,0.12)');
    root.setProperty('--info', '#818cf8');
    root.setProperty('--info-dim', 'rgba(129,140,248,0.12)');
    root.setProperty('--success', '#34d399');
    root.setProperty('--success-dim', 'rgba(52,211,153,0.12)');

    var accent = prefs.accent || 'blue';
    var accentVars = WG.ACCENT_COLORS[accent] || WG.ACCENT_COLORS.blue;
    Object.keys(accentVars).forEach(function(k) { root.setProperty(k, accentVars[k]); });
  }

  // Font size
  var fontSize = prefs.fontSize || 'default';
  root.setProperty('font-size', WG.FONT_SIZES[fontSize] || '14px');
};

WG.setThemeMode = function(mode) {
  WG.saveThemePrefs({ mode: mode });
  WG.applyTheme();
};

WG.setAccentColor = function(color) {
  WG.saveThemePrefs({ accent: color });
  WG.applyTheme();
};

WG.setFontSize = function(size) {
  WG.saveThemePrefs({ fontSize: size });
  WG.applyTheme();
};

/* Notification preferences */
WG.getNotifPrefs = function() {
  try {
    return JSON.parse(localStorage.getItem('wg_notifs')) || {
      scanComplete: true, criticalFinding: true, reportReady: true,
      scanFailed: true, weeklyDigest: false, email: false,
    };
  } catch (e) { return { scanComplete: true, criticalFinding: true, reportReady: true, scanFailed: true, weeklyDigest: false, email: false }; }
};

WG.saveNotifPrefs = function(prefs) {
  localStorage.setItem('wg_notifs', JSON.stringify(prefs));
  if (WG.isLoggedIn && WG.isLoggedIn()) {
    WG.api('/preferences/', { method: 'PUT', body: JSON.stringify({ notifications: prefs }) }).catch(function() {});
  }
};

/* Apply theme on load immediately */
WG.applyTheme();
