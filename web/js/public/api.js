/* Wire_Ghost — API service.
 * All data is served by the Django API. There is no offline/demo fallback. */

/* Read CSRF token from cookie */
WG._getCSRF = function() {
  var m = document.cookie.match(/csrftoken=([^;]+)/);
  return m ? m[1] : '';
};

WG.api = async function(path, opts) {
  opts = opts || {};
  try {
    var headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});

    // Add CSRF token for mutating requests (POST/PUT/DELETE)
    var method = (opts.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      headers['X-CSRFToken'] = WG._getCSRF();
    }

    var res = await fetch(WG.API_BASE + path, {
      headers: headers,
      method: opts.method || 'GET',
      body: opts.body || undefined,
      credentials: 'include',
    });

    // 401 = not authenticated; tear down session and bounce to login.
    // `WG.clearSession` is defined in Tier-1 app/auth.js; guard for Tier-0
    // contexts (e.g. setup.html) where that file isn't shipped.
    if (res.status === 401 && path !== '/auth/login/' && path !== '/auth/csrf/') {
      if (WG.clearSession) WG.clearSession();
      window.location.href = '/login';
      return null;
    }
    // 403 = authenticated but forbidden; let the caller handle it.
    if (res.status === 403) return null;

    if (!res.ok) {
      if (res.status === 404) return null;
      throw new Error(res.statusText);
    }
    return await res.json();
  } catch (e) {
    return null;
  }
};

/* Fetch data — returns the API payload (or its `results` array for paginated
 * responses), or null on failure. Pages should handle null as an empty state. */
WG.fetchData = async function(apiPath) {
  var data = await WG.api(apiPath);
  if (!data) return null;
  return data.results || data;
};

/* In-memory cache for API data — avoids re-fetching on every render. */
WG._cache = {};
WG._cacheTime = {};

WG.getCached = function(key, apiPath, maxAge) {
  maxAge = maxAge || 30000; // 30 sec default
  var now = Date.now();
  if (WG._cache[key] && (now - WG._cacheTime[key]) < maxAge) {
    return WG._cache[key];
  }
  // Fire-and-forget refresh; caller re-reads from cache on next render.
  WG.fetchData(apiPath).then(function(data) {
    if (data != null) {
      WG._cache[key] = data;
      WG._cacheTime[key] = Date.now();
    }
  });
  return WG._cache[key] || [];
};

/* Invalidate cache after mutations */
WG.invalidateCache = function(key) {
  if (key) { delete WG._cache[key]; delete WG._cacheTime[key]; }
  else { WG._cache = {}; WG._cacheTime = {}; }
};

/* Refresh list data from the server and re-render a page ONLY when the new
 * data differs from the currently cached copy. Prevents the UI "blink" that
 * used to fire on every page mount because list pages unconditionally
 * replaced the mainContent DOM after every background fetch — even when
 * nothing changed. 95% of revisits return identical data, so skipping the
 * re-render is the right default.
 *
 * Guards:
 *   - page-name check: won't rerender if the user has navigated away
 *   - modal-active check: won't wipe an open dialog
 *   - JSON-signature compare: cheap O(N) diff on typical list sizes */
WG.refreshAndRerender = function(key, apiPath, renderFn, pageName) {
  WG.fetchData(apiPath).then(function(data) {
    if (data == null) return;
    if (pageName && WG.state.currentPage !== pageName) return;
    if (document.querySelector('.modal-overlay.active')) return;
    var prev = WG._cache[key];
    var sig = JSON.stringify(data);
    if (prev && JSON.stringify(prev) === sig) {
      /* Touch the timestamp so getCached treats it as fresh, but no DOM op. */
      WG._cacheTime[key] = Date.now();
      return;
    }
    WG._cache[key] = data;
    WG._cacheTime[key] = Date.now();
    var main = document.getElementById('mainContent');
    if (!main) return;
    main.textContent = '';
    main.insertAdjacentHTML('beforeend', renderFn());
  });
};
