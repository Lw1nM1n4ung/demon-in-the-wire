/* Wire_Ghost — API service (production)
   Every page should call WG.fetchData() which tries API first, falls back to mock. */

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

    if (res.status === 401 || res.status === 403) {
      if (path !== '/auth/login/' && path !== '/auth/csrf/' && path !== '/dashboard/') {
        WG.clearSession();
        window.location.hash = '#login';
        return null;
      }
    }

    if (!res.ok) {
      // 404 means resource not found — don't switch to mock mode
      if (res.status === 404) return null;
      throw new Error(res.statusText);
    }
    WG.USE_MOCK = false;
    return await res.json();
  } catch (e) {
    WG.USE_MOCK = true;
    return null;
  }
};

/* Fetch data — tries API first, falls back to mock */
WG.fetchData = async function(apiPath, mockType) {
  var data = await WG.api(apiPath);
  if (data) {
    // API returns paginated or direct
    return data.results || data;
  }
  return WG.MOCK[mockType] || [];
};

WG.getMock = function(type) {
  return WG.MOCK[type] || [];
};

/* Cache for API data — avoids re-fetching on every render */
WG._cache = {};
WG._cacheTime = {};

WG.getCached = function(key, apiPath, mockType, maxAge) {
  maxAge = maxAge || 30000; // 30 sec default
  var now = Date.now();
  if (WG._cache[key] && (now - WG._cacheTime[key]) < maxAge) {
    return WG._cache[key];
  }
  // Return mock immediately, fetch in background
  WG.fetchData(apiPath, mockType).then(function(data) {
    WG._cache[key] = data;
    WG._cacheTime[key] = Date.now();
  });
  return WG._cache[key] || WG.MOCK[mockType] || [];
};

/* Invalidate cache after mutations */
WG.invalidateCache = function(key) {
  if (key) { delete WG._cache[key]; delete WG._cacheTime[key]; }
  else { WG._cache = {}; WG._cacheTime = {}; }
};
