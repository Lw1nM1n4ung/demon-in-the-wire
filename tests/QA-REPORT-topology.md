# QA Report — Enhanced Network Topology Module

**Date:** 2026-04-27
**Scope:** 11 JS modules (`web/js/app/pages/topology/`), backend API enrichment (`views.py:189-355`), supporting changes (`app.html`, `router.js`, `variables.css`)
**Stack:** Python 3.12 / Django + DRF (backend), Vanilla JS + D3.js v7 (frontend), Node.js v20 (JS tests)

---

## Targets

| File | Lines | Role |
|---|---|---|
| `topology/core.js` | 700 | Orchestrator: state, teardown, page render, D3 graph |
| `topology/heatmap.js` | 95 | Risk score, glow filters, halo circles, size mode |
| `topology/search.js` | 70 | Search index, debounced query, match/dim classes |
| `topology/ports.js` | 146 | Expand/collapse port satellites, LRU cap, rebind |
| `topology/edges.js` | 46 | Decorative inter-host edges (CVE/service) |
| `topology/cluster.js` | 127 | Auto-cluster >50 hosts, expand/collapse |
| `topology/layouts.js` | 120 | Force/tree/radial/grid layout modes |
| `topology/minimap.js` | 101 | Overview minimap with viewport rect |
| `topology/contextmenu.js` | 79 | Right-click menu with 5 actions |
| `topology/export.js` | 123 | SVG/PNG export, fullscreen toggle |
| `topology/live.js` | 87 | Live scan polling, node merge |
| `views.py` (topology action) | 167 | Enriched API: risk_score, cves, edges, caching |
| `app.html` | +11 | Script tag swap (1→11) |
| `router.js` | +1 | Teardown call on nav |
| `variables.css` | +12 | Keyframes + utility classes |

**Total new/modified:** ~1,700 lines JS + 167 lines Python

---

## Tests Written

### Frontend (Node.js — `tests/test_topology_js.js`)

| Suite | Tests | Status |
|---|---|---|
| Risk Score | 8 | ✅ |
| Search Index | 8 | ✅ |
| Auto-Clustering | 4 | ✅ |
| getBounds | 3 | ✅ |
| Service/Severity Colors | 3 | ✅ |
| Fresh State + Backward Compat | 3 | ✅ |
| Size Mode | 3 | ✅ |
| Port Expansion (LRU, toggle) | 4 | ✅ |
| Edge Toggle | 1 | ✅ |
| Teardown | 1 | ✅ |
| **Total** | **38** | **38/38 pass** |

### Backend (Django — `scanner/tests/test_topology.py`)

| Suite | Tests | Status |
|---|---|---|
| TopologyEndpointTests | 23 | ✅ |
| TopologyRBACTests | 2 | ✅ |
| **Total** | **25** | **25/25 pass** |

**Combined: 63 tests, 63 passing.**

---

## Static Review Findings

### Fixed (6 issues)

| # | Severity | File | Issue | Fix |
|---|---|---|---|---|
| 1 | **CRITICAL** | `core.js:208` | D3 simulation leak on scan-switch — `_topoRenderGraph` never stopped old simulation before creating new one | Added `s.simulation.stop()` + `clearInterval(s.pollHandle)` guard at top of `_topoRenderGraph` |
| 2 | **CRITICAL** | `ports.js:53` | Operator precedence bug: `!src.indexOf('port_') === 0` — `!` binds before `===`, always evaluates false | Replaced broken double-filter with single correct predicate using `src.type === 'port'` check |
| 3 | **HIGH** | `live.js:14` | Scan completion handler called `_topoLoadScan()` which full-re-renders, discarding user state (zoom, expanded ports, layout) | Changed to `_topoMergeUpdate()` for data-only update |
| 4 | **HIGH** | `edges.js:7-11` | `_edgeNodeMap` built once, never rebuilt after cluster expand/collapse — edges render at (0,0) | Added map rebuild in `_topoRebindGraph()` |
| 5 | **MEDIUM** | `search.js:20` | `_searchTimer` not cleared on teardown — dangling 150ms timer after navigation | Added `clearTimeout` in `_topoTeardown()` |
| 6 | **MEDIUM** | `cluster.js:108` | Collapse link filter fails for unresolved string source IDs (before simulation tick resolves them) | Added fallback check: remove links whose source node no longer exists in `s.nodes` |

### Verified Clean

| Area | Status |
|---|---|
| XSS / injection | ✅ All user-facing data uses `textContent` or `WG.escHtml()`. No raw `innerHTML` with user input. |
| Backend SQL injection | ✅ Pure ORM queries — no `raw()`, `extra()`, or string interpolation. |
| Cache key collision | ✅ `topo:{scan.id}:{updated_at.timestamp()}` — unique per scan+version. |
| Backend auth bypass | ✅ `self.get_object()` enforces DRF permission classes. |
| Event listener leaks | ✅ Context menu dismissal cleans up both `click` and `keydown` listeners. Teardown clears fullscreen listener. |
| Memory: intervals | ✅ `pollHandle` cleared on teardown, on scan completion, and on re-render. |
| D3 enter/update/exit | ✅ All selections use `.data(…, keyFn)` + `.enter()` + `.merge()` + `.exit().remove()` correctly. |

---

## Coverage

| Layer | Covered | Not Covered |
|---|---|---|
| Risk score formula | ✅ 8 tests | — |
| Search index + query | ✅ 8 tests | Visual DOM class application (requires browser) |
| Clustering logic | ✅ 4 tests | `expandCluster` / `collapseCluster` (requires D3 sim) |
| Port expansion LRU | ✅ 4 tests | Visual satellite positioning (requires SVG) |
| Minimap getBounds | ✅ 3 tests | Minimap viewport drag (requires D3 zoom) |
| Layout modes | — | Requires D3 tree/cluster/transition (integration) |
| Backend topology API | ✅ 25 tests | — |
| Backend edge cap | ✅ 1 test | >3-edge-per-host scenario (needs 4+ CVE-sharing hosts) |

**Estimated line coverage:** ~70% (pure logic fully covered; D3-dependent rendering requires browser/Playwright integration tests)

---

## Recommendations

1. **Playwright integration test**: Load topology page with a real scan, verify nodes render, search highlights, layout switch animates. Would cover the remaining 30%.
2. **Edge cap stress test**: Create 10+ hosts all sharing 5+ CVEs to verify the 3-per-host cap under heavy edge density.
3. **Performance profiling**: Test with 100+ and 500+ hosts to validate `alphaDecay(0.03)` guard and clustering threshold.
