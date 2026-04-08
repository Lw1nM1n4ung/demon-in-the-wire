/* Wire_Ghost Interactive Dashboard */
(function () {
  "use strict";

  var DATA = window.__SCAN_DATA__ || {};
  var palette = {
    critical: "#b22222",
    high: "#ff0000",
    medium: "#ff8c00",
    low: "#daa520",
    info: "#6495ed"
  };
  var sevOrder = ["critical", "high", "medium", "low", "info"];

  /* ── Severity Doughnut Chart ── */
  function initSeverityChart() {
    if (typeof Chart === "undefined") return;
    var canvas = document.getElementById("severityChart");
    if (!canvas) return;

    var stats = DATA.severity_stats || {};
    var labels = [];
    var values = [];
    var colors = [];

    for (var i = 0; i < sevOrder.length; i++) {
      var sev = sevOrder[i];
      var count = stats[sev] || 0;
      if (count > 0) {
        labels.push(sev.charAt(0).toUpperCase() + sev.slice(1));
        values.push(count);
        colors.push(palette[sev]);
      }
    }

    if (values.length === 0) return;

    new Chart(canvas, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: "#161b22",
          borderWidth: 3,
          hoverBorderWidth: 0
        }]
      },
      options: {
        responsive: true,
        cutout: "65%",
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#c9d1d9",
              font: { size: 11, family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" },
              padding: 16,
              usePointStyle: true,
              pointStyleWidth: 10
            }
          }
        }
      }
    });
  }

  /* ── Source Horizontal Bar Chart ── */
  function initSourceChart() {
    if (typeof Chart === "undefined") return;
    var canvas = document.getElementById("sourceChart");
    if (!canvas) return;

    var sc = DATA.source_counts || {};
    var labels = [];
    var values = [];
    var sourceNames = ["nuclei", "nmap_vuln", "searchsploit", "openvas", "nettacker"];
    var sourceLabels = {
      nuclei: "Nuclei",
      nmap_vuln: "Nmap Vuln",
      searchsploit: "SearchSploit",
      openvas: "OpenVAS",
      nettacker: "Nettacker"
    };

    for (var i = 0; i < sourceNames.length; i++) {
      var s = sourceNames[i];
      var c = sc[s] || 0;
      if (c > 0) {
        labels.push(sourceLabels[s] || s);
        values.push(c);
      }
    }

    if (values.length === 0) return;

    new Chart(canvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: "#006D38",
          borderColor: "#00945c",
          borderWidth: 1,
          borderRadius: 4,
          barThickness: 28
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: {
              color: "#8b949e",
              font: { size: 11 },
              stepSize: 1
            },
            grid: { color: "rgba(48,54,61,0.5)" }
          },
          y: {
            ticks: {
              color: "#c9d1d9",
              font: { size: 12, weight: "600" }
            },
            grid: { display: false }
          }
        }
      }
    });
  }

  /* ── State ── */
  var sevActive = {};
  for (var si = 0; si < sevOrder.length; si++) {
    // INFO hidden by default (too much noise — tech detection, headers, etc.)
    sevActive[sevOrder[si]] = sevOrder[si] !== "info";
  }
  var currentSource = "all";
  var currentSort = "severity";
  var searchQuery = "";

  /* ── Severity filter toggles ── */
  function initSevFilters() {
    var buttons = document.querySelectorAll(".sev-btn");
    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var sev = btn.getAttribute("data-sev");
        sevActive[sev] = !sevActive[sev];
        btn.classList.toggle("off", !sevActive[sev]);
        applyFilters();
      });
    });
  }

  /* ── Source filter ── */
  function initSourceFilter() {
    var sel = document.getElementById("sourceFilter");
    if (!sel) return;
    sel.addEventListener("change", function () {
      currentSource = sel.value;
      applyFilters();
    });
  }

  /* ── Sort ── */
  function initSort() {
    var sel = document.getElementById("sortSelect");
    if (!sel) return;
    sel.addEventListener("change", function () {
      currentSort = sel.value;
      sortFindings();
      applyFilters();
    });
  }

  /* ── Search ── */
  function initSearch() {
    var input = document.getElementById("searchInput");
    if (!input) return;
    input.addEventListener("input", function () {
      searchQuery = input.value.toLowerCase();
      applyFilters();
    });
  }

  /* ── Apply all filters ── */
  function applyFilters() {
    var cards = document.querySelectorAll(".finding-card");
    var visibleCount = 0;
    cards.forEach(function (card) {
      var sev = card.getAttribute("data-severity");
      var source = card.getAttribute("data-source");
      var text = card.textContent.toLowerCase();

      var sevMatch = sevActive[sev] !== false;
      var sourceMatch = currentSource === "all" || source === currentSource;
      var searchMatch = !searchQuery || text.indexOf(searchQuery) !== -1;

      var visible = sevMatch && sourceMatch && searchMatch;
      card.style.display = visible ? "" : "none";
      if (visible) visibleCount++;
    });

    var noResults = document.getElementById("noResults");
    if (noResults) {
      noResults.style.display = visibleCount === 0 ? "block" : "none";
    }
  }

  /* ── Sort findings ── */
  function sortFindings() {
    var container = document.getElementById("findingsList");
    if (!container) return;

    var cards = Array.prototype.slice.call(container.querySelectorAll(".finding-card"));
    var sevPriority = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    cards.sort(function (a, b) {
      if (currentSort === "host") {
        var hostA = a.getAttribute("data-host") || "";
        var hostB = b.getAttribute("data-host") || "";
        if (hostA !== hostB) return hostA.localeCompare(hostB);
      }
      var sa = sevPriority[a.getAttribute("data-severity")] || 99;
      var sb = sevPriority[b.getAttribute("data-severity")] || 99;
      return sa - sb;
    });

    for (var i = 0; i < cards.length; i++) {
      container.appendChild(cards[i]);
    }
  }

  /* ── Finding card click to collapse (all start open) ── */
  function initFindingCards() {
    // All cards start open — mark them
    document.querySelectorAll(".finding-card").forEach(function (card) {
      card.classList.add("open");
    });

    document.querySelectorAll(".finding-header").forEach(function (header) {
      header.addEventListener("click", function () {
        var card = header.closest(".finding-card");
        var detail = card.querySelector(".finding-detail");
        if (!detail) return;

        var isOpen = card.classList.contains("open");
        card.classList.toggle("open", !isOpen);
        detail.style.display = isOpen ? "none" : "";
      });
    });
  }

  /* ── Copy curl command ── */
  function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.stopPropagation();
        var codeEl = btn.closest(".curl-section").querySelector("code");
        if (!codeEl) return;

        var text = codeEl.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            showCopied(btn);
          });
        } else {
          // Fallback
          var ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.left = "-9999px";
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          document.body.removeChild(ta);
          showCopied(btn);
        }
      });
    });
  }

  function showCopied(btn) {
    var original = btn.textContent;
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(function () {
      btn.textContent = original;
      btn.classList.remove("copied");
    }, 1500);
  }

  /* ── Host panel toggle ── */
  function initHostPanels() {
    document.querySelectorAll(".host-toggle").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var panel = btn.closest(".host-panel");
        var detail = panel.querySelector(".host-detail");
        if (!detail) return;

        var isOpen = panel.classList.contains("open");
        panel.classList.toggle("open", !isOpen);
        detail.style.display = isOpen ? "none" : "block";
      });
    });
  }

  /* ── Bootstrap ── */
  document.addEventListener("DOMContentLoaded", function () {
    initSeverityChart();
    initSourceChart();
    initSevFilters();
    initSourceFilter();
    initSort();
    initSearch();
    initFindingCards();
    initCopyButtons();
    // Apply initial filter (hides INFO by default)
    applyFilters();
    initHostPanels();
  });
})();
