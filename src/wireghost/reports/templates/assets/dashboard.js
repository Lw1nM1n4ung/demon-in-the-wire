/* Wire_Ghost Interactive Dashboard */
(function () {
  "use strict";

  var DATA = window.__SCAN_DATA__ || {};
  var findings = DATA.findings || [];

  /* ── Chart.js doughnut ── */
  function initChart() {
    if (typeof Chart === "undefined") return;
    var canvas = document.getElementById("sevChart");
    if (!canvas) return;

    var stats = DATA.severity_stats || {};
    var labels = [];
    var values = [];
    var colors = [];

    var palette = {
      critical: "#b22222",
      high: "#ff0000",
      medium: "#ff8c00",
      low: "#daa520",
      info: "#6495ed"
    };

    var order = ["critical", "high", "medium", "low", "info"];
    for (var i = 0; i < order.length; i++) {
      var sev = order[i];
      var count = stats[sev] || 0;
      if (count > 0) {
        labels.push(sev.toUpperCase());
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
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#c9d1d9", font: { size: 11 } }
          }
        }
      }
    });
  }

  /* ── Severity filter toggles ── */
  function initFilters() {
    var buttons = document.querySelectorAll(".sev-btn");
    var activeSet = {};
    buttons.forEach(function (btn) {
      activeSet[btn.getAttribute("data-sev")] = true;
    });

    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var sev = btn.getAttribute("data-sev");
        activeSet[sev] = !activeSet[sev];
        btn.classList.toggle("off", !activeSet[sev]);
        filterTable(activeSet);
      });
    });

    window._sevActiveSet = activeSet;
  }

  function filterTable(activeSet) {
    var rows = document.querySelectorAll("#findingsTable tbody tr");
    var query = (document.getElementById("searchInput") || {}).value || "";
    query = query.toLowerCase();

    rows.forEach(function (row) {
      var sev = row.getAttribute("data-sev");
      var text = row.textContent.toLowerCase();
      var sevMatch = activeSet[sev] !== false;
      var searchMatch = !query || text.indexOf(query) !== -1;
      row.style.display = sevMatch && searchMatch ? "" : "none";
    });
  }

  /* ── Search ── */
  function initSearch() {
    var input = document.getElementById("searchInput");
    if (!input) return;
    input.addEventListener("input", function () {
      filterTable(window._sevActiveSet || {});
    });
  }

  /* ── Collapsible host panels ── */
  function initHostPanels() {
    var toggles = document.querySelectorAll(".host-toggle");
    toggles.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var body = btn.nextElementSibling;
        if (body) body.classList.toggle("open");
      });
    });
  }

  /* ── Bootstrap ── */
  document.addEventListener("DOMContentLoaded", function () {
    initChart();
    initFilters();
    initSearch();
    initHostPanels();
  });
})();
