WG._topo = WG._topo || {};

WG._topoToggleExport = function() {
  var menu = document.getElementById('topoExportMenu');
  if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
};

WG._topoExportSVG = function() {
  var svg = document.getElementById('topoSvg');
  if (!svg) return;
  var clone = svg.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.style.background = '#0f1419';
  var blob = new Blob([new XMLSerializer().serializeToString(clone)], { type: 'image/svg+xml' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = 'wireghost-topology.svg'; a.click();
  URL.revokeObjectURL(url);
  WG._topoToggleExport();
  WG.toast('SVG exported', 'success');
};

WG._topoExportPNG = function() {
  var svg = document.getElementById('topoSvg');
  if (!svg) return;
  var clone = svg.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.style.background = '#0f1419';
  var svgData = new XMLSerializer().serializeToString(clone);
  var img = new Image();
  var w = parseInt(svg.getAttribute('width')) * 2;
  var h = parseInt(svg.getAttribute('height')) * 2;
  img.onload = function() {
    var canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#0f1419';
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    var a = document.createElement('a');
    a.href = canvas.toDataURL('image/png');
    a.download = 'wireghost-topology.png'; a.click();
    WG.toast('PNG exported', 'success');
  };
  img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
  WG._topoToggleExport();
};

WG._topoToggleFullscreen = function() {
  var panel = document.getElementById('topoGraphPanel');
  if (!panel) return;
  var s = WG._topo.state;

  if (s.fullscreen) {
    WG._topoExitFullscreen();
    return;
  }

  s.fullscreen = true;
  s._fsRestore = {
    position: panel.style.position, inset: panel.style.inset,
    zIndex: panel.style.zIndex, width: panel.style.width, height: panel.style.height
  };

  if (panel.requestFullscreen) {
    panel.requestFullscreen().catch(function() { WG._topoFallbackFs(panel); });
  } else {
    WG._topoFallbackFs(panel);
  }

  WG._topo._fsHandler = function() {
    if (!document.fullscreenElement) WG._topoExitFullscreen();
  };
  document.addEventListener('fullscreenchange', WG._topo._fsHandler);

  setTimeout(function() {
    var container = document.getElementById('topoContainer');
    if (container && s.svg) {
      container.style.height = '100vh';
      s.svg.attr('width', window.innerWidth).attr('height', window.innerHeight);
      if (s.simulation) s.simulation.force('center', d3.forceCenter(window.innerWidth / 2, window.innerHeight / 2)).alpha(0.3).restart();
    }
  }, 100);
};

WG._topoFallbackFs = function(panel) {
  panel.style.position = 'fixed';
  panel.style.inset = '0';
  panel.style.zIndex = '500';
  panel.style.width = '100vw';
  panel.style.height = '100vh';
};

WG._topoExitFullscreen = function() {
  var s = WG._topo.state;
  s.fullscreen = false;
  var panel = document.getElementById('topoGraphPanel');

  if (document.fullscreenElement) {
    document.exitFullscreen().catch(function() {});
  }

  if (panel && s._fsRestore) {
    panel.style.position = s._fsRestore.position || '';
    panel.style.inset = s._fsRestore.inset || '';
    panel.style.zIndex = s._fsRestore.zIndex || '';
    panel.style.width = s._fsRestore.width || '';
    panel.style.height = s._fsRestore.height || '';
  }

  if (WG._topo._fsHandler) {
    document.removeEventListener('fullscreenchange', WG._topo._fsHandler);
    WG._topo._fsHandler = null;
  }

  var container = document.getElementById('topoContainer');
  if (container && s.svg) {
    container.style.height = '600px';
    var w = container.clientWidth || 800;
    s.svg.attr('width', w).attr('height', 600);
    if (s.simulation) s.simulation.force('center', d3.forceCenter(w / 2, 300)).alpha(0.3).restart();
  }
};
