(function() {
  var overlay, img, caption, items, idx;

  function create() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'lightbox-overlay';
    overlay.onclick = function(e) { if (e.target === overlay) close(); };

    var wrap = document.createElement('div');
    wrap.className = 'lightbox-wrap';

    var prev = document.createElement('button');
    prev.className = 'lightbox-nav lightbox-prev';
    prev.textContent = '‹';
    prev.onclick = function() { navigate(-1); };

    var next = document.createElement('button');
    next.className = 'lightbox-nav lightbox-next';
    next.textContent = '›';
    next.onclick = function() { navigate(1); };

    img = document.createElement('img');
    img.className = 'lightbox-img';

    caption = document.createElement('div');
    caption.className = 'lightbox-caption';

    var closeBtn = document.createElement('button');
    closeBtn.className = 'lightbox-close';
    closeBtn.textContent = '×';
    closeBtn.onclick = close;

    wrap.appendChild(prev);
    wrap.appendChild(img);
    wrap.appendChild(next);
    overlay.appendChild(closeBtn);
    overlay.appendChild(wrap);
    overlay.appendChild(caption);
    document.body.appendChild(overlay);

    document.addEventListener('keydown', function(e) {
      if (!overlay.classList.contains('active')) return;
      if (e.key === 'Escape') close();
      if (e.key === 'ArrowLeft') navigate(-1);
      if (e.key === 'ArrowRight') navigate(1);
    });
  }

  function open(screenshots, startIdx) {
    create();
    items = screenshots;
    idx = startIdx || 0;
    show();
    overlay.classList.add('active');
  }

  function show() {
    if (!items || !items[idx]) return;
    var s = items[idx];
    img.src = s.image_url;
    img.alt = s.url || '';
    var text = s.url || '';
    if (s.title) text += ' — ' + s.title;
    if (s.status_code) text += ' [' + s.status_code + ']';
    caption.textContent = text;
  }

  function navigate(dir) {
    if (!items || items.length < 2) return;
    idx = (idx + dir + items.length) % items.length;
    show();
  }

  function close() {
    if (overlay) overlay.classList.remove('active');
  }

  window.WGLightbox = { open: open, close: close };
})();
