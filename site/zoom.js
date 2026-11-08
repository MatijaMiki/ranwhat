// Screenshots that open full screen on click (/install, /commands), the same as the cenner.hr blog. The picture grows
// from where it sits to fit the screen and shrinks back on close (Esc, a click or the button), over a light veil.
// The page does not scroll while it is open, and the scrollbar stays, so nothing reflows. No motion when the
// visitor asks for reduced motion.
(() => {
  const MS = 200;
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const ease = MS + 'ms cubic-bezier(0.22, 1, 0.36, 1)';

  const fitBox = (img) => {
    const ratio = (img.naturalWidth || 16) / (img.naturalHeight || 10);
    const maxW = innerWidth * 0.96, maxH = innerHeight * 0.92;
    const width = Math.min(maxW, maxH * ratio), height = width / ratio;
    return { left: (innerWidth - width) / 2, top: (innerHeight - height) / 2, width, height };
  };
  const boxOf = (el) => { const r = el.getBoundingClientRect(); return { left: r.left, top: r.top, width: r.width, height: r.height }; };
  // The part of the thumbnail hidden under the sticky bar or below the screen, so the first frame never covers the bar.
  const cutOf = (el) => {
    const r = el.getBoundingClientRect();
    const bar = document.querySelector('header');
    const barBottom = bar ? bar.getBoundingClientRect().bottom : 0;
    return { t: Math.max(0, Math.min(r.height, barBottom - r.top)), b: Math.max(0, Math.min(r.height, r.bottom - innerHeight)) };
  };
  const place = (el, box, cut) => {
    el.style.left = box.left + 'px'; el.style.top = box.top + 'px';
    el.style.width = box.width + 'px'; el.style.height = box.height + 'px';
    el.style.clipPath = 'inset(' + cut.t + 'px 0 ' + cut.b + 'px 0)';
  };

  const zoom = (thumb) => {
    let veil, big, shut, closing = false, x0, y0;
    const stop = (e) => e.preventDefault();
    const hold = () => { if (scrollY !== y0 || scrollX !== x0) scrollTo(x0, y0); };
    const onKey = (e) => {
      if (e.key === 'Escape') close();
      else if ([' ', 'PageUp', 'PageDown', 'Home', 'End', 'ArrowUp', 'ArrowDown'].includes(e.key)) e.preventDefault();
    };
    const onResize = () => { if (!closing) place(big, fitBox(thumb), { t: 0, b: 0 }); };
    const listen = (on) => {
      const f = on ? addEventListener : removeEventListener;
      f('wheel', stop, { passive: false }); f('touchmove', stop, { passive: false });
      f('scroll', hold); f('keydown', onKey); f('resize', onResize);
    };

    function close() {
      if (closing) return;
      closing = true;
      place(big, boxOf(thumb), cutOf(thumb));
      veil.style.transition = 'opacity ' + Math.round(MS * 0.6) + 'ms ease';
      veil.style.opacity = '0'; shut.style.opacity = '0';
      listen(false);
      setTimeout(() => { thumb.style.visibility = ''; veil.remove(); big.remove(); shut.remove(); thumb.closest('button').focus({ preventScroll: true }); }, reduce ? 0 : MS);
    }

    return async () => {
      if (big && big.isConnected) return;
      const src = thumb.currentSrc || thumb.src;
      // Decode first, so there is no blank frame between the thumbnail and the big picture.
      try { const pre = new Image(); pre.src = src; await pre.decode(); } catch (e) { /* shows when it loads */ }
      closing = false; x0 = scrollX; y0 = scrollY;
      veil = document.createElement('div');
      veil.className = 'zoom-veil';
      veil.addEventListener('click', close);
      big = document.createElement('img');
      big.className = 'zoom-big';
      big.src = src; big.alt = thumb.alt;
      big.setAttribute('role', 'dialog'); big.setAttribute('aria-modal', 'true'); big.setAttribute('aria-label', thumb.alt);
      big.addEventListener('click', close);
      shut = document.createElement('button');
      shut.type = 'button'; shut.className = 'zoom-close'; shut.textContent = 'Close';
      shut.setAttribute('aria-label', 'Close the picture');
      shut.addEventListener('click', close);
      if (!reduce) {
        big.style.transition = ['left', 'top', 'width', 'height', 'clip-path'].map((p) => p + ' ' + ease).join(', ');
        veil.style.transition = 'opacity ' + MS + 'ms ease';
        shut.style.transition = 'opacity 120ms ease';
      }
      place(big, boxOf(thumb), cutOf(thumb));
      document.body.append(veil, big, shut);
      thumb.style.visibility = 'hidden';
      listen(true);
      requestAnimationFrame(() => requestAnimationFrame(() => {
        place(big, fitBox(thumb), { t: 0, b: 0 });
        veil.style.opacity = '1'; shut.style.opacity = '1';
        shut.focus({ preventScroll: true });
      }));
    };
  };

  for (const img of document.querySelectorAll('.shot img')) {
    const pic = img.closest('picture') || img;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'shot__zoom';
    btn.setAttribute('aria-label', 'Enlarge: ' + img.alt);
    pic.replaceWith(btn);
    btn.append(pic);
    btn.addEventListener('click', zoom(img));
  }
})();
