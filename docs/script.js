/* Neuron Encrypt site interactions — vanilla JS, no dependencies, GitLab Pages safe */
(function () {
  'use strict';

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var finePointer = window.matchMedia && window.matchMedia('(pointer: fine)').matches;

  /* ---------- Preloader ---------- */
  var preloader = document.getElementById('preloader');
  document.documentElement.classList.add('preload');
  function hidePreloader() {
    document.documentElement.classList.remove('preload');
    if (preloader) preloader.classList.add('done');
  }
  if (document.readyState === 'complete') {
    window.setTimeout(hidePreloader, 250);
  } else {
    window.addEventListener('load', function () { window.setTimeout(hidePreloader, 250); });
    window.setTimeout(hidePreloader, 2600); /* never trap the user */
  }

  /* ---------- Year ---------- */
  var yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  /* ---------- Announcement bar (dismiss persists) ---------- */
  var announce = document.getElementById('announce');
  var announceClose = document.getElementById('announce-close');
  try {
    if (announce && window.localStorage && localStorage.getItem('ne-announce-dismissed') === '1') {
      announce.classList.add('dismissed');
    }
  } catch (err) { /* private mode safe */ }
  if (announceClose && announce) {
    announceClose.addEventListener('click', function () {
      announce.classList.add('dismissed');
      try { if (window.localStorage) localStorage.setItem('ne-announce-dismissed', '1'); } catch (err) { /* ignore */ }
    });
  }

  /* ---------- Nav: menu, scrolled, progress, active link, back-to-top ---------- */
  var nav = document.getElementById('nav');
  var menuToggle = document.getElementById('menu-toggle');
  var navLinks = document.getElementById('nav-links');
  var navAnchors = navLinks ? Array.prototype.slice.call(navLinks.querySelectorAll('a')) : [];
  var progressBar = document.getElementById('scroll-progress-bar');
  var backToTop = document.getElementById('back-to-top');

  function closeMenu() {
    if (!menuToggle || !navLinks) return;
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.setAttribute('aria-label', 'Open navigation');
    navLinks.classList.remove('open');
  }
  if (menuToggle && navLinks) {
    menuToggle.addEventListener('click', function () {
      var isOpen = menuToggle.getAttribute('aria-expanded') === 'true';
      menuToggle.setAttribute('aria-expanded', String(!isOpen));
      menuToggle.setAttribute('aria-label', isOpen ? 'Open navigation' : 'Close navigation');
      navLinks.classList.toggle('open', !isOpen);
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeMenu(); closeLightbox(); } });
    navLinks.addEventListener('click', function (e) { if (e.target.closest('a')) closeMenu(); });
    document.addEventListener('click', function (e) {
      if (!navLinks.classList.contains('open')) return;
      if (e.target.closest('#nav-links') || e.target.closest('#menu-toggle')) return;
      closeMenu();
    });
  }

  var ticking = false;
  function onScroll() {
    ticking = false;
    var y = window.scrollY || window.pageYOffset;
    if (nav) nav.classList.toggle('scrolled', y > 18);
    var max = document.documentElement.scrollHeight - window.innerHeight;
    if (progressBar) progressBar.style.width = (max > 0 ? Math.min(100, (y / max) * 100) : 0) + '%';
    if (backToTop) backToTop.classList.toggle('visible', y > 700);
  }
  window.addEventListener('scroll', function () {
    if (!ticking) { ticking = true; window.requestAnimationFrame(onScroll); }
  }, { passive: true });
  onScroll();
  if (backToTop) backToTop.addEventListener('click', function () { window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' }); });

  /* Smooth anchor offset */
  document.querySelectorAll('a[href^="#"]').forEach(function (link) {
    link.addEventListener('click', function (e) {
      var href = link.getAttribute('href');
      if (!href || href === '#') return;
      var target = document.querySelector(href);
      if (!target) return;
      e.preventDefault();
      var top = target.getBoundingClientRect().top + window.scrollY - 84;
      window.scrollTo({ top: Math.max(0, top), behavior: reduceMotion ? 'auto' : 'smooth' });
      try { history.replaceState(null, '', href); } catch (err) { /* file:// safe */ }
      if (target.hasAttribute('tabindex')) target.focus({ preventScroll: true });
    });
  });

  /* Active nav highlighting */
  if ('IntersectionObserver' in window && navAnchors.length) {
    var sections = navAnchors.map(function (a) { return document.querySelector(a.getAttribute('href')); }).filter(Boolean);
    var navObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        navAnchors.forEach(function (a) { a.classList.toggle('active', a.getAttribute('href') === '#' + entry.target.id); });
      });
    }, { rootMargin: '-35% 0px -55% 0px', threshold: 0 });
    sections.forEach(function (s) { navObserver.observe(s); });
  }

  /* ---------- Reveal on scroll ---------- */
  var revealEls = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && !reduceMotion) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) { entry.target.classList.add('visible'); revealObserver.unobserve(entry.target); }
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -30px 0px' });
    revealEls.forEach(function (el, i) {
      el.style.transitionDelay = Math.min((i % 4) * 70, 210) + 'ms';
      revealObserver.observe(el);
    });
  } else {
    revealEls.forEach(function (el) { el.classList.add('visible'); });
  }

  /* ---------- Animated counters ---------- */
  var counters = document.querySelectorAll('.hero-proof strong[data-count]');
  var counted = false;
  function animateCounters() {
    if (counted) return;
    var proof = document.querySelector('.hero-proof');
    if (!proof) return;
    var r = proof.getBoundingClientRect();
    if (r.top >= window.innerHeight || r.bottom <= 0) return;
    counted = true;
    counters.forEach(function (stat) {
      var target = parseInt(stat.getAttribute('data-count'), 10);
      var suffix = stat.getAttribute('data-suffix') || '';
      if (isNaN(target)) return;
      if (reduceMotion) { stat.textContent = target + suffix; return; }
      var start = null;
      var dur = 1100;
      function frame(t) {
        if (!start) start = t;
        var p = Math.min(1, (t - start) / dur);
        var eased = 1 - Math.pow(1 - p, 3);
        stat.textContent = Math.round(target * eased) + suffix;
        if (p < 1) window.requestAnimationFrame(frame);
      }
      window.requestAnimationFrame(frame);
    });
  }
  window.addEventListener('scroll', animateCounters, { passive: true });
  animateCounters();

  /* ---------- Generic tabs (product + install) ---------- */
  function initTabs(tabList) {
    var tabs = Array.prototype.slice.call(tabList.querySelectorAll('[role="tab"]'));
    if (!tabs.length) return;
    function activate(tab, focus) {
      tabs.forEach(function (t) {
        var selected = t === tab;
        t.classList.toggle('active', selected);
        t.setAttribute('aria-selected', String(selected));
        t.tabIndex = selected ? 0 : -1;
        var panel = document.getElementById(t.getAttribute('aria-controls'));
        if (panel) {
          panel.hidden = !selected;
          panel.classList.toggle('active', selected);
        }
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (tab, i) {
      tab.addEventListener('click', function () { activate(tab, false); });
      tab.addEventListener('keydown', function (e) {
        var next = null;
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = tabs[(i + 1) % tabs.length];
        if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = tabs[(i - 1 + tabs.length) % tabs.length];
        if (e.key === 'Home') next = tabs[0];
        if (e.key === 'End') next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); activate(next, true); }
      });
    });
  }
  document.querySelectorAll('[role="tablist"]').forEach(initTabs);

  /* ---------- Toast ---------- */
  var toast = document.getElementById('toast');
  var toastTimer = null;
  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.hidden = false;
    window.requestAnimationFrame(function () { toast.classList.add('show'); });
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () {
      toast.classList.remove('show');
      window.setTimeout(function () { toast.hidden = true; }, 300);
    }, 2200);
  }

  /* ---------- Copy buttons ---------- */
  function decodeEntities(s) {
    var ta = document.createElement('textarea');
    ta.innerHTML = s;
    return ta.value;
  }
  document.querySelectorAll('.copy-button').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var raw = btn.getAttribute('data-copy') || '';
      var text = decodeEntities(raw).replace(/&quot;/g, '"');
      function done() {
        var original = btn.textContent;
        btn.textContent = 'Copied ✓';
        showToast('Copied to clipboard');
        window.setTimeout(function () { btn.textContent = original; }, 1500);
      }
      function fallback() {
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); done(); } catch (e) { showToast('Copy failed — select manually'); }
        document.body.removeChild(area);
      }
      if (navigator.clipboard && window.isSecureContext !== false && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(fallback);
      } else { fallback(); }
    });
  });

  /* ---------- OS detection → highlight download card ---------- */
  (function detectOS() {
    var hint = document.getElementById('os-hint');
    var ua = (navigator.userAgent || '').toLowerCase();
    var platform = (navigator.userAgentData && navigator.userAgentData.platform ? navigator.userAgentData.platform : navigator.platform || '').toLowerCase();
    var os = null;
    if (/android/.test(ua)) os = 'android';
    else if (/win/.test(platform) || /windows/.test(ua)) os = 'windows';
    else if (/mac/.test(platform) || /mac os|macintosh/.test(ua)) os = 'macos';
    else if (/linux/.test(platform) || /linux/.test(ua)) os = 'linux';
    var labels = { windows: 'Windows', macos: 'macOS', linux: 'Linux', android: 'Android' };
    if (os) {
      var card = document.querySelector('.platform-card[data-os="' + os + '"]');
      if (card) card.classList.add('recommended');
      /* Pre-select matching install tab */
      var map = { linux: 'instab-linux', windows: 'instab-windows', macos: 'instab-macos' };
      if (map[os]) {
        var tab = document.getElementById(map[os]);
        if (tab) tab.click();
      }
      if (hint) hint.textContent = 'Looks like you are on ' + (labels[os] || os) + ' — highlighted for you.';
    } else if (hint) {
      hint.textContent = 'All platforms ship the same audited core.';
    }
  })();

  /* ---------- FAQ search ---------- */
  var faqSearch = document.getElementById('faq-search');
  var faqItems = Array.prototype.slice.call(document.querySelectorAll('[data-faq]'));
  var faqEmpty = document.getElementById('faq-empty');
  var faqEmptyQ = document.getElementById('faq-empty-q');
  if (faqSearch) {
    faqSearch.addEventListener('input', function () {
      var q = faqSearch.value.trim().toLowerCase();
      var visible = 0;
      faqItems.forEach(function (item) {
        var hit = !q || item.textContent.toLowerCase().indexOf(q) !== -1;
        item.hidden = !hit;
        if (hit) visible += 1;
        if (hit && q) item.open = true;
      });
      if (faqEmpty) faqEmpty.hidden = visible !== 0;
      if (faqEmptyQ) faqEmptyQ.textContent = faqSearch.value.trim();
    });
  }

  /* ---------- Scrub replay demo ---------- */
  var scrubTags = document.getElementById('scrub-tags');
  var scrubReplay = document.getElementById('scrub-replay');
  var scrubResult = document.getElementById('scrub-result');
  function playScrub() {
    if (!scrubTags) return;
    var items = Array.prototype.slice.call(scrubTags.querySelectorAll('[data-tag]'));
    items.forEach(function (li) { li.classList.remove('scrubbed'); });
    if (scrubResult) scrubResult.textContent = 'Inspecting container…';
    if (reduceMotion) {
      items.forEach(function (li) { li.classList.add('scrubbed'); });
      if (scrubResult) scrubResult.textContent = '5 tag groups inspected · 4 removed · 0 pixels altered';
      return;
    }
    items.forEach(function (li, i) {
      window.setTimeout(function () {
        li.classList.add('scrubbed');
        if (i === items.length - 1 && scrubResult) {
          scrubResult.textContent = '5 tag groups inspected · 4 removed · 0 pixels altered';
        }
      }, 350 + i * 420);
    });
  }
  if (scrubTags && 'IntersectionObserver' in window) {
    var scrubOnce = false;
    var scrubObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting && !scrubOnce) { scrubOnce = true; playScrub(); scrubObserver.disconnect(); }
      });
    }, { threshold: 0.35 });
    scrubObserver.observe(scrubTags);
  }
  if (scrubReplay) scrubReplay.addEventListener('click', playScrub);

  /* ---------- Live encryption demo (WebCrypto illustration) ---------- */
  var demoForm = document.getElementById('demo-form');
  var demoPass = document.getElementById('demo-pass');
  var demoBar = document.getElementById('demo-strength-bar');
  var demoLabel = document.getElementById('demo-strength-label');
  var demoChunks = document.getElementById('demo-chunks');
  var demoOutput = document.getElementById('demo-output');
  var demoStatus = document.getElementById('demo-status');
  var demoBtnLabel = document.getElementById('demo-encrypt-label');
  var chunkSpans = demoChunks ? Array.prototype.slice.call(demoChunks.querySelectorAll('span')) : [];

  function scorePassphrase(v) {
    var score = 0;
    if (v.length >= 8) score += 1;
    if (v.length >= 12) score += 1;
    if (v.length >= 16) score += 1;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score += 1;
    if (/\d/.test(v)) score += 1;
    if (/[^A-Za-z0-9]/.test(v)) score += 1;
    return Math.min(5, score);
  }
  if (demoPass && demoBar) {
    demoPass.addEventListener('input', function () {
      var v = demoPass.value;
      var s = scorePassphrase(v);
      var pct = v ? 12 + s * 17 : 8;
      demoBar.style.width = Math.min(100, pct) + '%';
      var colors = ['#ff8499', '#ff8499', '#f2bd67', '#f2bd67', '#5fd9a4', '#5fd9a4'];
      demoBar.style.background = colors[s];
      var words = ['too short…', 'weak — keep going…', 'okay…', 'good…', 'strong…', 'vault-grade…'];
      if (demoLabel) {
        demoLabel.textContent = v ? words[s] : 'enter 12+ characters…';
        demoLabel.classList.toggle('strong', s >= 4);
      }
    });
  }

  function setChunks(n) {
    chunkSpans.forEach(function (sp, i) { sp.classList.toggle('lit', i < n); });
  }
  function bufToB64(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/=+$/, '').slice(0, 44);
  }
  if (demoForm) {
    demoForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var pass = demoPass ? demoPass.value : '';
      if (!pass || pass.length < 4) {
        if (demoOutput) demoOutput.innerHTML = '<b>Hold on.</b> Type at least 4 characters to run the demo.';
        if (demoPass) demoPass.focus();
        return;
      }
      if (demoStatus) demoStatus.textContent = 'sealing…';
      if (demoBtnLabel) demoBtnLabel.textContent = 'Sealing…';
      if (demoOutput) demoOutput.innerHTML = 'Deriving key → streaming 8 chunks → authenticating…';
      setChunks(0);
      var i = 0;
      var timer = window.setInterval(function () {
        i += 1;
        setChunks(i);
        if (i >= chunkSpans.length) {
          window.clearInterval(timer);
          sealDemo(pass);
        }
      }, reduceMotion ? 30 : 130);
    });
  }
  function sealDemo(pass) {
    function finish(fakeHash) {
      if (demoOutput) {
        demoOutput.innerHTML = '<b>✓ sealed</b> tax-return-2025.pdf.vx2 · VAULTX04 · auth <span style="color:var(--cyan)">' +
          fakeHash + '</span>…<br>Passphrase wiped from demo memory.';
      }
      if (demoStatus) demoStatus.textContent = 'verified';
      if (demoBtnLabel) demoBtnLabel.textContent = 'Encrypt locally';
      pass = null;
    }
    try {
      if (!window.crypto || !window.crypto.subtle) throw new Error('no-subtle');
      var enc = new TextEncoder();
      var salt = window.crypto.getRandomValues(new Uint8Array(16));
      window.crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']).then(function (base) {
        return window.crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: 60000, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
        );
      }).then(function (key) {
        var iv = window.crypto.getRandomValues(new Uint8Array(12));
        return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode('neuron-demo:' + Date.now()));
      }).then(function (ct) {
        var digestInput = new Uint8Array(ct.slice(0, 32));
        return window.crypto.subtle.digest('SHA-256', digestInput);
      }).then(function (hash) {
        finish(bufToB64(hash));
      }).catch(function () {
        finish('a3f9c41d07e2b8');
      });
    } catch (err) {
      finish('a3f9c41d07e2b8');
    }
  }

  /* ---------- Lightbox ---------- */
  var lightbox = document.getElementById('lightbox');
  var lightboxImg = document.getElementById('lightbox-img');
  var lightboxClose = document.getElementById('lightbox-close');
  var lastFocus = null;
  function openLightbox(src, alt) {
    if (!lightbox || !lightboxImg) return;
    lastFocus = document.activeElement;
    lightboxImg.src = src;
    lightboxImg.alt = alt || 'Enlarged screenshot';
    lightbox.hidden = false;
    document.body.style.overflow = 'hidden';
    if (lightboxClose) lightboxClose.focus();
  }
  function closeLightbox() {
    if (!lightbox || lightbox.hidden) return;
    lightbox.hidden = true;
    document.body.style.overflow = '';
    if (lightboxImg) lightboxImg.src = '';
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  document.querySelectorAll('[data-lightbox]').forEach(function (card) {
    card.addEventListener('click', function () {
      openLightbox(card.getAttribute('data-lightbox'), card.getAttribute('data-alt'));
    });
  });
  if (lightboxClose) lightboxClose.addEventListener('click', closeLightbox);
  if (lightbox) lightbox.addEventListener('click', function (e) { if (e.target === lightbox) closeLightbox(); });

  /* ---------- Tilt + magnetic + spotlight (fine pointers only, motion-safe) ---------- */
  if (finePointer && !reduceMotion) {
    document.querySelectorAll('.feature-card, .platform-card, .privacy-panel, .flow-step, .timeline-item').forEach(function (card) {
      card.addEventListener('pointermove', function (e) {
        var r = card.getBoundingClientRect();
        card.style.setProperty('--mx', (e.clientX - r.left).toFixed(1) + 'px');
        card.style.setProperty('--my', (e.clientY - r.top).toFixed(1) + 'px');
      });
    });
    document.querySelectorAll('.screenshot-card').forEach(function (card) {
      card.addEventListener('mousemove', function (e) {
        var r = card.getBoundingClientRect();
        var x = e.clientX - r.left;
        var y = e.clientY - r.top;
        var rx = (y - r.height / 2) / 22;
        var ry = (r.width / 2 - x) / 22;
        card.style.transform = 'perspective(800px) rotateX(' + rx.toFixed(2) + 'deg) rotateY(' + ry.toFixed(2) + 'deg) translateY(-6px)';
      });
      card.addEventListener('mouseleave', function () { card.style.transform = ''; });
    });
    document.querySelectorAll('.magnetic').forEach(function (btn) {
      btn.addEventListener('mousemove', function (e) {
        var r = btn.getBoundingClientRect();
        var x = e.clientX - r.left - r.width / 2;
        var y = e.clientY - r.top - r.height / 2;
        btn.style.transform = 'translate(' + (x * 0.12).toFixed(1) + 'px,' + (y * 0.12).toFixed(1) + 'px)';
      });
      btn.addEventListener('mouseleave', function () { btn.style.transform = ''; });
    });
  }

  /* ---------- Particle canvas (compositor-light, pauses offscreen) ---------- */
  (function particles() {
    var canvas = document.getElementById('bg-canvas');
    if (!canvas || reduceMotion) { if (canvas) canvas.style.display = 'none'; return; }
    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    var pts = [];
    var COUNT = window.innerWidth < 700 ? 36 : 70;
    var LINK = 130;
    var mx = -9999, my = -9999;
    var running = true;

    function resize() {
      var dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      canvas.style.width = window.innerWidth + 'px';
      canvas.style.height = window.innerHeight + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    function spawn() {
      return {
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        r: Math.random() * 1.8 + 0.6,
        a: Math.random() * 0.45 + 0.18
      };
    }
    function init() {
      pts = [];
      for (var k = 0; k < COUNT; k++) pts.push(spawn());
    }
    resize();
    init();
    window.addEventListener('resize', function () { resize(); init(); });
    document.addEventListener('mousemove', function (e) { mx = e.clientX; my = e.clientY; }, { passive: true });
    document.addEventListener('mouseleave', function () { mx = -9999; my = -9999; });
    document.addEventListener('visibilitychange', function () { running = !document.hidden; if (running) window.requestAnimationFrame(tick); });

    function tick() {
      if (!running) return;
      /* Skip work when hero is far offscreen */
      if (window.scrollY > window.innerHeight * 2.5) { window.requestAnimationFrame(tick); return; }
      ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
      var i, j, p, q, dx, dy, d;
      for (i = 0; i < pts.length; i++) {
        p = pts[i];
        p.x += p.vx; p.y += p.vy;
        if (p.x < -20) p.x = window.innerWidth + 20;
        if (p.x > window.innerWidth + 20) p.x = -20;
        if (p.y < -20) p.y = window.innerHeight + 20;
        if (p.y > window.innerHeight + 20) p.y = -20;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(139,139,245,' + p.a.toFixed(2) + ')';
        ctx.fill();
      }
      ctx.lineWidth = 0.5;
      for (i = 0; i < pts.length; i++) {
        p = pts[i];
        for (j = i + 1; j < pts.length; j++) {
          q = pts[j];
          dx = p.x - q.x; dy = p.y - q.y;
          d = Math.sqrt(dx * dx + dy * dy);
          if (d < LINK) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = 'rgba(124,124,244,' + (0.09 * (1 - d / LINK)).toFixed(3) + ')';
            ctx.stroke();
          }
        }
        dx = mx - p.x; dy = my - p.y;
        d = Math.sqrt(dx * dx + dy * dy);
        if (d < 150) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(mx, my);
          ctx.strokeStyle = 'rgba(169,169,255,' + (0.16 * (1 - d / 150)).toFixed(3) + ')';
          ctx.stroke();
        }
      }
      window.requestAnimationFrame(tick);
    }
    window.requestAnimationFrame(tick);
  })();
}());
