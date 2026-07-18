// Neuron Encrypt website — minimal interactivity.
// No tracking, no analytics, no third-party scripts.

(function () {
  'use strict';

  // ── Smooth scroll for nav links (supplements CSS scroll-behavior) ──
  document.querySelectorAll('a[href^="#"]').forEach(function (link) {
    link.addEventListener('click', function (e) {
      var target = document.querySelector(this.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // ── Scroll reveal — fades in sections as they enter the viewport ──
  if ('IntersectionObserver' in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
    );

    // Mark sections for reveal (skip hero — it should be visible immediately)
    document.querySelectorAll('.section, .feature, .download-card, .how-step').forEach(function (el, i) {
      el.classList.add('reveal');
      el.style.transitionDelay = (i % 4) * 60 + 'ms';
      observer.observe(el);
    });
  }

  // ── Active nav highlight based on scroll position ──
  var navLinks = document.querySelectorAll('.nav-links a[href^="#"]');
  var sections = [];
  navLinks.forEach(function (link) {
    var target = document.querySelector(link.getAttribute('href'));
    if (target) sections.push({ link: link, el: target });
  });

  if (sections.length > 0 && 'IntersectionObserver' in window) {
    var navObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          var match = sections.find(function (s) { return s.el === entry.target; });
          if (match) {
            if (entry.isIntersecting) {
              navLinks.forEach(function (l) { l.style.color = ''; });
              match.link.style.color = 'var(--text-hi)';
            }
          }
        });
      },
      { rootMargin: '-40% 0px -55% 0px' }
    );
    sections.forEach(function (s) { navObserver.observe(s.el); });
  }

  // ── Console easter egg for the curious ──
  if (typeof console !== 'undefined' && console.log) {
    console.log(
      '%c🔒 Neuron Encrypt',
      'color: #6366f1; font-size: 20px; font-weight: bold; font-family: monospace;'
    );
    console.log(
      '%cLocal file encryption. No accounts. No internet. No compromise.\n' +
      'Source: https://github.com/darkmaster0345/Neuron-Encrypt',
      'color: #a8a8a8; font-family: monospace;'
    );
  }
})();
