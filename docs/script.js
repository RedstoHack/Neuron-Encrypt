// Neuron Encrypt website — minimal vanilla JS.
// No tracking, no analytics, no third-party scripts.

(function () {
  'use strict';

  // ── Nav scroll effect ──
  const nav = document.getElementById('nav');
  let lastScroll = 0;

  function handleScroll() {
    const scroll = window.scrollY;
    if (scroll > 20) {
      nav.classList.add('scrolled');
    } else {
      nav.classList.remove('scrolled');
    }
    lastScroll = scroll;
  }

  window.addEventListener('scroll', handleScroll, { passive: true });

  // ── Smooth scroll for anchor links ──
  document.querySelectorAll('a[href^="#"]').forEach(function (link) {
    link.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      if (href === '#') return;
      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        const offset = 80; // nav height
        const top = target.getBoundingClientRect().top + window.scrollY - offset;
        window.scrollTo({ top: top, behavior: 'smooth' });
      }
    });
  });

  // ── Scroll reveal with IntersectionObserver ──
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(
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

    // Mark elements for reveal (skip hero — visible immediately)
    const revealSelectors = [
      '.section-header',
      '.feature-card',
      '.download-card',
      '.download-cli',
      '.security-card',
      '.audit-badge',
      '.faq-list',
      '.cta-content',
      '.trust-bar'
    ];

    revealSelectors.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (el, i) {
        el.classList.add('reveal');
        el.style.transitionDelay = ((i % 4) * 60) + 'ms';
        observer.observe(el);
      });
    });
  }

  // ── Active nav link based on scroll position ──
  const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');
  const sections = [];
  navLinks.forEach(function (link) {
    const target = document.querySelector(link.getAttribute('href'));
    if (target) sections.push({ link: link, el: target });
  });

  if (sections.length > 0 && 'IntersectionObserver' in window) {
    const navObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          const match = sections.find(function (s) { return s.el === entry.target; });
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

  // ── Console easter egg ──
  if (typeof console !== 'undefined' && console.log) {
    const styles = [
      'color: #6366f1',
      'font-size: 24px',
      'font-weight: bold',
      'font-family: monospace',
      'text-shadow: 2px 2px 0 rgba(99,102,241,0.3)'
    ].join(';');

    console.log('%c🔒 Neuron Encrypt', styles);
    console.log(
      '%cLocal file encryption. No accounts. No internet. No compromise.\n' +
      'Source: https://gitlab.com/theredhacker0345/neuron-encrypt',
      'color: #a8a8a8; font-family: monospace; font-size: 12px;'
    );
  }
})();
