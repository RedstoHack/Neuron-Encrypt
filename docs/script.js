(function () {
  'use strict';

  var nav = document.querySelector('.nav');
  var menuToggle = document.querySelector('.menu-toggle');
  var navLinks = document.querySelector('.nav-links');
  var navAnchors = Array.prototype.slice.call(document.querySelectorAll('.nav-links a'));
  var sections = navAnchors
    .map(function (link) { return document.querySelector(link.getAttribute('href')); })
    .filter(Boolean);

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
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') closeMenu();
    });
    navLinks.addEventListener('click', function (event) {
      if (event.target.closest('a')) closeMenu();
    });
  }

  function updateNav() {
    if (nav) nav.classList.toggle('scrolled', window.scrollY > 18);
  }
  window.addEventListener('scroll', updateNav, { passive: true });
  updateNav();

  document.querySelectorAll('a[href^="#"]').forEach(function (link) {
    link.addEventListener('click', function (event) {
      var href = link.getAttribute('href');
      if (!href || href === '#') return;
      var target = document.querySelector(href);
      if (!target) return;
      event.preventDefault();
      var top = target.getBoundingClientRect().top + window.scrollY - 78;
      window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
      history.replaceState(null, '', href);
    });
  });

  if ('IntersectionObserver' in window) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          revealObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -30px 0px' });

    document.querySelectorAll('.reveal').forEach(function (element, index) {
      element.style.transitionDelay = Math.min((index % 4) * 70, 210) + 'ms';
      revealObserver.observe(element);
    });

    var navObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        navAnchors.forEach(function (anchor) {
          anchor.classList.toggle('active', anchor.getAttribute('href') === '#' + entry.target.id);
        });
      });
    }, { rootMargin: '-35% 0px -55% 0px', threshold: 0 });
    sections.forEach(function (section) { navObserver.observe(section); });
  } else {
    document.querySelectorAll('.reveal').forEach(function (element) { element.classList.add('visible'); });
  }

  var copyButtons = document.querySelectorAll('.copy-button');
  copyButtons.forEach(function (button) {
    button.addEventListener('click', function () {
      var text = button.getAttribute('data-copy') || '';
      function done() {
        var original = button.textContent;
        button.textContent = 'Copied';
        window.setTimeout(function () { button.textContent = original; }, 1400);
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done); });
      } else {
        fallbackCopy(text, done);
      }
    });
  });

  function fallbackCopy(text, done) {
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); done(); } catch (error) { }
    document.body.removeChild(area);
  }

  var canvas = document.getElementById('particle-canvas');
  if (canvas) {
    var ctx = canvas.getContext('2d');
    var particles = [];
    var particleCount = 60;
    var mouseX = -1000;
    var mouseY = -1000;

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    document.addEventListener('mousemove', function (e) {
      mouseX = e.clientX;
      mouseY = e.clientY;
    });

    function createParticle() {
      return {
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        size: Math.random() * 1.5 + 0.5,
        alpha: Math.random() * 0.4 + 0.1
      };
    }

    for (var i = 0; i < particleCount; i++) {
      particles.push(createParticle());
    }

    function animate() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(124,124,244,' + p.alpha + ')';
        ctx.fill();

        var dx = mouseX - p.x;
        var dy = mouseY - p.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(mouseX, mouseY);
          ctx.strokeStyle = 'rgba(124,124,244,' + (0.08 * (1 - dist / 120)) + ')';
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }

      requestAnimationFrame(animate);
    }
    animate();
  }

  var screenshotCards = document.querySelectorAll('.screenshot-card');
  screenshotCards.forEach(function (card) {
    card.addEventListener('mousemove', function (e) {
      var rect = card.getBoundingClientRect();
      var x = e.clientX - rect.left;
      var y = e.clientY - rect.top;
      var centerX = rect.width / 2;
      var centerY = rect.height / 2;
      var rotateX = (y - centerY) / 20;
      var rotateY = (centerX - x) / 20;
      card.style.transform = 'perspective(800px) rotateX(' + rotateX + 'deg) rotateY(' + rotateY + 'deg) translateY(-6px)';
    });
    card.addEventListener('mouseleave', function () {
      card.style.transform = 'perspective(800px) rotateX(0) rotateY(0) translateY(0)';
    });
  });

  var heroStats = document.querySelectorAll('.hero-proof strong');
  var statsAnimated = false;
  function animateStats() {
    if (statsAnimated) return;
    var heroProof = document.querySelector('.hero-proof');
    if (!heroProof) return;
    var rect = heroProof.getBoundingClientRect();
    if (rect.top < window.innerHeight && rect.bottom > 0) {
      statsAnimated = true;
      heroStats.forEach(function (stat) {
        var target = parseInt(stat.textContent, 10);
        if (isNaN(target)) return;
        var current = 0;
        var increment = target / 30;
        var suffix = stat.textContent.replace(/[0-9]/g, '');
        function update() {
          current += increment;
          if (current >= target) {
            stat.textContent = target + suffix;
            return;
          }
          stat.textContent = Math.floor(current) + suffix;
          requestAnimationFrame(update);
        }
        update();
      });
    }
  }
  window.addEventListener('scroll', animateStats, { passive: true });
  animateStats();
}());
