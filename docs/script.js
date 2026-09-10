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

  var canvas = document.getElementById('bg-canvas');
  if (canvas) {
    var ctx = canvas.getContext('2d');
    var particles = [];
    var particleCount = 80;
    var mouseX = -1000;
    var mouseY = -1000;
    var connectionDistance = 140;

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
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        size: Math.random() * 2 + 0.5,
        alpha: Math.random() * 0.5 + 0.2
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

        for (var j = i + 1; j < particles.length; j++) {
          var p2 = particles[j];
          var dx = p.x - p2.x;
          var dy = p.y - p2.y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < connectionDistance) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            var alpha = 0.08 * (1 - dist / connectionDistance);
            ctx.strokeStyle = 'rgba(124,124,244,' + alpha + ')';
            ctx.lineWidth = 0.4;
            ctx.stroke();
          }
        }

        var mdx = mouseX - p.x;
        var mdy = mouseY - p.y;
        var mdist = Math.sqrt(mdx * mdx + mdy * mdy);
        if (mdist < 160) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(mouseX, mouseY);
          var malpha = 0.15 * (1 - mdist / 160);
          ctx.strokeStyle = 'rgba(166,166,255,' + malpha + ')';
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }

      requestAnimationFrame(animate);
    }
    animate();
  }

  var orbs = document.querySelectorAll('.gradient-orb');
  window.addEventListener('scroll', function () {
    var scrollY = window.scrollY;
    orbs.forEach(function (orb, index) {
      var speed = (index + 1) * 0.05;
      orb.style.transform = 'translateY(' + (scrollY * speed) + 'px)';
    });
  }, { passive: true });

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
      card.style.transform = 'perspective(800px) rotateX(' + rotateX + 'deg) rotateY(' + rotateY + 'deg) translateY(-8px) scale(1.02)';
    });
    card.addEventListener('mouseleave', function () {
      card.style.transform = 'perspective(800px) rotateX(0) rotateY(0) translateY(0) scale(1)';
    });
  });

  var magneticButtons = document.querySelectorAll('.magnetic');
  magneticButtons.forEach(function (btn) {
    btn.addEventListener('mousemove', function (e) {
      var rect = btn.getBoundingClientRect();
      var x = e.clientX - rect.left - rect.width / 2;
      var y = e.clientY - rect.top - rect.height / 2;
      btn.style.transform = 'translate(' + (x * 0.15) + 'px, ' + (y * 0.15) + 'px)';
    });
    btn.addEventListener('mouseleave', function () {
      btn.style.transform = 'translate(0, 0)';
    });
  });

  var heroStats = document.querySelectorAll('.hero-proof strong[data-count]');
  var statsAnimated = false;
  function animateStats() {
    if (statsAnimated) return;
    var heroProof = document.querySelector('.hero-proof');
    if (!heroProof) return;
    var rect = heroProof.getBoundingClientRect();
    if (rect.top < window.innerHeight && rect.bottom > 0) {
      statsAnimated = true;
      heroStats.forEach(function (stat) {
        var target = parseInt(stat.getAttribute('data-count'), 10);
        if (isNaN(target)) return;
        var current = 0;
        var increment = target / 40;
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

  var parallaxElements = document.querySelectorAll('.hero-visual, .vault-panel');
  window.addEventListener('scroll', function () {
    var scrollY = window.scrollY;
    parallaxElements.forEach(function (el, index) {
      var speed = (index + 1) * 0.03;
      el.style.transform = 'translateY(' + (scrollY * speed) + 'px)';
    });
  }, { passive: true });
}());
