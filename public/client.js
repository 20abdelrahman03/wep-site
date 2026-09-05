'use strict';
/* ALUCARD site client — rendering, motion, and the privacy-aware beacon.
 * No fingerprinting, no cross-site anything. The beacon reports coarse env
 * only (languages, tz, screen bucket, connection) — same privacy model as v1.
 */
(function () {
  var reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ================= analytics beacon ================= */
  var out = {
    path: location.pathname,
    query: Object.fromEntries(new URLSearchParams(location.search)),
    referrer: document.referrer || null,
    env: {
      languages: navigator.languages ? navigator.languages.slice(0, 3) : [navigator.language || null],
      timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone) || null,
      screen_bucket: (function () {
        if (!screen.width) return null;
        return Math.round(screen.width / 240) * 240 + 'x' + Math.round(screen.height / 240) * 240;
      })(),
      touch: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0),
      connection: (navigator.connection && navigator.connection.effectiveType) || null,
      standalone: navigator.standalone === true || matchMedia('(display-mode: standalone)').matches,
      in_app_app: null,
      pcm_injected: false,
    }
  };
  try {
    var ua = navigator.userAgent;
    if (/Instagram \d|Instagram\/\d/.test(ua)) out.env.in_app_app = 'Instagram';
    else if (/FBAV|FBAN|FB_IAB/i.test(ua)) out.env.in_app_app = 'Facebook';
    else if (/TikTok/.test(ua)) out.env.in_app_app = 'TikTok';
    else if (/Snapchat/.test(ua)) out.env.in_app_app = 'Snapchat';
  } catch (e) {}
  /* passive detection of Meta's pcm.js injection (in-app browser marker) */
  try {
    if (document.getElementById('iab-pcm-sdk')) out.env.pcm_injected = true;
    var mo = new MutationObserver(function (muts) {
      muts.forEach(function (m) {
        m.addedNodes.forEach(function (n) {
          if (n.tagName === 'SCRIPT' && /connect\.facebook\.net\/.*\/pcm\.js/.test(n.src || '')) {
            out.env.pcm_injected = true;
          }
        });
      });
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(function () { mo.disconnect(); }, 4000);
  } catch (e) {}

  fetch('/api/beacon', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(out),
    keepalive: true,
  }).catch(function () {});

  /* ================= nav ================= */
  var burger = document.getElementById('burger');
  var navlinks = document.getElementById('navlinks');
  if (burger && navlinks) {
    burger.addEventListener('click', function () {
      var open = navlinks.classList.toggle('open');
      burger.setAttribute('aria-expanded', open ? 'true' : 'false');
      burger.textContent = open ? '✕' : '≡';
    });
    navlinks.addEventListener('click', function (e) {
      if (e.target.closest('a')) {
        navlinks.classList.remove('open');
        burger.setAttribute('aria-expanded', 'false');
        burger.textContent = '≡';
      }
    });
  }
  /* scrollspy */
  var secs = document.querySelectorAll('main section[id]');
  var links = document.querySelectorAll('.navlinks a[data-nav]');
  var spy = function () {
    var pos = scrollY + 120, cur = secs[0];
    secs.forEach(function (s) { if (s.offsetTop <= pos) cur = s; });
    links.forEach(function (a) {
      a.classList.toggle('act', a.getAttribute('href') === '#' + cur.id);
    });
  };
  addEventListener('scroll', spy, { passive: true }); spy();

  /* ================= rotating descriptors ================= */
  var rot = document.getElementById('rot');
  var words = ['GAMER', 'AI EXPERIMENTER', 'VIBE CODER', 'BUG HUNTER'];
  if (rot && !reduceMotion) {
    var wi = 0;
    setInterval(function () {
      rot.style.opacity = 0;
      rot.style.transform = 'translateY(-6px)';
      setTimeout(function () {
        wi = (wi + 1) % words.length;
        rot.textContent = words[wi];
        rot.style.opacity = 1;
        rot.style.transform = 'none';
      }, 260);
    }, 2800);
    rot.style.transition = 'opacity .26s ease, transform .26s ease';
  } else if (rot) { rot.textContent = words[0]; }

  /* ================= scroll reveal ================= */
  if (!reduceMotion && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); }
      });
    }, { threshold: 0.12 });
    document.querySelectorAll('.rv').forEach(function (el) { io.observe(el); });
  } else {
    document.querySelectorAll('.rv').forEach(function (el) { el.classList.add('in'); });
  }

  /* ================= game cards + modal ================= */
  var grid = document.getElementById('games');
  var modal = document.getElementById('gmodal');
  var mi = document.getElementById('gm-img'),
      mt = document.getElementById('gm-title'),
      mg = document.getElementById('gm-genre'),
      mc = document.getElementById('gm-chips'),
      mn = document.getElementById('gm-note');

  var SOULS = ['dark-souls', 'dark-souls-2', 'dark-souls-3', 'sekiro', 'elden-ring', 'lies-of-p'];
  var lastFocus = null;

  function openModal(g) {
    lastFocus = document.activeElement;
    mi.src = g.img; mi.alt = 'غلاف ' + g.name;
    mt.textContent = g.name;
    mg.textContent = g.genre;
    mc.innerHTML = '';
    (g.chips || []).forEach(function (c) {
      var s = document.createElement('span');
      s.className = 'chip ' + (c[1] === 'hot' ? 'hot' : c[1] === 'blood' ? 'blood' : '');
      s.textContent = c[0];
      mc.appendChild(s);
    });
    mn.textContent = g.note || '';
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    modal.querySelector('.mclose').focus();
  }
  function closeModal() {
    modal.classList.remove('open');
    document.body.style.overflow = '';
    if (lastFocus) lastFocus.focus();
  }

  if (grid && window.GAMES) {
    window.GAMES.forEach(function (g, idx) {
      var card = document.createElement('button');
      card.type = 'button';
      card.className = 'gcard';
      card.setAttribute('aria-label', 'تفاصيل ' + g.name);
      /* above-the-fold covers load eagerly, rest lazy */
      card.innerHTML =
        '<img src="' + g.img + '" alt="غلاف لعبة ' + g.name + '" loading="' +
        (idx < 6 ? 'eager' : 'lazy') + '" decoding="async" width="640" height="640">' +
        '<span class="shade"></span>' +
        (SOULS.indexOf(g.id) > -1 ? '<span class="mark souls" title="من سلسلة السولز اللي كمّلتها كلها">⚔</span>' : '') +
        '<span class="cap"><small>' + (SOULS.indexOf(g.id) > -1 ? 'SOULS · كملتها' : 'ARCHIVE') +
        '</small><b>' + g.name + '</b></span>';
      card.addEventListener('click', function () { openModal(g); });
      grid.appendChild(card);
    });
  }
  if (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target.hasAttribute('data-close')) closeModal();
    });
    addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && modal.classList.contains('open')) closeModal();
    });
  }

  /* ================= external link click events ================= */
  document.querySelectorAll('a[data-ext]').forEach(function (a) {
    a.addEventListener('click', function () {
      fetch('/api/click', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ href: a.href, label: a.textContent.trim().slice(0, 40), path: location.pathname }),
        keepalive: true,
      }).catch(function () {});
    });
  });
})();
