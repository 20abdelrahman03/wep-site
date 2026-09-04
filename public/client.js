'use strict';
/* First-party client beacon. Normal web APIs only — no fingerprinting,
 * no cross-site storage access, no deceptive collection.
 * Records: coarse env (languages, timezone, screen *bucket*, connection type)
 * and whether Meta's pcm.js gets injected into us (Instagram in-app browser marker).
 */
(function () {
  var out = {
    path: location.pathname,
    query: Object.fromEntries(new URLSearchParams(location.search)),
    referrer: document.referrer || null,
    env: {
      languages: navigator.languages ? navigator.languages.slice(0, 3) : [navigator.language || null],
      timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone) || null,
      screen_bucket: (function () { // coarse buckets, not exact resolution
        if (!screen.width) return null;
        var w = Math.round(screen.width / 240) * 240, h = Math.round(screen.height / 240) * 240;
        return w + 'x' + h;
      })(),
      touch: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0),
      connection: (navigator.connection && navigator.connection.effectiveType) || null,
      standalone: navigator.standalone === true || matchMedia('(display-mode: standalone)').matches,
      in_app_app: null,
      pcm_injected: false,
    }
  };

  /* UA-based in-app hint (client side mirrors server logic) */
  try {
    var ua = navigator.userAgent;
    if (/Instagram \d|Instagram\/\d/.test(ua)) out.env.in_app_app = 'Instagram';
    else if (/FBAV|FBAN|FB_IAB/.test(ua)) out.env.in_app_app = 'Facebook';
    else if (/TikTok/.test(ua)) out.env.in_app_app = 'TikTok';
    else if (/Snapchat/.test(ua)) out.env.in_app_app = 'Snapchat';
  } catch (e) {}

  /* Research signal: Meta apps inject https://connect.facebook.net/en_US/pcm.js
   * and probe for element id "iab-pcm-sdk" (Krause 2022). Observing that injection
   * is passive and reproducible evidence of the Instagram/Facebook in-app browser.
   */
  try {
    if (document.getElementById('iab-pcm-sdk')) { out.env.pcm_injected = true; }
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

  /* read our own first-party cookie (not set httpOnly on purpose) */
  var m = document.cookie.match(/avid=([a-f0-9]{32})/);
  out.visitor_id = m ? m[1] : null;

  fetch('/api/beacon', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(out),
    keepalive: true,
  }).catch(function () {});

  /* populate site content */
  fetch('/api/site').then(r => r.json()).then(function (s) {
    var icons = { ig: '📷', gh: '🐙', mail: '✉️', web: '🌐' };
    document.getElementById('nm').textContent = s.name;
    document.getElementById('nm2').textContent = s.name;
    document.getElementById('tg').textContent = s.tagline;
    document.getElementById('yr').textContent = new Date().getFullYear();
    var box = document.getElementById('links');
    box.innerHTML = '';
    s.links.forEach(function (l) {
      var a = document.createElement('a');
      a.className = 'l'; a.href = l.href;
      if (!/^mailto:/.test(l.href)) a.target = '_blank', a.rel = 'noopener';
      a.innerHTML = '<span class="ic">' + (icons[l.icon] || '🔗') + '</span><span><strong>' +
        l.label + '</strong><small>' + l.href.replace(/^https?:\/\//, '').replace(/\/$/, '') + '</small></span>';
      a.addEventListener('click', function () {
        fetch('/api/click', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ href: l.href, label: l.label, path: location.pathname }),
          keepalive: true }).catch(function () {});
      });
      box.appendChild(a);
    });
  }).catch(function () {});
})();
