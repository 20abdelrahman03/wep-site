// Coarse, non-fingerprinting environment detection (ESM — Workers & Node compatible).
// Same logic as the original CommonJS module: classify device category, OS family,
// browser family, and whether the request appears to come from an in-app browser.
// This is explicitly NOT an identity system — it describes a browser context,
// never a person. Two different humans can produce identical rows here.

export function classifyUserAgent(ua) {
  ua = String(ua || '');
  const s = ua.toLowerCase();

  let device = 'desktop';
  if (/ipad|tablet|android(?!.*mobile)/.test(s)) device = 'tablet';
  if (/mobi|iphone|ipod|android.*mobile/.test(s)) device = 'mobile';

  let os = 'unknown';
  if (/iphone|ipad|ipod|ios/.test(s)) os = 'iOS';
  else if (/android/.test(s)) os = 'Android';
  else if (/windows/.test(s)) os = 'Windows';
  else if (/mac os x|macintosh/.test(s)) os = 'macOS';
  else if (/linux/.test(s)) os = 'Linux';

  let browser = 'unknown';
  if (/edg\//.test(s)) browser = 'Edge';
  else if (/opr\/|opera/.test(s)) browser = 'Opera';
  else if (/firefox|fxios/.test(s)) browser = 'Firefox';
  else if (/chrome|crios/.test(s)) browser = 'Chrome';
  else if (/safari/.test(s)) browser = 'Safari';

  return { device, os, browser };
}

// In-app browser detection. Instagram Android UA contains "Instagram <ver> Android";
// Instagram iOS UA contains "...Mobile... Instagram/<ver>". Android WebView additionally
// sends X-Requested-With: com.instagram.android (removal was SUSPENDED by Chrome team).
export function detectInApp(ua, headers) {
  ua = String(ua || '');
  const xrw = String((headers && (headers['x-requested-with'] || headers['X-Requested-With'])) || '');
  const ual = ua.toLowerCase();
  const xrwl = xrw.toLowerCase();

  const apps = [];
  let app = null, isWebview = false;

  if (/instagram \d|instagram\/\d/.test(ua) || xrwl.includes('com.instagram.android')) {
    app = 'Instagram';
  } else if (/fban|fbav|fb_iab/.test(ua) || xrwl.includes('com.facebook')) {
    app = 'Facebook';
  } else if (/tiktok/.test(ua) || xrwl.includes('com.zhiliaoapp.musically')) {
    app = 'TikTok';
  } else if (/snapchat/.test(ua)) {
    app = 'Snapchat';
  } else if (/twitter/.test(ua)) {
    app = 'X/Twitter';
  } else if (/line\//.test(ua)) {
    app = 'LINE';
  } else if (/whatsapp/.test(ua)) {
    app = 'WhatsApp';
  } else if (/micromessenger/.test(ua)) {
    app = 'WeChat';
  } else if (/pinterest/.test(ua)) {
    app = 'Pinterest';
  } else if (/reddit\/\d/.test(ua)) {
    app = 'Reddit';
  }

  if (app) {
    isWebview = true;
    apps.push(app);
  }
  if (/;\s*wv\)/.test(ua) || (xrwl && /^com\.[a-z0-9_.]+$/i.test(xrw) && !app)) {
    isWebview = true;
    if (xrw) apps.push(xrw);
  }
  if (/iphone|ipad/.test(ua) && /safari/.test(ua) && !/chrome|crios|fxios|edg\//.test(ua) && !/macintosh/.test(ua)) {
    // iOS in-app WebViews often look like Safari but lack desktop-Safari markers;
    // weak signal only — recorded, never asserted.
    if (app) isWebview = true;
  }

  return { isWebview, inAppApp: app, xRequestedWith: xrw || null, apps };
}

export function classifyReferrer(referrer, isIgInApp) {
  if (!referrer) return isIgInApp ? 'instagram-inapp-no-referrer' : 'direct';
  try {
    const host = new URL(referrer).hostname.toLowerCase();
    if (host.includes('instagram.com')) return 'instagram';
    if (host.includes('facebook.com') || host.includes('fb.com')) return 'facebook';
    if (host.includes('tiktok.com')) return 'tiktok';
    if (host.includes('t.co')) return 'twitter';
    if (host.includes('google.') || host.includes('bing.com') || host.includes('duckduckgo.com')) return 'search';
    return 'website: ' + host;
  } catch {
    return 'unparseable';
  }
}

// Extract a compact, documented observation set from an incoming request.
// Standard, browser-supplied request data only — nothing exotic.
const HEADERS_TO_KEEP = [
  'accept', 'accept-language', 'referer', 'user-agent',
  'x-requested-with', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
  'sec-ch-ua-model', 'origin', 'dnt', 'sec-gpc', 'priority', 'upgrade-insecure-requests',
];

export function extractRequestObservations(reqLike) {
  // reqLike: { method, path, query, headers } — built by the worker from the
  // standard Request object, so this stays pure and testable in both runtimes.
  const h = reqLike.headers || {};
  const headers = {};
  for (const key of HEADERS_TO_KEEP) {
    if (h[key] != null) headers[key] = Array.isArray(h[key]) ? h[key].join(', ') : String(h[key]);
  }
  const ua = headers['user-agent'] || '';
  const det = detectInApp(ua, h);
  const uaInfo = classifyUserAgent(ua);

  return {
    method: reqLike.method,
    path: reqLike.path,
    query: reqLike.query || {},
    headers,
    ua,
    is_ig_inapp: det.inAppApp === 'Instagram',
    in_app_app: det.inAppApp,
    is_webview: det.isWebview,
    x_requested_with: det.xRequestedWith,
    device: uaInfo.device,
    os: uaInfo.os,
    browser: uaInfo.browser,
    referrer: headers['referer'] || null,
    referrer_source: classifyReferrer(headers['referer'], det.inAppApp === 'Instagram'),
  };
}
