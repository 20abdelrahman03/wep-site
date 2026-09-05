// lib/ua.js — rich device / OS / browser parsing from UA + Client Hints (ESM).
// Principles:
//   - Use UA tokens AND sec-ch-* client hints together; never a single regex.
//   - Never fabricate: if only a vendor is provable, show vendor only.
//     If nothing is provable, return "Unknown …" honestly.
//   - This describes a browser context, never a person.

/* ---------------- device vendor / model ---------------- */

// Android model strings are messy. These rules map the model token
// (from sec-ch-ua-model or the UA "Build/" segment) to a display vendor.
const VENDOR_RULES = [
  [/^SM-[A-Z0-9]+|S20[UF]?E?|S21[UF]?E?|S22[UF]?E?|S23[UF]?E?|S24[UF]?E?|^GT-|^SC-|SCG/i, 'Samsung'],
  [/Redmi/i, 'Redmi'],
  [/POCO/i, 'POCO'],
  [/Mi \d|Mi Note|Xiaomi|Mix \d/i, 'Xiaomi'],
  [/^\d{10}[A-Z]?$/i, 'Xiaomi'],          // e.g. "2201123G" (Xiaomi numeric model ids)
  [/CPH\d{4}/i, 'OPPO'],
  [/RMX\d{4}/i, 'Realme'],
  [/OnePlus|^IN\d{4}|^LE2|^KB2/i, 'OnePlus'],
  [/^V2\d{3}[A-Z]?$/i, 'Vivo'],
  [/HUAWEI|HarmonyOS|^ELS-|^VOG-|^ANE-/i, 'Huawei'],
  [/Honor/i, 'Honor'],
  [/^moto |Moto [GE]/i, 'Motorola'],
  [/Pixel/i, 'Google Pixel'],
  [/Nokia/i, 'Nokia'],
  [/Infinix/i, 'Infinix'],
  [/TECNO/i, 'Tecno'],
  [/itel/i, 'Itel'],
  [/^LM-[A-Z0-9]+/i, 'LG'],
];

// Extract the Android device model token from a UA.
// Chrome Android UA: "...; SM-G991B Build/RP1A..." or "...; Xiaomi Redmi Note 9 Build/RKQ..."
function androidModelFromUa(ua) {
  let m = ua.match(/;\s*([^;)]+?)\s+Build\//);
  if (m) return m[1].trim();
  // Fallback for WebViews / privacy browsers missing the "Build/" token.
  // It captures the last token before the closing parenthesis if the OS is Android.
  m = ua.match(/Android [^;)]+;\s*([^;)]+?)\)/);
  if (m) {
    const t = m[1].trim();
    // Exclude tokens that clearly aren't models (like "wv" or language codes like "en-US")
    if (t !== 'wv' && !/^[a-z]{2}-[A-Z]{2}$/.test(t)) return t;
  }
  return null;
}

// Samsung numeric model fallback: "S928B" (S24 Ultra) style tokens.
function normalizeModel(model) {
  if (!model) return null;
  return model.replace(/\s+/g, ' ').trim().slice(0, 40) || null;
}

function vendorFromModel(model) {
  if (!model) return null;
  for (const [re, vendor] of VENDOR_RULES) if (re.test(model)) return vendor;
  return null;
}

/* ---------------- OS + version ---------------- */

function osFromUa(ua) {
  const s = ua.toLowerCase();
  if (/iphone|ipad|ipod/.test(s)) {
    const m = ua.match(/(?:iPhone |CPU |iPad )OS (\d+_\d+(?:_\d+)?)/);
    return { os: 'iOS', os_version: m ? m[1].replace(/_/g, '.') : null };
  }
  if (/android/.test(s)) {
    const m = ua.match(/Android (\d+(?:\.\d+)?)/);
    return { os: 'Android', os_version: m ? m[1] : null };
  }
  if (/windows/.test(s)) {
    const m = ua.match(/Windows NT ([\d.]+)/);
    const v = m ? m[1] : null;
    let ver = null;
    if (v === '10.0') ver = '10/11';
    else if (v === '6.3') ver = '8.1';
    else if (v === '6.2') ver = '8';
    else if (v === '6.1') ver = '7';
    return { os: 'Windows', os_version: ver };
  }
  if (/mac os x|macintosh/.test(s)) {
    const m = ua.match(/Mac OS X (\d+_\d+(?:_\d+)?)/);
    return { os: 'macOS', os_version: m ? m[1].replace(/_/g, '.') : null };
  }
  if (/cros/.test(s)) return { os: 'ChromeOS', os_version: null };
  if (/linux/.test(s)) return { os: 'Linux', os_version: null };
  return { os: 'unknown', os_version: null };
}

/* ---------------- browser + version ---------------- */

function browserFromUa(ua, xrwl) {
  // In-app browsers first — they wrap a real engine and often carry both names.
  let m = ua.match(/Instagram[ /]([\d.]+)/);
  if (m) return { browser: 'Instagram in-app', browser_version: m[1] };
  m = ua.match(/FBAV\/([\d.]+)/);
  if (m) return { browser: 'Facebook in-app', browser_version: m[1] };
  m = ua.match(/FBAN\/([\w.]+)/);
  if (m) return { browser: 'Facebook in-app', browser_version: m[1] };
  m = ua.match(/SamsungBrowser\/([\d.]+)/);
  if (m) return { browser: 'Samsung Internet', browser_version: m[1] };
  m = ua.match(/Edg(?:A|iOS)?\/([\d.]+)/);
  if (m) return { browser: 'Edge', browser_version: m[1] };
  m = ua.match(/OPR\/([\d.]+)/);
  if (m) return { browser: 'Opera', browser_version: m[1] };
  m = ua.match(/Opera(?: |\/)([\d.]+)/);
  if (m) return { browser: 'Opera', browser_version: m[1] };

  m = ua.match(/Firefox\/([\d.]+)/);
  if (m) return { browser: 'Firefox', browser_version: m[1] };
  m = ua.match(/FxiOS\/([\d.]+)/);
  if (m) return { browser: 'Firefox', browser_version: m[1] };

  m = ua.match(/(?:Chrome|CriOS)\/([\d.]+)/);
  if (m) {
    // WebView markers: "; wv" in UA, or an app package in X-Requested-With
    if (/;\s*wv\)/.test(ua) || (xrwl && /^com\.[a-z0-9_.]+$/i.test(xrwl)))
      return { browser: 'Android WebView', browser_version: m[1] };
    return { browser: 'Chrome', browser_version: m[1] };
  }

  m = ua.match(/Version\/([\d.]+).*Safari/);
  if (m) return { browser: 'Safari', browser_version: m[1] };

  // iOS WebView: Mobile Safari engine without the "Safari/xx" token.
  if (/AppleWebKit/.test(ua) && /\((?:iPhone|iPad)/.test(ua) && !/Safari\//.test(ua))
    return { browser: 'iOS WebView', browser_version: null };
  if (/Safari/.test(ua)) return { browser: 'Safari', browser_version: null };

  return { browser: 'unknown', browser_version: null };
}

/* ---------------- full parse ---------------- */

export function parseUAFull(uaRaw, headers) {
  const ua = String(uaRaw || '');
  const h = headers || {};
  const xrwl = String(h['x-requested-with'] || '').toLowerCase();

  const os = osFromUa(ua);
  const br = browserFromUa(ua, xrwl);

  // Client hints (Chromium): higher quality than UA tokens.
  const chPlatform = h['sec-ch-ua-platform'] ? h['sec-ch-ua-platform'].replace(/"/g, '') : null;
  const chMobile = h['sec-ch-ua-mobile'];
  const chModel = h['sec-ch-ua-model'] ? h['sec-ch-ua-model'].replace(/"/g, '').trim() : null;
  if (chPlatform && os.os === 'unknown') os.os = chPlatform;

  // Device type
  let device = 'desktop';
  if (chMobile === '?1') device = 'mobile';
  else if (chMobile === '?0') device = 'desktop';
  if (/ipad|tablet|android(?!.*mobile)/i.test(ua)) device = 'tablet';
  if (/mobi|iphone|ipod|android.*mobile/i.test(ua)) device = 'mobile';

  // Vendor / model
  let vendor = null, model = null;
  if (/iphone/i.test(ua)) { vendor = 'Apple'; model = 'iPhone'; device = 'mobile'; }
  else if (/ipad/i.test(ua)) { vendor = 'Apple'; model = 'iPad'; device = 'tablet'; }
  else if (/ipod/i.test(ua)) { vendor = 'Apple'; model = 'iPod'; device = 'mobile'; }
  else if (os.os === 'Android' || device === 'mobile' && os.os === 'unknown') {
    model = normalizeModel(chModel || androidModelFromUa(ua));
    vendor = vendorFromModel(model);
    if (!vendor) vendor = model ? 'Unknown Android device' : null;
    if (!model && os.os === 'Android') model = null; // honest: no fabrication
  }
  if (device === 'desktop') { vendor = vendor || 'PC'; model = null; }

  return {
    device_type: device,
    device_vendor: vendor,
    device_model: model,
    os: os.os,
    os_version: os.os_version,
    browser: br.browser,
    browser_version: br.browser_version,
    ua,
  };
}
