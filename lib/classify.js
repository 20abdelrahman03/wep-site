// lib/classify.js — multi-signal, weighted session classifier (ESM).
// Probabilistic by design: no single signal decides anything. Every fired
// signal adds weight to human / bot / suspicious, and the reason list is
// preserved so the dashboard can explain WHY a session was classified.
//
// Output classes:
//   human_likely | unknown | bot | social_preview | internal | suspicious

const BOT_UA_RE = new RegExp(
  '(googlebot|bingbot|yandexbot|duckduckbot|baiduspider|slurp|sogou|exabot' +
  '|applebot|petalbot|bytespider|gptbot|claudebot|ccbot|amazonbot' +
  '|semrushbot|ahrefsbot|mj12bot|dotbot|backlinkcrawler|serpstatbot' +
  '|python-requests|python-urllib|scrapy|httpx' +
  '|curl\\/|wget\\/|go-http-client|java\\/|okhttp|apache-httpclient|libwww-perl' +
  '|node-fetch|axios\\/|postmanruntime|undici' +
  '|headlesschrome|phantomjs|selenium|puppeteer|playwright' +
  '|uptimerobot|pingdom|statuscake|nagios|check_http|zgrab|masscan|nmap' +
  '|cloudflare-al|cloudflare-healthcheck)', 'i');

// Link-preview fetchers get their own class — they are automated, but they are
// not "crawlers scraping content"; they render a preview card for a human.
const PREVIEW_UA_RE = new RegExp(
  '(facebookexternalhit|facebot|twitterbot|whatsapp|telegrambot' +
  '|slackbot|discordbot|discordapp\\.com|skypeuripreview|viber' +
  '|google favicon|googlesitespreview|iframely|quora link preview' +
  '|pinterestbot|snapchat\\s?link|vkshare|xingwidget)', 'i');

export function isBotUA(ua)     { return BOT_UA_RE.test(String(ua || '')); }
export function isPreviewUA(ua) { return PREVIEW_UA_RE.test(String(ua || '')); }

/* ─────────────────────────────────────────────────────────────
   classifySession(facts) → { classification, confidence, reasons[] }
   facts (all optional / null-safe):
     ua, is_webview, in_app_app,
     known_bot, social_preview,          // precomputed UA classes (or raw ua given)
     js_beacon_count, heartbeat_count, interaction_count,
     pageviews, distinct_paths, refresh_count,
     active_duration_s, has_client_hints, has_accept_language,
     browser_like_ua, no_sec_fetch,      // request-shape signals
     cf_bot_score,                        // Cloudflare bot score if available (1-99)
     is_internal, visitor_burst_sessions, // same visitor: many short sessions recently
     webdriver                            // navigator.webdriver true (client side)
───────────────────────────────────────────────────────────── */

export function classifySession(f) {
  f = f || {};
  const ua = String(f.ua || '');
  const known_bot     = f.known_bot     !== undefined ? f.known_bot     : isBotUA(ua);
  const social_preview= f.social_preview!== undefined ? f.social_preview: isPreviewUA(ua);

  const reasons = { human: [], bot: [], suspicious: [] };
  let human = 0, bot = 0, suspicious = 0;

  const add = (cat, w, text) => { if (cat === 'h') { human += w; reasons.human.push({ w, text }); }
                                  else if (cat === 'b') { bot += w; reasons.bot.push({ w, text }); }
                                  else { suspicious += w; reasons.suspicious.push({ w, text }); } };

  /* ---- explicit internal flag wins immediately ---- */
  if (f.is_internal) {
    return { classification: 'internal', confidence: 100,
             reasons: [{ w: 100, text: 'علامة القياس الداخلي (cookie اختبار)' }] };
  }

  /* ---- UA-class signals (strong) ---- */
  if (social_preview) {
    return { classification: 'social_preview', confidence: 95,
             reasons: [{ w: 95, text: 'UA معروف لتوليد معاينات الروابط (Social preview)' }] };
  }
  if (known_bot) add('b', 65, 'UA معروف لبوت/كراولر');

  /* ---- request-shape signals ---- */
  if (f.webdriver) add('b', 80, 'علامة navigator.webdriver (أتمتة متصفح)');
  if (f.no_sec_fetch && f.browser_like_ua) add('b', 15, 'UA بيدّعي متصفح لكن بدون Sec-Fetch headers');
  if (!f.has_accept_language && f.browser_like_ua) add('b', 10, 'Accept-Language مفقود');
  if (f.cf_bot_score != null && f.cf_bot_score < 30) add('b', 25, 'Cloudflare bot score منخفض (' + f.cf_bot_score + ')');
  if (f.cf_bot_score != null && f.cf_bot_score >= 30) add('h', 8, 'Cloudflare bot score مقبول (' + f.cf_bot_score + ')');

  /* ---- JS / engagement signals (the real discriminators) ---- */
  if ((f.js_beacon_count || 0) > 0) add('h', 30, 'JS اشتغل — بيئة العميل وصلت (beacon)');
  if ((f.heartbeat_count || 0) > 0) add('h', 20, 'نبضات جلسة نشطة (heartbeat)');
  if ((f.interaction_count || 0) > 0) add('h', 20, 'تفاعل حقيقي (نقرات أو إيماءات لافتة)');
  if ((f.js_beacon_count || 0) === 0 && (f.pageviews || 0) >= 2) add('b', 10, 'تحميلات متعددة بدون أي JS');
  if ((f.distinct_paths || 0) >= 2) add('h', 8, 'تنقل بين أكتر من صفحة');
  if (f.in_app_app) add('h', 15, 'متصفح مدمج بتطبيق اجتماعي (' + f.in_app_app + ')');
  if (f.has_client_hints) add('h', 6, 'Client Hints موجودة (متصفح حديث)');
  if (f.has_accept_language) add('h', 4, 'Accept-Language موجودة');
  if ((f.active_duration_s || 0) > 30) add('h', 10, 'وقت نشط معقول (' + Math.round(f.active_duration_s) + 'ث)');
  if ((f.active_duration_s || 0) > 120) add('h', 5, 'وقت نشط طويل');

  /* ---- automation-pattern signals ---- */
  if ((f.refresh_count || 0) >= 3) add('s', 20, 'نمط تحديث متكرر (' + f.refresh_count + ' refreshes)');
  if ((f.refresh_count || 0) >= 6) add('s', 15, 'لووب تحديث متطرف');
  if ((f.visitor_burst_sessions || 0) >= 5) add('s', 15, 'جلسات قصيرة متكررة من نفس الزائر (' + f.visitor_burst_sessions + ' في آخر ساعة)');

  /* ---- decision ---- */
  let classification, confidence;

  if (bot >= 55) {
    classification = 'bot';
    confidence = Math.min(98, Math.round(55 + (bot - 55) * 0.6));
  } else if (suspicious >= 35 && suspicious > human) {
    classification = 'suspicious';
    confidence = Math.min(90, Math.round(50 + suspicious * 0.5));
  } else if (human >= 35 && human > suspicious) {
    classification = 'human_likely';
    confidence = Math.min(95, Math.round(50 + (human - 35) * 0.9));
  } else {
    classification = 'unknown';
    confidence = Math.max(35, Math.min(60, Math.round(40 + human * 0.4 - suspicious * 0.2)));
  }

  /* ---- reason list (all categories, heaviest first, capped) ---- */
  const all = []
    .concat(reasons.human.map(r => ({ kind: 'human', ...r })))
    .concat(reasons.bot.map(r => ({ kind: 'bot', ...r })))
    .concat(reasons.suspicious.map(r => ({ kind: 'suspicious', ...r })))
    .sort((a, b) => b.w - a.w)
    .slice(0, 8);

  if (classification === 'unknown' && all.length === 0) {
    all.push({ kind: 'none', w: 0, text: 'مفيش أدلة كافية في أي اتجاه — طلب متحفظ' });
  }

  return { classification, confidence, reasons: all };
}
