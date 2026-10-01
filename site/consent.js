/* Measurement, and only with consent.
 *
 * Two things on this site can measure a visit, and each needs its own yes
 * under the ePrivacy rules, because each sets cookies and sends the visit to
 * another company:
 *   visit statistics  Google Analytics: which pages people read, and where
 *                     they came from;
 *   ad measurement    X's pixel: whether an ad on X brought anyone here.
 * Nothing from either loads until the visitor ticks it. "No thanks" is as
 * easy as "Allow all", and a browser that sends Global Privacy Control is
 * taken at its word and never asked.
 *
 * The answer is kept in localStorage so the question is asked once. The
 * footer's "Privacy choices" reopens it; withdrawing a yes clears what that
 * tool set on this domain and reloads the page so it is gone.
 */
(function () {
  "use strict";

  var GA_ID = "G-MTR111ZTTE";
  var PIXEL = "rfz6t";
  /* Event IDs come from X Events Manager. Empty means "not set up yet", and
     nothing is recorded for it. */
  var EVENTS = { lead: "tw-rfz6t-rfz7z" };
  var KEY = "ranwhat-consent";
  var CLICK = "ranwhat-twclid";
  var CLICK_DAYS = 30;

  function read(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function write(key, value) {
    try {
      if (value === null) window.localStorage.removeItem(key);
      else window.localStorage.setItem(key, value);
    } catch (e) { /* private mode: we simply ask again next time */ }
  }

  /* {stats, ads}, or null when the visitor has not answered. The first
     version stored "granted" or "denied" for the X pixel alone: that answer
     still stands for ads, and statistics is asked about once. */
  function choice() {
    var stored = read(KEY);
    if (stored && stored.charAt(0) === "{") {
      try {
        var c = JSON.parse(stored);
        if (typeof c.stats === "boolean" && typeof c.ads === "boolean") return c;
      } catch (e) { /* damaged: ask again */ }
    }
    if (navigator.globalPrivacyControl === true) return { stats: false, ads: false };
    return null;
  }
  function earlierAds() { return read(KEY) === "granted"; }

  var statsLoaded = false;
  function loadStats() {
    if (statsLoaded) return;
    statsLoaded = true;
    /* Google's gtag.js snippet, unrolled so it can live in this file: the
       site's CSP allows no inline script. Google signals and ad
       personalisation stay off, because this is for counting visits. */
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag("js", new Date());
    window.gtag("config", GA_ID, {
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
    });
    var s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtag/js?id=" + GA_ID;
    document.head.appendChild(s);
  }

  var adsLoaded = false;
  function loadAds() {
    if (adsLoaded) return;
    adsLoaded = true;
    /* X's base code, unrolled: a queue that uwt.js drains once it arrives. */
    var q = window.twq = function () {
      q.exe ? q.exe.apply(q, arguments) : q.queue.push(arguments);
    };
    q.version = "1.1";
    q.queue = [];
    var s = document.createElement("script");
    s.async = true;
    s.src = "https://static.ads-twitter.com/uwt.js";
    document.head.appendChild(s);
    window.twq("config", PIXEL);
    rememberClick();
  }

  /* An ad click lands with ?twclid=. Kept for 30 days so a contact message
     sent on a later visit can still be credited to the ad that brought the
     visitor, and only ever after consent. */
  function rememberClick() {
    try {
      var id = new URLSearchParams(location.search).get("twclid");
      if (id && /^[A-Za-z0-9_-]{8,200}$/.test(id)) {
        write(CLICK, JSON.stringify({ id: id, at: Date.now() }));
      }
    } catch (e) { /* nothing to keep */ }
  }

  function click() {
    try {
      var kept = JSON.parse(read(CLICK) || "null");
      if (kept && Date.now() - kept.at < CLICK_DAYS * 864e5) return kept.id;
    } catch (e) { /* ignore a damaged entry */ }
    return null;
  }

  /* First-party cookies a tool may have set on this domain. Cookies on
     Google's or X's own domains are theirs, or the browser's, to clear. */
  function clearCookies(pattern) {
    document.cookie.split(";").forEach(function (pair) {
      var name = pair.split("=")[0].trim();
      if (!pattern.test(name)) return;
      var host = location.hostname;
      document.cookie = name + "=; Max-Age=0; path=/";
      document.cookie = name + "=; Max-Age=0; path=/; domain=" + host;
      document.cookie = name + "=; Max-Age=0; path=/; domain=." + host;
    });
  }

  function apply(c) {
    if (c.stats) loadStats();
    if (c.ads) loadAds();
  }

  var panel = null;
  function box(purpose) { return panel.querySelector('[data-purpose="' + purpose + '"]'); }

  function decide(next) {
    write(KEY, JSON.stringify({ stats: next.stats, ads: next.ads }));
    panel.hidden = true;
    var gone = false;
    if (!next.stats) {
      /* Google's own opt-out switch: gtag.js stops sending and stops writing
         cookies at once, so the ping it sends as the page unloads cannot
         put _ga_<id> back after it has been cleared. */
      window["ga-disable-" + GA_ID] = true;
      clearCookies(/^_ga(_|$)/);
      gone = gone || statsLoaded;
    }
    if (!next.ads) {
      write(CLICK, null);
      clearCookies(/^_?tw|twclid/i);
      gone = gone || adsLoaded;
    }
    /* A script that already ran cannot be unloaded, only left behind. */
    if (gone) { location.reload(); return; }
    apply(next);
  }

  function ask() {
    var c = choice() || { stats: false, ads: earlierAds() };
    if (!panel) {
      panel = document.createElement("section");
      panel.className = "consent";
      panel.setAttribute("aria-label", "Measurement choices");
      panel.innerHTML =
        "<p><strong>Two questions.</strong> May we count visits with Google " +
        "Analytics, and may X’s pixel measure whether our posts on X bring " +
        "people here? Each sets cookies and sends your visit to that company. " +
        "Nothing else on this site tracks you. " +
        '<a href="/privacy#stats">What each sends</a></p>' +
        '<div class="consent-acts">' +
        '<button type="button" data-answer="all">Allow all</button>' +
        '<button type="button" data-answer="none">No thanks</button>' +
        "</div>" +
        '<button type="button" class="consent-more" data-answer="choose" aria-expanded="false">Choose for each</button>' +
        '<div class="consent-opts" hidden>' +
        '<label class="consent-opt"><input type="checkbox" data-purpose="stats"> ' +
        "Visit statistics (Google Analytics)</label>" +
        '<label class="consent-opt"><input type="checkbox" data-purpose="ads"> ' +
        "Ad measurement (X)</label>" +
        '<div class="consent-acts">' +
        '<button type="button" data-answer="save">Save choices</button>' +
        "</div>" +
        "</div>";
      panel.addEventListener("click", function (ev) {
        var answer = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-answer");
        if (answer === "all") decide({ stats: true, ads: true });
        else if (answer === "none") decide({ stats: false, ads: false });
        else if (answer === "save") decide({ stats: box("stats").checked, ads: box("ads").checked });
        else if (answer === "choose") expand(true);
      });
      document.body.appendChild(panel);
    }
    box("stats").checked = c.stats;
    box("ads").checked = c.ads;
    /* Someone reopening it from "Privacy choices" sees what they chose. */
    expand(choice() !== null);
    panel.hidden = false;
  }

  /* Two buttons by default; the per-purpose boxes open on request. Neither
     box starts ticked: a pre-ticked box is not consent. */
  function expand(open) {
    panel.querySelector(".consent-opts").hidden = !open;
    var more = panel.querySelector(".consent-more");
    more.hidden = open;
    more.setAttribute("aria-expanded", open ? "true" : "false");
  }

  /* Other scripts ask here rather than reading storage themselves. */
  function adsAllowed() { var c = choice(); return !!(c && c.ads) || earlierAds(); }
  window.ranwhatAds = {
    allowed: adsAllowed,
    click: function () { return adsAllowed() ? click() : null; },
    lead: function (conversionId) {
      if (!adsAllowed() || !EVENTS.lead || !window.twq) return;
      window.twq("event", EVENTS.lead, { conversion_id: conversionId });
    },
  };

  document.addEventListener("click", function (ev) {
    var link = ev.target && ev.target.closest && ev.target.closest("[data-consent-open]");
    if (!link) return;
    ev.preventDefault();
    ask();
  });

  var now = choice();
  /* A cookie a tool managed to write before it was declined goes on the
     next page load, wherever the visitor lands. */
  if (now && !now.stats) clearCookies(/^_ga(_|$)/);
  if (now && !now.ads) clearCookies(/^_?tw|twclid/i);
  if (now) apply(now);
  else {
    /* An earlier yes to the X pixel alone still counts until it is changed. */
    if (earlierAds()) loadAds();
    if (document.body) ask();
    else document.addEventListener("DOMContentLoaded", ask);
  }
})();
