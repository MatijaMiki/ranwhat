/* X ad measurement, and only with consent.
 *
 * We advertise on X, and X's pixel is how an ad finds out whether anyone it
 * sent actually arrived. It sets cookies and tells X about the visit, which
 * under the ePrivacy rules needs a yes first. So nothing from X loads until
 * the visitor says so, "No thanks" is exactly as easy as "Allow", and a
 * browser that sends Global Privacy Control is taken at its word and never
 * asked.
 *
 * The answer is kept in localStorage so the question is asked once. The
 * footer's "Privacy choices" reopens it, and changing a yes to a no reloads
 * the page so the pixel that already loaded is gone.
 */
(function () {
  "use strict";

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

  function choice() {
    var stored = read(KEY);
    if (stored === "granted" || stored === "denied") return stored;
    if (navigator.globalPrivacyControl === true) return "denied";
    return null;
  }

  var loaded = false;
  function load() {
    if (loaded) return;
    loaded = true;
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

  /* First-party cookies the pixel may have set on this domain. X's own
     cookies live on X's domains, where only X or the browser can clear them. */
  function forget() {
    write(CLICK, null);
    document.cookie.split(";").forEach(function (pair) {
      var name = pair.split("=")[0].trim();
      if (/^_?tw|twclid/i.test(name)) {
        document.cookie = name + "=; Max-Age=0; path=/";
        document.cookie = name + "=; Max-Age=0; path=/; domain=." + location.hostname;
      }
    });
  }

  var panel = null;
  function ask() {
    if (panel) { panel.hidden = false; return; }
    panel = document.createElement("section");
    panel.className = "consent";
    panel.setAttribute("aria-label", "Ad measurement");
    panel.innerHTML =
      '<p><strong>One question.</strong> May X’s ad pixel measure whether ' +
      'our posts on X bring people here? It sets cookies and tells X you ' +
      'visited. Nothing else on this site tracks you. ' +
      '<a href="/privacy#ads">What it sends</a></p>' +
      '<div class="consent-acts">' +
      '<button type="button" data-answer="granted">Allow</button>' +
      '<button type="button" data-answer="denied">No thanks</button>' +
      "</div>";
    panel.addEventListener("click", function (ev) {
      var answer = ev.target && ev.target.getAttribute("data-answer");
      if (!answer) return;
      var before = choice();
      write(KEY, answer);
      panel.hidden = true;
      if (answer === "granted") { load(); return; }
      forget();
      if (before === "granted" || loaded) location.reload();
    });
    document.body.appendChild(panel);
  }

  /* Other scripts ask here rather than reading storage themselves. */
  window.ranwhatAds = {
    allowed: function () { return choice() === "granted"; },
    click: function () { return choice() === "granted" ? click() : null; },
    lead: function (conversionId) {
      if (choice() !== "granted" || !EVENTS.lead || !window.twq) return;
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
  if (now === "granted") load();
  else if (now === null) {
    if (document.body) ask();
    else document.addEventListener("DOMContentLoaded", ask);
  }
})();
