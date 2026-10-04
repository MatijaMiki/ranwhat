/* The email signup: posts an address to /api/subscribe, which checks the
 * Turnstile token, stores the address and mails it a confirmation link
 * through Resend (worker/src/list.js). Nobody is on the list until they
 * confirm.
 *
 * Turnstile loads only once someone starts on the form, so a page that
 * carries one, the home page among them, asks nothing of Cloudflare's
 * challenge until then. It renders as "interaction-only": invisible unless
 * it needs the visitor to do something.
 *
 * The checks that matter run on the server, like the contact form's.
 */
(function () {
  "use strict";
  var forms = document.querySelectorAll("form[data-subscribe]");
  if (!forms.length) return;

  var SITEKEY = "0x4AAAAAAFBNRE3i-BOA9gTd";
  var READY = "ranwhatTurnstileReady";
  var API = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=" + READY;
  var SHAPE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  var state = "idle", waiting = [];   // idle, loading, ready, failed

  /* One copy of Turnstile's script for every form on the page. */
  function withTurnstile(fn) {
    if (state === "ready") return fn(true);
    if (state === "failed") return fn(false);
    waiting.push(fn);
    if (state === "loading") return;
    state = "loading";
    window[READY] = function () {
      state = "ready";
      waiting.splice(0).forEach(function (f) { f(true); });
    };
    var script = document.createElement("script");
    script.src = API;
    script.async = true;
    script.onerror = function () {
      state = "failed";
      waiting.splice(0).forEach(function (f) { f(false); });
    };
    document.head.appendChild(script);
  }

  Array.prototype.forEach.call(forms, function (form) {
    var input = form.querySelector('input[type="email"]');
    var button = form.querySelector('button[type="submit"]');
    var note = form.querySelector('[role="status"]');
    var box = form.querySelector(".sub-check");
    var LABEL = button.innerHTML;
    var RESTING = note ? note.textContent.trim() : "";
    var widget = null, token = "", pending = false;

    function say(text, kind) {
      if (!note) return;
      note.textContent = text;
      note.className = "fnote" + (kind ? " " + kind : "");
    }
    function busy(on) {
      button.disabled = on;
      button.innerHTML = on ? "Subscribing&hellip;" : LABEL;
    }
    function blocked() {
      pending = false;
      busy(false);
      say("The check that keeps bots off the list did not load. If a blocker " +
          "stops challenges.cloudflare.com, allow it, or follow the RSS feed instead.", "warn");
    }

    function start() {
      if (widget !== null) return;
      widget = "loading";
      withTurnstile(function (ok) {
        if (!ok) { widget = null; if (pending) blocked(); return; }
        widget = window.turnstile.render(box, {
          sitekey: SITEKEY,
          action: "subscribe",
          theme: "auto",
          appearance: "interaction-only",
          callback: function (t) {
            token = t;
            if (pending) { pending = false; send(); }
          },
          "expired-callback": function () { token = ""; },
          "error-callback": function () {
            token = "";
            if (pending) blocked();
          },
        });
      });
    }

    async function send() {
      var t = token;
      token = "";
      var sent = false;
      try {
        var res = await fetch("/api/subscribe", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email: input.value.trim(), "cf-turnstile-response": t }),
        });
        var data = await res.json().catch(function () { return {}; });
        if (res.ok && data.ok) {
          input.value = "";
          say(data.queued
            ? "Thanks. Today\u2019s emails are used up, so the link to confirm " +
              "comes tomorrow. If you were already subscribed, there is nothing more to do."
            : "Check your inbox for a link to confirm. If you were already " +
              "subscribed, there is nothing more to do.", "sent");
          sent = true;
          return;
        }
        say(data.error || "That did not go through. Try again in a minute.", "warn");
      } catch (e) {
        say("That did not go through, which may be the network. Try again in a minute.", "warn");
      } finally {
        busy(false);
        /* A token is accepted once, so get a fresh one for whatever comes next. */
        if (window.turnstile && typeof widget === "string" && widget !== "loading") {
          try { window.turnstile.reset(widget); } catch (e) { /* the next submit asks again */ }
        }
        if (!sent) input.focus();
      }
    }

    input.addEventListener("focus", start);
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (!SHAPE.test(input.value.trim())) {
        say("That email address does not look right.", "warn");
        input.focus();
        return;
      }
      busy(true);
      if (token) { send(); return; }
      /* No token yet: send as soon as the challenge passes. */
      pending = true;
      say("Checking you are not a bot first.");
      start();
    });
    /* Typing again clears a stale result, but never the resting line. */
    input.addEventListener("input", function () {
      if (note && note.className !== "fnote") say(RESTING);
    });
  });
})();
