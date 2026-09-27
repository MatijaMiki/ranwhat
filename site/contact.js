/* Posts the form to /api/contact, which verifies the Turnstile token before
 * sending anything. Everything here is convenience: the checks that matter run
 * on the server, because anything in this file can be edited by whoever is
 * looking at the page.
 */
(function () {
  "use strict";
  var form = document.getElementById("contact-form");
  if (!form) return;

  var note = document.getElementById("form-note");
  var button = document.getElementById("send");
  var FIELDS = ["email", "message"];
  var SETTLE_MS = 2500;
  var RESTING = note ? note.textContent.trim() : "";

  /* Let a link carry the topic in, so "Start a trial" lands on the right one. */
  try {
    var wanted = new URLSearchParams(location.search).get("about");
    var about = document.getElementById("about");
    if (wanted && about && about.querySelector('option[value="' + wanted + '"]')) {
      about.value = wanted;
    }
  } catch (e) { /* keep the default */ }

  function say(text, state) {
    if (!note) return;
    note.textContent = text;
    note.className = "fnote" + (state ? " " + state : "");
  }

  /* The button already says "Sending…", so the note stays quiet rather than
     saying it a second time directly underneath. */
  function busy(on) {
    if (!button) return;
    button.disabled = on;
    button.textContent = on ? "Sending…" : "Send →";
  }

  /* After a send the form dims and stops accepting input for a moment. It
     acknowledges the send without the page moving, and it absorbs the second
     click people give a button that has just gone quiet. */
  function lock(on) {
    form.classList.toggle("is-sent", on);
    Array.prototype.forEach.call(form.elements, function (el) {
      if (el.id !== "send") el.disabled = on;
    });
    if (button) button.disabled = on;
  }

  function get(id) {
    var el = document.getElementById(id);
    return el ? (el.value || "").trim() : "";
  }

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();

    var token = form.querySelector('[name="cf-turnstile-response"]');
    var payload = {
      about: (document.getElementById("about") || {}).value || "other",
      email: get("email"),
      message: get("message"),
      "cf-turnstile-response": token ? token.value : "",
    };

    /* Ad measurement rides along only when the visitor allowed it
       (consent.js). One ID for the message, so X counts the pixel's event and
       the server's report of it as a single lead rather than two. */
    var ads = window.ranwhatAds;
    var conversion = null;
    if (ads && ads.allowed()) {
      conversion = (window.crypto && crypto.randomUUID) ? crypto.randomUUID()
        : String(Date.now()) + "-" + Math.random().toString(36).slice(2);
      payload.measure = true;
      payload.conversion_id = conversion;
      var clickId = ads.click();
      if (clickId) payload.twclid = clickId;
    }

    if (!payload.message) { say("Add a message first.", "warn"); return; }
    if (!payload.email) { say("Add an email so we can reply.", "warn"); return; }
    if (!payload["cf-turnstile-response"]) {
      say("Wait for the challenge to finish, then send.", "warn");
      return;
    }

    busy(true);
    say(RESTING);
    var sent = false;
    try {
      var res = await fetch("/api/contact", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      var data = await res.json().catch(function () { return {}; });

      if (res.ok && data.ok) {
        /* Empty the fields rather than tearing the form out, so the page does
           not jump and a second message costs nothing. */
        FIELDS.forEach(function (id) {
          var el = document.getElementById(id);
          if (el) el.value = "";
        });
        say("Sent. We read everything, and a day or two is a normal reply time.", "sent");
        if (conversion && ads) ads.lead(conversion);
        sent = true;
        return;
      }
      say(data.error || "That did not send. Write to hello@ranwhat.com instead.", "warn");
    } catch (e) {
      say("That did not send, which may be the network. Write to hello@ranwhat.com instead.", "warn");
    } finally {
      busy(false);
      /* A used token is not accepted twice, so get a fresh one for a retry. */
      if (window.turnstile) { try { window.turnstile.reset(); } catch (e) {} }
      if (sent) {
        lock(true);
        setTimeout(function () { lock(false); }, SETTLE_MS);
      }
    }
  });

  /* Typing again clears a stale result, but never the resting explanation. */
  form.addEventListener("input", function () {
    if (note && note.className !== "fnote") say(RESTING);
  });
})();
