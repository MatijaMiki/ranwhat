/* Light or dark, the visitor's choice, the header's phone menu, and which
 * section of /commands its sidebar marks.
 *
 * The stylesheet follows the system setting on its own; this only adds a
 * manual override, kept in localStorage. It loads in <head> without defer,
 * so a saved choice is applied before the first paint: a page that flashed
 * the wrong theme on every load would be worse than having no switch.
 *
 * For the same reason it marks the page html.js before the first paint:
 * the stylesheet folds a phone's links into the menu only then, so a page
 * without script keeps them open, and none draws them open and then shuts.
 */
(function () {
  "use strict";

  var KEY = "ranwhat-theme";
  var GROUND = { light: "#edeff1", dark: "#0E1318" };
  var root = document.documentElement;
  root.classList.add("js");
  var system = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function saved() {
    try {
      var v = window.localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : null;
    } catch (e) { return null; }
  }
  function current() {
    return saved() || (system && system.matches ? "dark" : "light");
  }
  function paint(theme) {
    root.setAttribute("data-theme", theme);
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) metas[i].setAttribute("content", GROUND[theme]);
  }

  var choice = saved();
  if (choice) paint(choice);

  function describe(button) {
    button.setAttribute("aria-label",
      current() === "dark" ? "Switch to the light theme" : "Switch to the dark theme");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    describe(button);
    button.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      try { window.localStorage.setItem(KEY, next); } catch (e) { /* this page only */ }
      paint(next);
      describe(button);
    });
    if (system && system.addEventListener) {
      system.addEventListener("change", function () { if (!saved()) describe(button); });
    }
  });

  // The phone menu: the button after GitHub opens the links under the bar
  // (styles.css, "phone menu"). Escape, a tap outside it or on a link shuts
  // it. On a wider screen the button is hidden and the links always show.
  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector("[data-menu-toggle]");
    var bar = button && button.parentNode;
    if (!bar) return;
    function open(yes) {
      bar.classList.toggle("open", yes);
      button.setAttribute("aria-expanded", yes ? "true" : "false");
      button.setAttribute("aria-label", yes ? "Close menu" : "Open menu");
    }
    button.addEventListener("click", function () {
      open(!bar.classList.contains("open"));
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && bar.classList.contains("open")) {
        open(false);
        button.focus();
      }
    });
    document.addEventListener("click", function (e) {
      if (!bar.classList.contains("open")) return;
      var link = e.target.closest && e.target.closest("nav a");
      if (!bar.contains(e.target) || link) open(false);
    });
  });

  // The commands sidebar. On a page whose own sections it links to
  // (/commands), it marks the section being read rather than the page: the
  // last one whose top has passed under the header. Without script the
  // page's own link stays marked. On a phone the sidebar is one row of
  // links, scrolled sideways to keep the marked one in sight.
  document.addEventListener("DOMContentLoaded", function () {
    var nav = document.querySelector(".docnav");
    if (!nav) return;
    var here = location.pathname.replace(/\.html$/, "");
    var links = [], sections = [];      // a null section: the top of the page
    var all = nav.querySelectorAll("li a[href]");
    for (var i = 0; i < all.length; i++) {
      var url = new URL(all[i].getAttribute("href"), location.href);
      if (url.pathname.replace(/\.html$/, "") !== here) continue;
      var section = url.hash ? document.getElementById(url.hash.slice(1)) : null;
      if (url.hash && !section) continue;
      links.push(all[i]);
      sections.push(section);
    }
    if (links.length < 2) return;
    var current = -1, LINE = 120;       // the 58px header and the anchors' scroll padding, with room
    function mark(n) {
      if (n === current) return;
      current = n;
      for (var j = 0; j < links.length; j++) {
        if (j === n) links[j].setAttribute("aria-current", sections[j] ? "location" : "page");
        else links[j].removeAttribute("aria-current");
      }
      if (nav.scrollWidth > nav.clientWidth) {
        nav.scrollLeft = links[n].offsetLeft - (nav.clientWidth - links[n].offsetWidth) / 2;
      }
    }
    function update() {
      var n = 0, last = 0;
      for (var j = 0; j < sections.length; j++) {
        if (!sections[j]) continue;
        last = j;
        if (sections[j].getBoundingClientRect().top <= LINE) n = j;
      }
      // scrolled to the end, the last section is the one being read, however short
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) n = last;
      mark(n);
    }
    var queued = false;
    window.addEventListener("scroll", function () {
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(function () { queued = false; update(); });
    }, { passive: true });
    window.addEventListener("hashchange", update);
    window.addEventListener("load", update);
    update();
  });
})();
