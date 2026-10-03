/* Light or dark, the visitor's choice.
 *
 * The stylesheet follows the system setting on its own; this only adds a
 * manual override, kept in localStorage. It loads in <head> without defer,
 * so a saved choice is applied before the first paint: a page that flashed
 * the wrong theme on every load would be worse than having no switch.
 */
(function () {
  "use strict";

  var KEY = "ranwhat-theme";
  var GROUND = { light: "#edeff1", dark: "#0E1318" };
  var root = document.documentElement;
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
})();
