// Tooltips accesibles (hover y foco) y selector de tema. Sin dependencias.
(function () {
  "use strict";
  var tip = document.getElementById("tooltip");

  function show(el, x, y) {
    tip.replaceChildren();
    [["tv", el.dataset.tipValue], ["tl", el.dataset.tipLabel], ["tx", el.dataset.tipExtra]].forEach(function (p) {
      if (!p[1]) return;
      p[1].split("\n").forEach(function (line) {
        var div = document.createElement("div");
        div.className = p[0];
        div.textContent = line; // los datos nunca se insertan como HTML
        tip.appendChild(div);
      });
    });
    tip.style.display = "block";
    var r = tip.getBoundingClientRect();
    var left = Math.min(x + 14, window.innerWidth - r.width - 8);
    var top = y + 14 + r.height > window.innerHeight ? y - r.height - 10 : y + 14;
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = Math.max(8, top) + "px";
  }
  function hide() { tip.style.display = "none"; }

  document.querySelectorAll("[data-tip-value]").forEach(function (el) {
    el.addEventListener("pointermove", function (e) { show(el, e.clientX, e.clientY); });
    el.addEventListener("pointerleave", hide);
    el.addEventListener("focus", function () {
      var r = el.getBoundingClientRect();
      show(el, r.left + r.width / 2, r.top + r.height);
    });
    el.addEventListener("blur", hide);
    el.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && el.dataset.href) window.location = el.dataset.href;
    });
    el.addEventListener("click", function () { if (el.dataset.href) window.location = el.dataset.href; });
  });

  var toggle = document.getElementById("theme-toggle");
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem("soc-theme");
    if (saved) root.dataset.theme = saved;
  } catch (e) { /* almacenamiento no disponible */ }
  if (toggle) {
    toggle.addEventListener("click", function () {
      var dark = root.dataset.theme
        ? root.dataset.theme === "dark"
        : window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem("soc-theme", root.dataset.theme); } catch (e) { /* noop */ }
    });
  }
})();
