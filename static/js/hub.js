// static/js/hub.js, hub interactivity: onboarding-primer taxonomy cards flip
// on click/keyboard activation. No network calls; the flag form is a plain
// HTML POST handled server-side (core/unlock.submit_flag).
(function () {
  "use strict";

  document.querySelectorAll("[data-flip-card]").forEach(function (card) {
    card.setAttribute("aria-pressed", "false");
    card.addEventListener("click", function () {
      var open = card.getAttribute("data-open") === "true";
      card.setAttribute("data-open", open ? "false" : "true");
      card.setAttribute("aria-pressed", open ? "false" : "true");
    });
  });
})();
