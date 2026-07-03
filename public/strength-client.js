/**
 * saltcorn-password-tools — Client-side strength meter.
 *
 * Suche alle .pwtools-wrapper im DOM und binde Input-Listener.
 * Nutzt zxcvbn (vom Plugin ueber CDN geladen) plus die konfigurierten
 * Policy-Regeln (data-pwtools-policy JSON-Attribut auf .pwtools-wrapper).
 */
(function () {
  "use strict";

  const LABELS = [
    "Sehr schwach",
    "Schwach",
    "Mittel",
    "Stark",
    "Sehr stark",
  ];
  const COLORS = ["#dc3545", "#fd7e14", "#ffc107", "#20c997", "#198754"];

  function init(wrapper) {
    if (wrapper.dataset.pwtoolsInit === "1") return;
    wrapper.dataset.pwtoolsInit = "1";

    const input = wrapper.querySelector("[data-pwtools-input]");
    const meter = wrapper.querySelector(".pwtools-strength");
    if (!input || !meter) return;

    const bar = meter.querySelector(".progress-bar");
    const label = meter.querySelector(".pwtools-strength-label");
    const feedback = meter.querySelector(".pwtools-strength-feedback");

    let policy = {};
    try {
      policy = JSON.parse(wrapper.getAttribute("data-pwtools-policy") || "{}");
    } catch (_e) {
      policy = {};
    }

    function evalRules(pw) {
      const problems = [];
      if (!pw) return { problems: ["Bitte Passwort eingeben"] };
      if (policy.minLength && pw.length < policy.minLength)
        problems.push("Mindestens " + policy.minLength + " Zeichen");
      if (policy.requireUpper && !/[A-Z]/.test(pw))
        problems.push("Grossbuchstabe fehlt");
      if (policy.requireLower && !/[a-z]/.test(pw))
        problems.push("Kleinbuchstabe fehlt");
      if (policy.requireDigit && !/[0-9]/.test(pw))
        problems.push("Ziffer fehlt");
      if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(pw))
        problems.push("Sonderzeichen fehlt");
      return { problems };
    }

    function render(pw) {
      const rules = evalRules(pw);
      let score = -1;
      const suggestions = [];
      if (window.zxcvbn && pw) {
        const z = window.zxcvbn(pw);
        score = z.score;
        if (z.feedback && z.feedback.warning)
          suggestions.push(z.feedback.warning);
        if (z.feedback && Array.isArray(z.feedback.suggestions))
          suggestions.push.apply(suggestions, z.feedback.suggestions);
      }

      const pct = pw ? Math.max(5, ((score + 1) / 5) * 100) : 0;
      bar.style.width = pct + "%";
      bar.style.background = score >= 0 ? COLORS[score] : "#e9ecef";

      if (!pw) {
        label.textContent = "Bitte Passwort eingeben";
        label.style.color = "";
      } else {
        const passesRules = rules.problems.length === 0;
        const passesScore =
          policy.minScore === undefined || score < 0 || score >= policy.minScore;
        const strong = passesRules && passesScore;
        const scoreLabel = score >= 0 ? LABELS[score] : "unbekannt";
        label.textContent =
          "Staerke: " +
          scoreLabel +
          (strong ? " — Policy erfuellt" : " — Policy NICHT erfuellt");
        label.style.color = strong ? "#198754" : "#dc3545";
      }

      feedback.innerHTML = "";
      rules.problems.concat(suggestions).forEach(function (msg) {
        const li = document.createElement("li");
        li.textContent = msg;
        feedback.appendChild(li);
      });
    }

    input.addEventListener("input", function () {
      render(input.value);
    });

    // Initial render (fuer den Fall, dass der Browser Autofill befuellt)
    render(input.value || "");
  }

  function scan() {
    const wrappers = document.querySelectorAll(".pwtools-wrapper");
    for (let i = 0; i < wrappers.length; i++) init(wrappers[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scan);
  } else {
    scan();
  }

  // Auch spaeter injizierte Formulare erfassen (z. B. Modal-Views)
  if (window.MutationObserver) {
    const obs = new MutationObserver(function () {
      scan();
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }
})();
