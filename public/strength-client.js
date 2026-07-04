/**
 * saltcorn-password-tools — Client-side strength meter and confirm-check.
 *
 * Suche alle .pwtools-wrapper im DOM und binde Input-Listener.
 * Nutzt zxcvbn (vom Plugin ueber CDN geladen) plus die konfigurierten
 * Policy-Regeln (data-pwtools-policy JSON-Attribut auf .pwtools-wrapper).
 *
 * Wenn data-pwtools-confirm="1" gesetzt ist, wird zusaetzlich das
 * Bestaetigungsfeld gegen das Primaerfeld geprueft und das umgebende
 * <form> beim Submit blockiert, falls beide nicht identisch sind.
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
    const confirmInput = wrapper.querySelector("[data-pwtools-confirm-input]");
    const meter = wrapper.querySelector(".pwtools-strength");
    if (!input || !meter) return;

    const bar = meter.querySelector(".progress-bar");
    const label = meter.querySelector(".pwtools-strength-label");
    const feedback = meter.querySelector(".pwtools-strength-feedback");
    const confirmMsg = wrapper.querySelector(".pwtools-confirm-msg");

    let policy = {};
    try {
      policy = JSON.parse(wrapper.getAttribute("data-pwtools-policy") || "{}");
    } catch (_e) {
      policy = {};
    }

    const requireConfirm =
      wrapper.getAttribute("data-pwtools-confirm") === "1" && !!confirmInput;

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

    function checkConfirm() {
      if (!requireConfirm) return true;
      const a = input.value || "";
      const b = confirmInput.value || "";

      if (!a && !b) {
        setConfirmState("neutral", "");
        return false;
      }
      if (!b) {
        setConfirmState("neutral", "Bitte Passwort wiederholen");
        return false;
      }
      if (a !== b) {
        setConfirmState("mismatch", "Passwoerter stimmen nicht ueberein");
        return false;
      }
      setConfirmState("match", "Passwoerter stimmen ueberein");
      return true;
    }

    function setConfirmState(state, text) {
      if (!confirmMsg) return;
      confirmMsg.textContent = text;
      if (state === "mismatch") {
        confirmMsg.classList.remove("text-success");
        confirmMsg.classList.add("text-danger");
        confirmInput.classList.add("is-invalid");
        confirmInput.classList.remove("is-valid");
      } else if (state === "match") {
        confirmMsg.classList.remove("text-danger");
        confirmMsg.classList.add("text-success");
        confirmInput.classList.remove("is-invalid");
        confirmInput.classList.add("is-valid");
      } else {
        confirmMsg.classList.remove("text-danger", "text-success");
        confirmInput.classList.remove("is-invalid", "is-valid");
      }
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
      checkConfirm();
    });

    if (requireConfirm) {
      confirmInput.addEventListener("input", checkConfirm);
      confirmInput.addEventListener("blur", checkConfirm);

      // Submit-Blockade beim umschliessenden Form (fuer klassischen und AJAX-Submit).
      const form = input.closest("form");
      if (form && !form.dataset.pwtoolsSubmitBound) {
        form.dataset.pwtoolsSubmitBound = "1";

        // 1) Klassisches submit-Event (capture, damit wir vor Saltcorn-Handlern greifen).
        form.addEventListener(
          "submit",
          function (ev) {
            if (!validateAllPwWrappers(form)) {
              ev.preventDefault();
              ev.stopPropagation();
              if (typeof ev.stopImmediatePropagation === "function")
                ev.stopImmediatePropagation();
              return false;
            }
          },
          true
        );

        // 2) Klick auf submit/save-Buttons abfangen (Saltcorn nutzt teils
        // direkte Button-Handler statt echtes form.submit()).
        const submitButtons = form.querySelectorAll(
          'button[type="submit"], input[type="submit"], button[onclick*="submit"], .btn-primary'
        );
        for (let i = 0; i < submitButtons.length; i++) {
          submitButtons[i].addEventListener(
            "click",
            function (ev) {
              if (!validateAllPwWrappers(form)) {
                ev.preventDefault();
                ev.stopPropagation();
                if (typeof ev.stopImmediatePropagation === "function")
                  ev.stopImmediatePropagation();
                return false;
              }
            },
            true
          );
        }
      }
    }

    // Initial render
    render(input.value || "");
    if (requireConfirm) checkConfirm();
  }

  function validateAllPwWrappers(form) {
    const dirty = form.querySelectorAll(
      '.pwtools-wrapper[data-pwtools-confirm="1"]'
    );
    let ok = true;
    for (let i = 0; i < dirty.length; i++) {
      const w = dirty[i];
      const p = w.querySelector("[data-pwtools-input]");
      const c = w.querySelector("[data-pwtools-confirm-input]");
      if (!p || !c) continue;
      const pv = p.value || "";
      const cv = c.value || "";
      if (pv && pv !== cv) {
        const msg = w.querySelector(".pwtools-confirm-msg");
        if (msg) {
          msg.textContent = "Passwoerter stimmen nicht ueberein";
          msg.classList.remove("text-success");
          msg.classList.add("text-danger");
        }
        c.classList.add("is-invalid");
        c.focus();
        ok = false;
      }
    }
    return ok;
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

  if (window.MutationObserver) {
    const obs = new MutationObserver(function () {
      scan();
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }
})();
