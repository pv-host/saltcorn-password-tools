/**
 * saltcorn-password-tools - Client-side strength meter, confirm-check, policy-check.
 *
 * Blockade-Strategie fuer Saltcorn-Edit-Views:
 * - Saltcorn rendert Save-Buttons oft als <button type="button" onclick="ajaxSubmitForm(this, true)">.
 *   Ein reines submit-Event feuert dabei NICHT.
 * - Wir haengen an alle relevanten Buttons einen Capture-Phase-Click-Handler,
 *   der bei Fehler stopImmediatePropagation() ruft. Das verhindert auch den
 *   inline onclick-Handler (browserseitig als spaeterer Listener behandelt).
 * - Zusaetzlich sichern wir das submit-Event (klassische Formulare).
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
    const enforcePolicy = wrapper.getAttribute("data-pwtools-enforce") !== "0";

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

    function computePolicyOk(pw) {
      if (!pw) return false;
      const rules = evalRules(pw);
      if (rules.problems.length > 0) return false;
      if (window.zxcvbn && policy.minScore !== undefined) {
        const z = window.zxcvbn(pw);
        if (z.score < policy.minScore) return false;
      }
      return true;
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
          (strong ? " - Policy erfuellt" : " - Policy NICHT erfuellt");
        label.style.color = strong ? "#198754" : "#dc3545";
      }

      feedback.innerHTML = "";
      rules.problems.concat(suggestions).forEach(function (msg) {
        const li = document.createElement("li");
        li.textContent = msg;
        feedback.appendChild(li);
      });

      // Marker fuer Submit-Blockade
      wrapper.dataset.pwtoolsPolicyOk = computePolicyOk(pw) ? "1" : "0";
    }

    input.addEventListener("input", function () {
      render(input.value);
      checkConfirm();
    });

    if (requireConfirm) {
      confirmInput.addEventListener("input", checkConfirm);
      confirmInput.addEventListener("blur", checkConfirm);
    }

    // Submit-Blockade
    const form = input.closest("form");
    if (form && !form.dataset.pwtoolsSubmitBound) {
      form.dataset.pwtoolsSubmitBound = "1";
      bindFormBlockade(form);
    }

    // Initial render
    render(input.value || "");
    if (requireConfirm) checkConfirm();
  }

  // Zentrale Validierung fuer ein Form: prueft alle .pwtools-wrapper.
  function validatePwFormState(form) {
    const wrappers = form.querySelectorAll(".pwtools-wrapper");
    let ok = true;
    for (let i = 0; i < wrappers.length; i++) {
      const w = wrappers[i];
      const p = w.querySelector("[data-pwtools-input]");
      if (!p) continue;
      const pv = p.value || "";

      // Nur pruefen, wenn ein Passwort eingegeben wurde. Leer = nicht editiert.
      if (!pv) continue;

      // Confirm
      if (w.getAttribute("data-pwtools-confirm") === "1") {
        const c = w.querySelector("[data-pwtools-confirm-input]");
        const cv = c ? c.value || "" : "";
        if (pv !== cv) {
          const msg = w.querySelector(".pwtools-confirm-msg");
          if (msg) {
            msg.textContent = "Passwoerter stimmen nicht ueberein";
            msg.classList.remove("text-success");
            msg.classList.add("text-danger");
          }
          if (c) {
            c.classList.add("is-invalid");
            c.focus();
          }
          ok = false;
          continue;
        }
      }

      // Policy
      if (w.getAttribute("data-pwtools-enforce") !== "0") {
        if (w.dataset.pwtoolsPolicyOk !== "1") {
          p.classList.add("is-invalid");
          // Fokus auf Passwortfeld
          if (ok) p.focus();
          ok = false;
        } else {
          p.classList.remove("is-invalid");
        }
      }
    }
    return ok;
  }

  function bindFormBlockade(form) {
    // 1) Klassisches submit-Event (feuert bei <button type="submit"> und form.submit()).
    form.addEventListener(
      "submit",
      function (ev) {
        if (!validatePwFormState(form)) {
          ev.preventDefault();
          ev.stopPropagation();
          if (typeof ev.stopImmediatePropagation === "function")
            ev.stopImmediatePropagation();
          return false;
        }
      },
      true
    );

    // 2) Alle potenziellen Save-Buttons: Capture-Click abfangen.
    //    Saltcorn nutzt <button type="button" onclick="ajaxSubmitForm(this, true)">
    //    - onclick-inline ist ein normaler Listener und wird von
    //      stopImmediatePropagation NICHT verlaesslich gestoppt.
    //    - Deshalb ersetzen wir bei Fehler den onclick durch einen Wrapper,
    //      der zunaechst validiert.
    const buttons = form.querySelectorAll(
      'button, input[type="submit"], input[type="button"]'
    );
    for (let i = 0; i < buttons.length; i++) {
      const btn = buttons[i];
      if (btn.dataset.pwtoolsClickBound === "1") continue;

      // onclick-inline wrappen (nur wenn ein onclick vorhanden ist, das
      // vermutlich einen Submit ausloest).
      const inlineOnClick = btn.getAttribute("onclick") || "";
      const looksLikeSubmit =
        /ajaxSubmitForm|submitWithAjax|form_submit|form\.submit|sc_form_submit/.test(
          inlineOnClick
        ) ||
        btn.type === "submit" ||
        btn.classList.contains("btn-primary");

      if (!looksLikeSubmit) continue;

      btn.dataset.pwtoolsClickBound = "1";

      // Wrap den inline onclick.
      if (inlineOnClick) {
        btn.removeAttribute("onclick");
        btn._pwtoolsOrigOnClick = inlineOnClick;
      }

      btn.addEventListener(
        "click",
        function (ev) {
          if (!validatePwFormState(form)) {
            ev.preventDefault();
            ev.stopPropagation();
            if (typeof ev.stopImmediatePropagation === "function")
              ev.stopImmediatePropagation();
            return false;
          }
          // Passwortprobleme keine -> Original-onclick ausfuehren.
          if (btn._pwtoolsOrigOnClick) {
            // Ausfuehren im Kontext des Buttons.
            try {
              // eslint-disable-next-line no-new-func
              new Function("event", btn._pwtoolsOrigOnClick).call(btn, ev);
            } catch (e) {
              console.error("[pwtools] onclick error:", e);
            }
          }
        },
        true
      );
    }
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
