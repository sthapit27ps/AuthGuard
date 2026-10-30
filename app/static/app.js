// AuthGuard front-end: strength meter and show/hide for password fields.
// No libraries, nothing inline (the Content-Security-Policy would block it).

(function () {
  "use strict";

  var csrf = document.querySelector('meta[name="csrf"]');
  var csrfToken = csrf ? csrf.getAttribute("content") : "";

  // sthapit27ps

  function debounce(fn, ms) {
    var timer;
    return function () {
      var args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(null, args); }, ms);
    };
  }

  // ---- show / hide ----
  document.querySelectorAll("[data-reveal]").forEach(function (button) {
    var input = document.getElementById(button.getAttribute("data-reveal"));
    if (!input) return;
    button.addEventListener("click", function () {
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      button.textContent = hidden ? "Hide" : "Show";
      button.setAttribute("aria-pressed", hidden ? "true" : "false");
    });
  });

  // ---- strength meter ----
  var field = document.querySelector("[data-strength]");
  var meter = document.getElementById("meter");
  var word = document.getElementById("strength-word");
  var hints = document.getElementById("strength-hints");
  if (!field || !meter || !word || !hints) return;

  var emailField = document.getElementById("email");
  var nameField = document.getElementById("display_name");
  var latest = 0;

  function paint(data) {
    meter.className = "meter lv" + data.score;
    word.textContent = data.label;
    hints.textContent = "";
    var lines = (data.problems || []).concat(data.tips || []);
    lines.slice(0, 3).forEach(function (line) {
      var li = document.createElement("li");
      li.textContent = line;
      hints.appendChild(li);
    });
  }

  function clear() {
    meter.className = "meter";
    word.textContent = "not entered yet";
    hints.textContent = "";
  }

  var check = debounce(function () {
    var value = field.value;
    if (!value) { latest++; clear(); return; }
    var ticket = ++latest;
    fetch("/api/password-strength", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({
        password: value,
        email: emailField ? emailField.value : "",
        name: nameField ? nameField.value : ""
      })
    })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { if (data && ticket === latest) paint(data); })
      .catch(function () { /* the server still checks on submit */ });
  }, 250);

  field.addEventListener("input", check);
}());
