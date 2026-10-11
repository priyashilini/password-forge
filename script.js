
// Password Forge — secure, offline password generation and analysis.
// No network requests. No persistent password storage.

"use strict";

(() => {
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];

  const CHARSETS = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?/"
  };

  const AMBIGUOUS = new Set(["l", "I", "1", "O", "0"]);
  const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
  const MAX_HISTORY = 5;

  let currentMode = "fortress";
  let currentPassword = "";
  let isHidden = false;
  let history = [];
  let clipboardTimer = null;
  let generationError = "";

  // Secure random integers without modulo bias.
  // Rejection sampling avoids favoring certain characters.
  function secureInt(max) {
    if (!Number.isSafeInteger(max) || max < 1 || max > 0x100000000) {
      throw new Error("Invalid random range.");
    }

    const range = 0x100000000;
    const limit = range - (range % max);
    const buffer = new Uint32Array(1);

    do {
      crypto.getRandomValues(buffer);
    } while (buffer[0] >= limit);

    return buffer[0] % max;
  }

  function pick(items) {
    if (!items || items.length === 0) {
      throw new Error("No choices available.");
    }
    return items[secureInt(items.length)];
  }

  function shuffle(items) {
    // Fisher–Yates using cryptographically secure indices.
    for (let i = items.length - 1; i > 0; i--) {
      const j = secureInt(i + 1);
      [items[i], items[j]] = [items[j], items[i]];
    }
    return items;
  }

  function randomFromString(characters) {
    return characters[secureInt(characters.length)];
  }

  function getFortressPassword() {
    const length = Number($("#lengthRange").value);
    const custom = $("#customCharset").value;
    const exclude = $("#excludeAmbiguous").checked;

    let alphabet = "";
    let requiredGroups = [];

    if (custom.trim()) {
      alphabet = [...new Set(custom)].join("");
      requiredGroups = [alphabet];
    } else {
      const groupIds = [
        ["lowercase", CHARSETS.lowercase],
        ["uppercase", CHARSETS.uppercase],
        ["numbers", CHARSETS.numbers],
        ["symbols", CHARSETS.symbols]
      ];

      for (const [id, chars] of groupIds) {
        if ($("#" + id).checked) {
          let group = chars;
          if (exclude) {
            group = [...group].filter((c) => !AMBIGUOUS.has(c)).join("");
          }
          if (group) {
            requiredGroups.push(group);
            alphabet += group;
          }
        }
      }
    }

    alphabet = [...new Set(alphabet)].join("");

    if (exclude && !custom.trim()) {
      alphabet = [...alphabet].filter((c) => !AMBIGUOUS.has(c)).join("");
    }

    if (!alphabet) {
      throw new Error("Select at least one character group or enter a custom character set.");
    }

    // A requested length must accommodate every selected character group.
    if (requiredGroups.length > length) {
      throw new Error("Password length must be at least the number of selected character groups.");
    }

    const result = [];

    // Guarantee one character from every enabled group.
    for (const group of requiredGroups) {
      result.push(randomFromString(group));
    }

    while (result.length < length) {
      result.push(randomFromString(alphabet));
    }

    shuffle(result);

    return {
      password: result.join(""),
      // Exact under the stated uniform-selection model, before warnings.
      entropy: length * Math.log2(alphabet.length),
      alphabetSize: alphabet.length,
      length,
      method: "fortress",
      wordCount: 0
    };
  }

  function capitalize(word) {
    return word.charAt(0).toUpperCase() + word.slice(1);
  }

  function getMemoryPassword() {
    if (!Array.isArray(PASSWORD_WORDS) || PASSWORD_WORDS.length < 300) {
      throw new Error("The word list is missing or incomplete. Check words.js.");
    }

    const count = Number($("#wordCount").value);
    const separator = $("#separator").value;
    const words = [];

    for (let i = 0; i < count; i++) {
      let word = pick(PASSWORD_WORDS);
      if ($("#capitalizeWords").checked) word = capitalize(word);
      words.push(word);
    }

    let password = words.join(separator);
    let extraAlphabetSize = 1;

    if ($("#memoryNumber").checked) {
      const number = String(secureInt(100)).padStart(2, "0");
      password += number;
      extraAlphabetSize *= 100;
    }

    if ($("#memorySymbol").checked) {
      password += randomFromString(SYMBOLS);
      extraAlphabetSize *= SYMBOLS.length;
    }

    // Repeated words are possible; this is a conservative estimate of the
    // word-choice entropy, plus optional independently generated extras.
    const entropy =
      count * Math.log2(new Set(PASSWORD_WORDS).size) +
      Math.log2(extraAlphabetSize);

    return {
      password,
      entropy,
      alphabetSize: new Set(PASSWORD_WORDS).size,
      length: password.length,
      method: "memory",
      wordCount: count
    };
  }

  const ONSETS = [
    "b", "br", "c", "ch", "d", "dr", "f", "fl", "g", "gr",
    "h", "j", "k", "kl", "kr", "l", "m", "n", "p", "pl",
    "pr", "qu", "r", "s", "sh", "sk", "sl", "sm", "sn",
    "st", "sw", "t", "tr", "v", "w", "z"
  ];
  const VOWELS = ["a", "e", "i", "o", "u", "ae", "ai", "ea", "oi"];
  const CODAS = [
    "", "", "", "b", "ck", "d", "f", "g", "k", "l",
    "m", "n", "nd", "ng", "nt", "p", "r", "rk", "s", "sh", "t", "x"
  ];

  function getHumanPassword() {
    const count = Number($("#syllableCount").value);
    const syllables = [];

    for (let i = 0; i < count; i++) {
      let syllable = pick(ONSETS) + pick(VOWELS) + pick(CODAS);
      if (i === 0) syllable = capitalize(syllable);
      syllables.push(syllable);
    }

    let password = syllables.join("-");

    const addNumber = $("#humanNumber").checked;
    const addSymbol = $("#humanSymbol").checked;

    if (addNumber) {
      password += "-" + String(secureInt(100)).padStart(2, "0");
    }
    if (addSymbol) {
      password += randomFromString(SYMBOLS);
    }

    // Conservative construction model: choices per independently selected
    // syllable, with optional number and symbol choices.
    let entropy =
      count *
      (Math.log2(ONSETS.length) +
        Math.log2(VOWELS.length) +
        Math.log2(CODAS.length));

    if (addNumber) entropy += Math.log2(100);
    if (addSymbol) entropy += Math.log2(SYMBOLS.length);

    return {
      password,
      entropy,
      alphabetSize: null,
      length: password.length,
      method: "human",
      wordCount: 0
    };
  }

  function generatePassword() {
    if (!window.crypto || typeof crypto.getRandomValues !== "function") {
      currentPassword = "";
      generationError = "This browser does not support secure random generation. Use a modern browser.";
      renderError();
      return;
    }

    try {
      let result;

      if (currentMode === "fortress") result = getFortressPassword();
      else if (currentMode === "memory") result = getMemoryPassword();
      else result = getHumanPassword();

      currentPassword = result.password;
      generationError = "";
      history.unshift(currentPassword);
      history = history.slice(0, MAX_HISTORY);

      isHidden = false;
      $("#visibilityToggle").setAttribute("aria-pressed", "false");
      $("#visibilityToggle").setAttribute("aria-label", "Hide password");
      $("#visibilityToggle").textContent = "◉";

      renderPassword();
      renderHistory();
      analyze(result);

      $("#copyStatus").textContent = "";
      $("#passwordOutput").classList.remove("is-hidden");

      if (clipboardTimer) {
        clearTimeout(clipboardTimer);
        clipboardTimer = null;
      }
    } catch (error) {
      currentPassword = "";
      generationError = error instanceof Error
        ? error.message
        : "Unable to generate a password.";
      renderError();
    }
  }

  function renderError() {
    $("#passwordOutput").textContent = "Configuration needed";
    $("#passwordLengthLabel").textContent = "NOT GENERATED";
    $("#strengthLabel").textContent = "UNAVAILABLE";
    $("#entropyLabel").textContent = "— bits";
    $("#strengthFill").style.width = "0%";
    $("#strengthProgress").setAttribute("aria-valuenow", "0");
    $("#crackTime").textContent = "—";
    $("#entropyDetail").textContent = "—";
    $("#lengthDetail").textContent = "—";
    $("#varietyDetail").textContent = "—";
    $("#whyText").textContent = generationError;
    $("#warningList").replaceChildren();
    $("#ingotWrap").dataset.strength = "weak";
    $("#ingotCaption").textContent = "AWAITING CONFIGURATION";
    $("#copyStatus").textContent = generationError;
    $("#copyButton").disabled = true;
    $("#visibilityToggle").disabled = true;
    renderHistory();
  }

  function renderPassword() {
    $("#copyButton").disabled = !currentPassword;
    $("#visibilityToggle").disabled = !currentPassword;

    $("#passwordOutput").textContent = isHidden
      ? "•".repeat(Math.min(currentPassword.length, 64))
      : currentPassword;

    $("#passwordOutput").classList.toggle("is-hidden", isHidden);
    $("#passwordLengthLabel").textContent =
      `${currentPassword.length} CHARACTERS`;
  }

  // A simple, intentionally conservative set of common patterns.
  const COMMON_PATTERNS = [
    "password", "passw0rd", "admin", "welcome", "letmein",
    "qwerty", "asdf", "zxcv", "123456", "654321",
    "abc123", "iloveyou", "monkey", "dragon", "football",
    "sunshine", "master", "login", "princess", "secret"
  ];

  function getWarnings(password) {
    const warnings = [];
    const lower = password.toLowerCase();

    if (/(.)\1{2,}/u.test(password)) {
      warnings.push("Contains a character repeated three or more times in a row.");
    }

    if (/(?:0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|abcd|bcde|cdef|qwer|wert|erty|asdf|sdfg|zxcv)/i.test(password)) {
      warnings.push("Contains a familiar keyboard or sequential pattern.");
    }

    if (/(password|admin|welcome|letmein|qwerty|iloveyou|login|secret|monkey|dragon)/i.test(password)) {
      warnings.push("Contains a commonly used password word.");
    }

    if (/(?:@|4)/i.test(password) ||
        /0/i.test(password) ||
        /1/i.test(password) ||
        /3/i.test(password) ||
        /5/i.test(password)) {
      if (/[a-z]/i.test(password) &&
          /[@@]|0|1|3|4|5/.test(password)) {
        warnings.push("Some substitutions (such as @ for a or 0 for o) may be predictable.");
      }
    }

    const normalized = lower
      .replace(/@/g, "a")
      .replace(/[04]/g, "o")
      .replace(/[13!|]/g, "i")
      .replace(/\$/g, "s")
      .replace(/5/g, "s")
      .replace(/7/g, "t");

    if (COMMON_PATTERNS.some((pattern) => normalized.includes(pattern))) {
      if (!warnings.some((w) => w.includes("commonly used password word"))) {
        warnings.push("Resembles a common password or a predictable substitution.");
      }
    }

    if (password.length < 12) {
      warnings.push("Short passwords provide less room for security; consider using a longer one.");
    }

    if (warnings.length === 0) {
      warnings.push("No obvious patterns detected. This does not guarantee resistance to every attack.");
    }

    return warnings;
  }

  function getStrength(entropy, warnings) {
    // Labels are practical heuristics, not a standardized security certification.
    let adjusted = entropy;

    for (const warning of warnings) {
      if (/common|substitution|keyboard/i.test(warning)) adjusted -= 18;
      else if (/repeated/i.test(warning)) adjusted -= 8;
    }

    adjusted = Math.max(0, adjusted);

    let label;
    let level;

    if (adjusted < 28) {
      label = "Weak";
      level = "weak";
    } else if (adjusted < 50) {
      label = "Fair";
      level = "fair";
    } else if (adjusted < 80) {
      label = "Strong";
      level = "strong";
    } else {
      label = "Fortress";
      level = "fortress";
    }

    return { label, level, adjusted };
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) return "Instantly";
    if (seconds < 1) return "Less than a second";

    const minute = 60;
    const hour = minute * 60;
    const day = hour * 24;
    const year = day * 365.25;

    if (seconds < minute) return `${Math.round(seconds)} seconds`;
    if (seconds < hour) return `${Math.round(seconds / minute)} minutes`;
    if (seconds < day) return `${Math.round(seconds / hour)} hours`;
    if (seconds < year) return `${Math.round(seconds / day)} days`;
    if (seconds < year * 1000) {
      const years = seconds / year;
      return years < 100 ? `${Math.round(years)} years` : `${years.toExponential(1)} years`;
    }

    const years = seconds / year;
    const logYears = Math.log10(years);

    if (logYears < 6) return `${Math.round(years).toLocaleString()} years`;
    return `~10^${Math.floor(logYears)} years`;
  }

  function analyze(result) {
    const warnings = getWarnings(result.password);
    const strength = getStrength(result.entropy, warnings);

    // Illustrative offline attack rate: 10 billion guesses/second.
    // Assumes average search time is half the keyspace.
    // This is a model, not a prediction of a specific attack.
    const guessesPerSecond = 1e10;
    const entropySeconds = result.entropy > 1023
      ? Infinity
      : Math.pow(2, result.entropy) / (2 * guessesPerSecond);

    const crackTime = formatDuration(entropySeconds);
    const displayPercent = Math.min(100, (strength.adjusted / 100) * 100);

    $("#strengthLabel").textContent = strength.label.toUpperCase();
    $("#entropyLabel").textContent = `${result.entropy.toFixed(1)} BITS`;
    $("#strengthFill").style.width = `${displayPercent}%`;
    $("#strengthProgress").setAttribute("aria-valuenow", String(Math.round(displayPercent)));
    $("#strengthProgress").setAttribute(
      "aria-valuetext",
      `${strength.label}, estimated entropy ${result.entropy.toFixed(1)} bits`
    );
    $("#ingotWrap").dataset.strength = strength.level;
    $("#ingotCaption").textContent = {
      weak: "CRITICAL WEAKNESS",
      fair: "REINFORCE YOUR DEFENSE",
      strong: "DEFENSES ENGAGED",
      fortress: "MAXIMUM DEFENSE"
    }[strength.level];

    $("#crackTime").textContent = crackTime;
    $("#entropyDetail").textContent = `${result.entropy.toFixed(1)} bits`;
    $("#lengthDetail").textContent = `${result.length} characters`;

    let variety;
    if (result.method === "fortress") {
      variety = `${result.alphabetSize} possible characters`;
    } else if (result.method === "memory") {
      variety = `${new Set(PASSWORD_WORDS).size.toLocaleString()} word choices`;
    } else {
      variety = `${ONSETS.length * VOWELS.length * CODAS.length} syllable choices`;
    }
    $("#varietyDetail").textContent = variety;

    let explanation = `Estimated entropy is ${result.entropy.toFixed(1)} bits. `;
    explanation += `After pattern warnings, the app classifies this password as ${strength.label.toLowerCase()}. `;

    if (result.method === "fortress") {
      explanation += `The estimate uses the configured character alphabet and length. `;
    } else if (result.method === "memory") {
      explanation += `The estimate uses the number of possible words and optional extras, not simply the final character count. `;
    } else {
      explanation += `The estimate uses the syllable-building choices and optional extras. `;
    }

    if (warnings.some((w) => /common|substitution|keyboard/i.test(w))) {
      explanation += "Predictable patterns can make a password easier to guess than raw entropy suggests. ";
    }
    explanation += "Crack-time figures assume a theoretical offline attacker and do not account for every attack strategy.";

    $("#whyText").textContent = explanation;

    const warningList = $("#warningList");
    warningList.replaceChildren();

    warnings.forEach((warning) => {
      const item = document.createElement("div");
      item.className = "warning-item";
      if (warning.startsWith("No obvious")) item.classList.add("info-warning");
      item.textContent = warning;
      warningList.appendChild(item);
    });
  }

  function renderHistory() {
    const list = $("#historyList");
    list.replaceChildren();

    if (history.length === 0) {
      const empty = document.createElement("li");
      empty.className = "history-empty";
      empty.textContent = "Your forged passwords will appear here.";
      list.appendChild(empty);
      return;
    }

    history.forEach((password, index) => {
      const li = document.createElement("li");
      const value = document.createElement("span");
      value.className = "history-password";
      value.textContent = password;
      value.title = `Generated password ${index + 1}`;

      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "history-copy";
      copy.textContent = "Copy";
      copy.setAttribute("aria-label", `Copy history password ${index + 1}`);
      copy.addEventListener("click", () => copyPassword(password));

      li.append(value, copy);
      list.appendChild(li);
    });
  }

  async function copyPassword(password) {
    if (!password) return;

    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      $("#copyStatus").textContent =
        "Clipboard access unavailable. Select and copy the password manually.";
      return;
    }

    try {
      await navigator.clipboard.writeText(password);
      $("#copyStatus").textContent =
        "Copied — clipboard will clear in 15 seconds, if permitted.";

      if (clipboardTimer) clearTimeout(clipboardTimer);

      clipboardTimer = setTimeout(async () => {
        try {
          // Best effort only: the browser may block this delayed clipboard write.
          await navigator.clipboard.writeText("");
          $("#copyStatus").textContent = "Clipboard clear requested.";
        } catch {
          $("#copyStatus").textContent =
            "Clipboard could not be cleared automatically. Clear it manually if needed.";
        }
        clipboardTimer = null;
      }, 15000);
    } catch {
      $("#copyStatus").textContent =
        "Copy was blocked by the browser. Select the password and copy it manually.";
    }
  }

  function setMode(mode) {
    currentMode = mode;

    const tabs = $$(".mode-tab");
    tabs.forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });

    $("#fortressSettings").hidden = mode !== "fortress";
    $("#memorySettings").hidden = mode !== "memory";
    $("#humanSettings").hidden = mode !== "human";

    $("#settingsHeading").textContent = {
      fortress: "Fortress configuration",
      memory: "Memory configuration",
      human: "Human-readable configuration"
    }[mode];

    $("#mode-settings").setAttribute("aria-labelledby", {
      fortress: "tab-fortress",
      memory: "tab-memory",
      human: "tab-human"
    }[mode]);

    generatePassword();
  }

  function toggleVisibility() {
    if (!currentPassword) return;
    isHidden = !isHidden;
    $("#visibilityToggle").setAttribute("aria-pressed", String(isHidden));
    $("#visibilityToggle").setAttribute(
      "aria-label",
      isHidden ? "Show password" : "Hide password"
    );
    $("#visibilityToggle").textContent = isHidden ? "◎" : "◉";
    renderPassword();
  }

  function toggleTheme() {
    const light = document.body.classList.toggle("light-theme");
    $("#themeToggle").textContent = light ? "☾" : "☼";
    $("#themeToggle").setAttribute(
      "aria-label",
      light ? "Switch to dark theme" : "Switch to light theme"
    );
    document.querySelector('meta[name="theme-color"]')
      .setAttribute("content", light ? "#edf2f8" : "#0b0e14");
  }

  function bindEvents() {
    $$(".mode-tab").forEach((tab, index, tabs) => {
      tab.addEventListener("click", () => setMode(tab.dataset.mode));

      tab.addEventListener("keydown", (event) => {
        let nextIndex = index;
        if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
        else if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === "Home") nextIndex = 0;
        else if (event.key === "End") nextIndex = tabs.length - 1;
        else return;

        event.preventDefault();
        tabs[nextIndex].focus();
        setMode(tabs[nextIndex].dataset.mode);
      });
    });

    // Rebuild instantly when any active or inactive setting changes.
    $$("#fortressSettings input, #memorySettings input, #memorySettings select, #humanSettings input")
    .forEach((input) => {
    input.addEventListener("input", updateSettingLabels);
    input.addEventListener("change", generatePassword);
  });

    $("#generateButton").addEventListener("click", generatePassword);
    $("#visibilityToggle").addEventListener("click", toggleVisibility);
    $("#copyButton").addEventListener("click", () => copyPassword(currentPassword));
    $("#themeToggle").addEventListener("click", toggleTheme);

    $("#clearHistory").addEventListener("click", () => {
      history = [];
      renderHistory();
    });

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        generatePassword();
      }
    });
  }

  function updateSettingLabels() {
    $("#lengthValue").textContent = $("#lengthRange").value;
    $("#wordCountValue").textContent = $("#wordCount").value;
    $("#syllableCountValue").textContent = $("#syllableCount").value;
  }

  function init() {
    bindEvents();
    updateSettingLabels();
    renderHistory();
    generatePassword();
  }

  // Expose only a minimal debug-free interface; no passwords are persisted.
  init();
})();
