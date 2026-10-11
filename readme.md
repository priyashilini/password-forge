
# Password Forge

A privacy-first password generator and strength analyzer built with HTML, CSS, vanilla JavaScript, and the Web Crypto API.

## Overview

Password Forge turns password creation into an interactive digital forge. Generate random passwords, memorable passphrases, or pronounceable credentials, then inspect their estimated entropy and potential weaknesses.

Everything runs locally in your browser. There are no accounts, backend services, analytics, external APIs, or third-party JavaScript libraries.

## Features

### Three generation modes

- **Fortress Mode:** Generate random passwords from 8–64 characters. Select lowercase, uppercase, numbers, and symbols. Exclude ambiguous characters or provide a custom character set.
- **Memory Mode:** Create passphrases from 3–8 locally bundled English words. Configure separators, capitalization, numbers, and symbols.
- **Human-readable Mode:** Generate pronounceable passwords from randomly selected syllables, with optional numbers and symbols.

### Strength analysis

- Estimated entropy in bits.
- Weak, Fair, Strong, and Fortress classifications.
- An animated strength meter and changing forge ingot.
- Illustrative offline crack-time estimate.
- Warnings for common password words, repeated characters, sequential patterns, and predictable substitutions.
- An explanation panel describing the rating.

### User experience

- Responsive desktop, tablet, and mobile layouts.
- Dark and light themes.
- Show/hide password control.
- One-click clipboard copying.
- Best-effort clipboard clearing after 15 seconds.
- Regenerate shortcut: `Ctrl + Enter` or `Cmd + Enter`.
- Last-five-password history held in JavaScript memory.
- Keyboard-accessible mode selection and visible focus indicators.

## Requirements

- A modern browser supporting the Web Crypto API.
- JavaScript enabled.
- VS Code is recommended for editing but is not required to run the project.

No installation, Node.js, npm, or build process is necessary.

## Getting started in Visual Studio Code

1. Create a folder named `password-forge`.
2. Open VS Code.
3. Select **File → Open Folder** and choose `password-forge`.
4. Create these five files in the folder:
   - `index.html`
   - `style.css`
   - `script.js`
   - `words.js`
   - `README.md`
5. Paste the corresponding code into each file.
6. Save all files.
7. Open `index.html` in a modern browser.

### Run with Live Server

1. Open the Extensions view in VS Code.
2. Install the **Live Server** extension if you want a local development server.
3. Right-click `index.html`.
4. Select **Open with Live Server**.
5. The application should open in your default browser.

Live Server is optional. Directly opening `index.html` should also work in modern browsers with Web Crypto support. If clipboard access is unavailable through a `file://` URL, use Live Server.

## Project structure

```text
password-forge/
├── index.html    # Semantic page structure and controls
├── style.css     # Responsive layout, themes, animations
├── script.js     # Generation, entropy estimates, UI logic
├── words.js      # Local passphrase vocabulary
└── README.md     # Project documentation
```

## Security notes

- Random values are generated with `crypto.getRandomValues()`.
- Random character selection uses rejection sampling to avoid modulo bias.
- Passwords are never sent to a server.
- Password history is stored in JavaScript memory only.
- No passwords are written to localStorage, sessionStorage, cookies, or files.
- No analytics, advertisements, external APIs, or runtime dependencies are included.
- Clipboard clearing is best-effort. Browser permissions or platform behavior can prevent the clipboard from being cleared.
- The crack-time display is a theoretical estimate based on an assumed attack rate, not a promise of security.
- Entropy estimates depend on the generation model. Human-generated passwords, reused credentials, compromised devices, and real-world attack strategies may behave differently.
- This tool is educational and should not replace a professional password manager or an organization's security policy.

## Portfolio extensions

Ideas for future versions:

- Unit tests for password-generation constraints.
- A stronger password-pattern analysis engine.
- Exportable security documentation without exporting passwords.
- A dedicated accessibility audit.
- A passphrase vocabulary audit for duplicate entries and word-frequency bias.

## License

Choose a license before publishing this project publicly. For example, MIT License.
