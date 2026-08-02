# 🔎 Threat Intel Search

A lightweight browser extension to instantly search selected IP addresses, domains, or hashes across popular threat intelligence platforms — all from the right-click menu.

---

### 🔥 Features

- 🔍 One-click context menu search for:
  - IP addresses
  - Domains
  - File hashes (MD5, SHA1, SHA256)
- 🚀 Instantly opens selected item in:
  - VirusTotal
  - AbuseIPDB
  - AlienVault OTX
  - MaxMind (IP only)
- ⚡ No data collection. No tracking. No nonsense.

---

### 📦 Installation

#### Option 1 — Official stores (recommended, auto-updates)

| Browser | Store |
|---|---|
| Firefox, LibreWolf | [![AMO](https://img.shields.io/amo/v/threat-intel-search?label=Firefox%20Add-ons&color=blue)](https://addons.mozilla.org/en-US/firefox/addon/threat-intel-search/) |
| Chrome, Edge, Brave | ![CWS](https://img.shields.io/badge/Chrome%20Web%20Store-pending%20review-lightgrey) |

#### Option 2 — Manual install

Grab the file for your browser from the [latest release](https://github.com/canmenzo/ThreatIntelSearch/releases/latest):

- **Firefox** — download `threat_intel_search-1.1.xpi` and drag it into `about:addons`.
- **Chrome / Edge / Brave / Opera** — download and unzip `threat_intel_search-chrome-1.1.zip`, then open `chrome://extensions`, enable **Developer mode**, and click **Load unpacked** on the unzipped folder.

You can also load straight from a clone: the Firefox build is the repo root (Manifest V2), the Chrome build is `chrome/` (Manifest V3).

---

### 🛡️ Privacy

This extension does **not** collect, store, or transmit any data. All functionality is local and user-triggered. Full policy: [PRIVACY.md](PRIVACY.md).

---

### 📄 License & Author
- MIT — do whatever you want, just don’t be evil.
- Created by someone who got tired of clicking through 5 tabs just to check an IP. Contributions welcome.
