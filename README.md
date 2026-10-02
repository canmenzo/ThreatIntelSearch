# 🔎 Threat Intel Search

Right-click an IP, domain, or file hash and get a compact lookup panel: every OSINT source one click away, plus an optional threat score from your own API keys. Built for SOC analysts.

[![Firefox Add-ons](https://img.shields.io/amo/v/threat-intel-search?label=Firefox%20Add-ons&color=blue)](https://addons.mozilla.org/en-US/firefox/addon/threat-intel-search/)
[![Chrome Web Store](https://img.shields.io/chrome-web-store/v/lmjmpdlnhndlndeiofcfimainondjbcg?label=Chrome%20Web%20Store&color=blue)](https://chromewebstore.google.com/detail/threat-intel-search/lmjmpdlnhndlndeiofcfimainondjbcg)
[![Source version](https://img.shields.io/github/manifest-json/v/canmenzo/ThreatIntelSearch?label=source&color=blueviolet)](manifest.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

### ✨ What's new in v2

- 🪟 **Lookup panel** instead of a pile of tabs, with an auto-detect **Threat Intel Search** menu entry
- 🧹 **Input cleanup**: strips quotes and URL schemes, reduces URLs to their host, defangs `evil[.]com` / `hxxp://`, and offers a one-click type switch if you picked wrong
- 🌐 **More sources**: GreyNoise, Shodan InternetDB, urlscan.io, SecurityTrails, Whois, crt.sh, MalwareBazaar, Hybrid Analysis
- 🎯 **Optional score** from your own VirusTotal / AbuseIPDB / AlienVault OTX keys, using an evidence-based (naive Bayes) model with a confidence line and per-vendor evidence rows
- ⌨️ **Shortcuts**: `1`-`9` open a source, `C` copies, `D` copies defanged, `Esc` closes

---

### 🔥 Features

- 🖱️ Right-click menu: **Threat Intel Search** (auto-detect) or force **I** (IP) / **D** (Domain) / **H** (Hash)
- 📋 Panel shows the indicator with a type badge, a score circle, one numbered button per source, and **Open all** for the type
- 🛑 Flags private, reserved, and documentation IPs so you don't waste lookups on them
- 🔗 Sources (links only, no account needed):

  | Type | Sources |
  |---|---|
  | 🌍 IP | VirusTotal, AlienVault OTX, AbuseIPDB, MaxMind, GreyNoise, Shodan InternetDB, urlscan.io |
  | 🏷️ Domain | VirusTotal, AlienVault OTX, AbuseIPDB, urlscan.io, SecurityTrails, Whois, crt.sh |
  | 🧬 Hash (MD5, SHA1, SHA256) | VirusTotal, AlienVault OTX, MalwareBazaar, Hybrid Analysis |

- 🚫 No data collection, no tracking, no servers

---

### 🎯 The score (optional)

Add free API keys in settings (gear icon in the panel). When you open a lookup, the circle fills in: **likely clean** (0-24), **suspicious** (25-59), or **malicious** (60-100), with a **confidence** line (high / medium / low / sources disagree). One row per vendor shows what it found; click a row to open that vendor's page.

#### How the score works

Each vendor's answer becomes **evidence** (log-odds): positive pushes toward malicious, negative toward clean. Evidence is added to a prior (things analysts right-click are more often bad than random traffic) and mapped to 0-100. A strong detection from one vendor isn't averaged away by another that has simply never seen the indicator, and weak signals that agree add up.

| Source | Covers | Toward malicious | Toward clean |
|---|---|---|---|
| VirusTotal | IP, domain, hash | engines flagging it (suspicious counts half) on a log curve; files need more hits than IPs/domains; bad community reputation | zero detections; good reputation; domain in a top 10k / 100k list |
| AbuseIPDB | IP | abuse confidence score (halved with a single reporter) | allowlisted; reports with 0% confidence |
| AlienVault OTX | IP, domain, hash | pulse count on a log curve plus named malware families / adversaries, capped | allowlisted / known false positive |

- "Not found", "0 reports" and "0 pulses" are absence of evidence, not proof of clean.
- If only one vendor had evidence and it was weak, the score is **capped at 59**, so one weak signal never reads as "malicious". Strong single-vendor evidence (e.g. 60/72 VT engines on a file) isn't capped.
- No keys or no answers means a gray circle and **not enough data**. The links work either way.
- Results are cached locally for 30 minutes (**refresh** bypasses it). Rejected keys (401/403) are flagged in settings; rate limits (429) show in the panel.

The score is a convenience heuristic, not a verdict.

---

### 📦 Installation

**Official stores** (recommended, auto-updates):

| Browser | Store |
|---|---|
| 🦊 Firefox, LibreWolf | [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/threat-intel-search/) |
| 🌐 Chrome, Edge, Brave, Opera | [Chrome Web Store](https://chromewebstore.google.com/detail/threat-intel-search/lmjmpdlnhndlndeiofcfimainondjbcg) |

**Manual** (no auto-updates): grab the build from the [latest release](https://github.com/canmenzo/ThreatIntelSearch/releases/latest).

- **Firefox**: drag the `.xpi` into `about:addons`.
- **Chromium**: unzip the `-chrome` `.zip`, open `chrome://extensions`, enable **Developer mode**, **Load unpacked**.

**From source**: the repo root is the Firefox build (MV2), `chrome/` is the Chrome build (MV3). See [DEV.md](DEV.md).

---

### 🛡️ Privacy

Nothing is collected by the extension or its author. Link buttons open the vendor's site as if you typed the indicator yourself. If you add API keys, the indicator and key go straight from your browser to that vendor, only for vendors you configured and only when you open a lookup. Keys and cached results stay in local extension storage. Full policy: [PRIVACY.md](PRIVACY.md).

---

### 📄 License & credits

- MIT. Do whatever you want, just don't be evil.
- UI icons: [Iconly](https://iconly.pro/) (Light set) by Piqo Design, via [react-iconly](https://github.com/jrgarciadev/react-iconly) (MIT).
- Made by someone who got tired of clicking through 5 tabs to check an IP. Contributions welcome.
