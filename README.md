# 🔎 Threat Intel Search

A lightweight browser extension for SOC analysts: right-click a selected IP address, domain, or file hash and get a compact lookup panel with every OSINT source one click away, plus an optional score from your own API keys.

[![Firefox Add-ons](https://img.shields.io/amo/v/threat-intel-search?label=Firefox%20Add-ons&color=blue)](https://addons.mozilla.org/en-US/firefox/addon/threat-intel-search/)
[![Chrome Web Store](https://img.shields.io/chrome-web-store/v/lmjmpdlnhndlndeiofcfimainondjbcg?label=Chrome%20Web%20Store&color=blue)](https://chromewebstore.google.com/detail/threat-intel-search/lmjmpdlnhndlndeiofcfimainondjbcg)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

### 🔥 Features

- 🔍 Right-click menu with four entries:
  - **Threat Intel Search**: auto-detects IP, domain, or hash
  - **I (IP Address)**, **D (Domain)**, **H (Hash)**: force a type
- 🧹 Cleans the selection first: trims, strips quotes and URL schemes, reduces a URL to its host, and refangs `evil[.]com` / `hxxp://`. If you pick the wrong type, the panel says what the indicator looks like and offers a one-click switch.
- 🪟 A small dark panel instead of a pile of tabs:
  - the indicator, copyable, with an IP / DOMAIN / HASH badge
  - a score circle (gray until there's data)
  - one button per source, each opening that single lookup
  - **Open all · IP / Domain / Hash** to open every source for the type in one go
- 🌐 Sources (links only, no account needed):

  | Type | Sources |
  |---|---|
  | IP | VirusTotal, AlienVault OTX, AbuseIPDB, MaxMind, GreyNoise, Shodan InternetDB, urlscan.io |
  | Domain | VirusTotal, AlienVault OTX, AbuseIPDB, urlscan.io, SecurityTrails, Whois, crt.sh |
  | Hash (MD5, SHA1, SHA256) | VirusTotal, AlienVault OTX, MalwareBazaar, Hybrid Analysis |

- ⚡ No data collection. No tracking. No nonsense.

#### How the score works

Add free API keys in the extension's settings (gear icon in the panel) and the circle fills in when you open a lookup. Under it, one row per vendor shows what that vendor said, with a colored dot for which way it pushed; click a row to open that vendor's page.

Each vendor's answer becomes **evidence** (log-odds): positive pushes toward malicious, negative toward clean, near zero means it didn't say much. Evidence is added to a prior (things analysts right-click are more often bad than random traffic) and turned into 0-100. This is a naive Bayes model, so strong evidence from one vendor isn't averaged away by another vendor that has simply never seen the indicator, and weak signals that agree add up.

| Source | Covers | Pushes toward malicious | Pushes toward clean |
|---|---|---|---|
| VirusTotal | IP, domain, hash | number of engines flagging it (suspicious counts half), on a log curve; files need more hits than IPs/domains because 1-2 generic file detections are usually false positives; bad community reputation | zero detections; good community reputation; domain in a top 10k / 100k popularity list |
| AbuseIPDB | IP | abuse confidence score (halved when only one user reported it) | allowlisted by AbuseIPDB; reports with 0% confidence |
| AlienVault OTX | IP, domain, hash | pulse count on a log curve, plus named malware families or adversaries; capped, since pulses are community feeds of mixed quality | allowlisted / known false positive |

"Not found", "0 reports" and "0 pulses" are treated as absence of evidence, not proof of clean.

Labels: **likely clean** (0-24), **suspicious** (25-59), **malicious** (60-100). Under the label:

- **Confidence**: high (2+ vendors with a clear combined signal), medium, low (a single vendor), or **sources disagree** when one vendor clearly says bad and another clearly says clean.
- **Capped**: if only one vendor had evidence and it was weak (for example only OTX pulses, or 5 VT engines on a domain), the score is held at 59, so one weak signal can never read as "malicious". Strong single-vendor evidence, like 60/72 VT engines on a file, is not capped.

No keys, no answer, or only errors means a gray circle and **not enough data**; the links keep working either way.

The score is a convenience heuristic, not a verdict.

Results are cached locally for 30 minutes so repeat lookups don't burn free API quotas (**refresh** bypasses the cache). Rejected keys (401/403) are skipped and flagged in settings; rate limits (429) are shown in the panel.

#### Panel shortcuts

`1`-`9` open that source, `C` copies the indicator, `D` copies it defanged (`evil[.]com`), `Esc` closes the panel.

---

### 📦 Installation

#### Option 1: Official stores (recommended, auto-updates)

| Browser | Store |
|---|---|
| Firefox, LibreWolf | [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/threat-intel-search/) |
| Chrome, Edge, Brave, Opera | [Chrome Web Store](https://chromewebstore.google.com/detail/threat-intel-search/lmjmpdlnhndlndeiofcfimainondjbcg) |

#### Option 2: Manual install (no auto-updates)

Grab the file for your browser from the [latest release](https://github.com/canmenzo/ThreatIntelSearch/releases/latest):

- **Firefox**: download the `.xpi` and drag it into `about:addons`.
- **Chrome / Edge / Brave / Opera**: download and unzip the `-chrome` `.zip`, then open `chrome://extensions`, enable **Developer mode**, and click **Load unpacked** on the unzipped folder.

You can also load straight from a clone: the Firefox build is the repo root (Manifest V2), the Chrome build is `chrome/` (Manifest V3). See [DEV.md](DEV.md).

---

### 🛡️ Privacy

Nothing is collected by the extension or its author. There are no servers, analytics, or telemetry. Link buttons open the vendor's site exactly as if you typed the indicator there yourself. If you add API keys, the indicator and your key go straight from your browser to that vendor's API, only for the vendors you configured and only when you open a lookup. Keys and cached results stay in local extension storage. Full policy: [PRIVACY.md](PRIVACY.md).

---

### 📄 License & Author
- MIT. Do whatever you want, just don't be evil.
- UI icons: [Iconly](https://iconly.pro/) (Light set) by Piqo Design, via [react-iconly](https://github.com/jrgarciadev/react-iconly) (MIT).
- Created by someone who got tired of clicking through 5 tabs just to check an IP. Contributions welcome.
