# Chrome Web Store submission: copy/paste reference

Not part of the extension package. Excluded from the upload zip.

**Published 2026-08-03**, item ID `lmjmpdlnhndlndeiofcfimainondjbcg`,
listing: https://chromewebstore.google.com/detail/threat-intel-search/lmjmpdlnhndlndeiofcfimainondjbcg
Keep the copy below in sync with the live listing when publishing an update.

## Store listing

**Item name**
```
Threat Intel Search
```

**Summary** (132 char max)
```
Right-click an IP, domain, or hash for a compact OSINT panel: one-click lookups, plus an optional score from your own API keys.
```

**Description**
```
🔎 Threat Intel Search is for analysts who are tired of opening five tabs to check one indicator.

Select an IP address, domain, or file hash on any page, right-click, and pick "Analyze" (auto-detects the type) for the lookup panel, or "I (IP Address)", "D (Domain)", or "H (Hash)" to open the standard reputation lookups straight in new tabs. The selection is cleaned up first: quotes and URL schemes are stripped, URLs are reduced to their host, and defanged indicators like evil[.]com or hxxp:// are refanged.

🧭 Analyze opens a small panel with:
- 📋 the indicator, copyable, with its type and a context line (network owner, country, file type) once lookups answer
- 🎯 a score circle
- 🔗 one button per source, each opening that single lookup: reputation, abuse reports, geolocation, internet scan data, certificate transparency, WHOIS, and malware sandboxes, depending on the indicator type
- 🚀 an "Open all" button that opens every source for the type at once

📊 Optional score: add your own free API keys for up to three supported reputation services in settings and the circle fills in (likely clean / suspicious / malicious) with a confidence level and one row per service showing what it found, why, and how hard it pushed the score. Evidence is combined so a strong detection isn't diluted by a service that has never seen the indicator, allowlisted and very popular domains count toward clean, and a single weak signal is capped at "suspicious". It is a convenience heuristic, not a verdict. Without keys everything else works exactly the same.

🧾 Select a whole log line and every indicator in it is one click away.

⌨️ Keyboard shortcuts: 1-9 open a source, O opens them all, C copies the indicator, D copies it defanged, R refreshes the score.

🛡️ Built for SOC analysts, incident responders, and threat hunters triaging alerts.

🔒 Privacy: the extension collects nothing and has no servers, analytics, or telemetry. Keys and a 30-minute result cache stay in local extension storage. Indicators are only sent to the services you chose, only when you look one up, straight from your browser.

💻 Open source (MIT), with the full list of supported sources in the README: https://github.com/canmenzo/ThreatIntelSearch
🦊 Also available for Firefox.
```

**Category**: Developer Tools (alternate: Workflow & Planning)
**Language**: English

## Privacy tab

**Single purpose**
```
Looks up a user-selected IP address, domain, or file hash on threat intelligence services, via a right-click menu and a small results panel.
```

**Permission justification: contextMenus**
```
Adds the "Analyze", "I (IP Address)", "D (Domain)", and "H (Hash)" entries to the right-click menu. This is how every lookup starts; without it there is no way to trigger one.
```

**Permission justification: storage**
```
Stores the user's optional API keys and settings, and caches lookup results for 30 minutes so repeat lookups don't use up the user's free API quota. Everything stays in local extension storage.
```

**Host permissions** (optional, not granted at install)
```
www.virustotal.com, api.abuseipdb.com, and otx.alienvault.com are optional host permissions. They are requested only when the user saves an API key for that vendor, and removed if the key is removed. They are used only to call that vendor's API for the indicator the user just looked up.
```

**Remote code**: No, I am not using remote code.

**Data usage**: check **Website content**. The only item is the text the user
selected, which is sent to the vendor APIs the user configured, only when they
open a lookup. It is never sent to the developer.

Then check all three certification boxes (no sale of data, no unrelated use, no
creditworthiness use).

**Privacy policy URL**
```
https://github.com/canmenzo/ThreatIntelSearch/blob/main/PRIVACY.md
```

## Distribution

- Visibility: Public
- Regions: All
- Not a paid item, no in-app purchases.

## Assets

- Icon: `chrome/icons/icon128.png` (128x128)
- Screenshots (1280x800, also usable on AMO), upload in this order:
  1. `chrome/store/screenshot-1280x800.png`: the right-click menu with Analyze and I / D / H (drawn to match the browser menu, not a capture).
  2. `chrome/store/screenshot-2-1280x800.png`: the Analyze panel (real extension UI, sample vendor data).
