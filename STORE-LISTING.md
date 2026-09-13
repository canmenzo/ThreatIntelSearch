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
Threat Intel Search is for analysts who are tired of opening five tabs to check one indicator.

Select an IP address, domain, or file hash on any page, right-click, and pick "Threat Intel Search" (auto-detects the type) or force I (IP Address), D (Domain), or H (Hash). The selection is cleaned up first: quotes and URL schemes are stripped, URLs are reduced to their host, and defanged indicators like evil[.]com or hxxp:// are refanged.

A small panel opens with:
- the indicator, copyable, with its type
- a score circle
- one button per source, each opening that single lookup
- "Open all" buttons that open every source for the type at once

Sources:
- IP: VirusTotal, AlienVault OTX, AbuseIPDB, MaxMind, GreyNoise, Shodan InternetDB, urlscan.io
- Domain: VirusTotal, AlienVault OTX, AbuseIPDB, urlscan.io, SecurityTrails, Whois, crt.sh
- Hash: VirusTotal, AlienVault OTX, MalwareBazaar, Hybrid Analysis

Optional score: add your own free VirusTotal, AbuseIPDB, or AlienVault OTX API keys in settings and the circle fills in (likely clean / suspicious / malicious) with a confidence level and one row per vendor showing what it found. Evidence from each vendor is combined so a strong detection isn't diluted by a vendor that has never seen the indicator, allowlisted and very popular domains count toward clean, and a single weak signal is capped at "suspicious". It is a convenience heuristic, not a verdict. Without keys everything else works exactly the same.

Keyboard shortcuts: 1-9 open a source, C copies the indicator, D copies it defanged.

Built for SOC analysts, incident responders, and threat hunters triaging alerts.

Privacy: the extension collects nothing and has no servers, analytics, or telemetry. Keys and a 30-minute result cache stay in local extension storage. Indicators are only sent to the vendors you chose, only when you look one up, straight from your browser.

Open source (MIT): https://github.com/canmenzo/ThreatIntelSearch
Also available for Firefox.
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
Adds the "Threat Intel Search", "IP Address", "Domain", and "Hash" entries to the right-click menu. This is how every lookup starts; without it there is no way to trigger one.
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
open a lookup. It is never sent to the developer. (v1 sent nothing itself and
checked nothing; v2's optional API calls are why this changes.)

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
- Screenshot: 1280x800 or 640x400 PNG, at least one required. The current
  `chrome/store/screenshot-1280x800.png` shows the v1 right-click menu; replace
  it with a real capture of the v2 panel open next to a selected indicator.
  Google rejects mockups and stock imagery.
