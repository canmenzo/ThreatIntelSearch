# Chrome Web Store submission — copy/paste reference

Not part of the extension package. Excluded from the upload zip.

**Published 2026-08-03** — item ID `lmjmpdlnhndlndeiofcfimainondjbcg`,
listing: https://chromewebstore.google.com/detail/threat-intel-search/lmjmpdlnhndlndeiofcfimainondjbcg
Keep the copy below in sync with the live listing when publishing an update.

## Store listing

**Item name**
```
Threat Intel Search
```

**Summary** (132 char max)
```
Right-click any selected IP, domain, or file hash to look it up across VirusTotal, AbuseIPDB, AlienVault OTX, and MaxMind.
```

**Description**
```
Threat Intel Search adds a right-click menu for analysts who are tired of opening five tabs to check one indicator.

Select an IP address, domain, or file hash on any page, right-click, and pick one of three entries:

- I (IP Address) — VirusTotal, AlienVault OTX, AbuseIPDB, MaxMind
- D (Domain) — VirusTotal, AlienVault OTX, AbuseIPDB
- H (Hash) — VirusTotal

Each lookup opens in its own tab, so you get the full picture in one action.

Built for SOC analysts, incident responders, and threat hunters triaging alerts, but useful to anyone who wants a fast second opinion on a suspicious link.

No accounts. No API keys. No configuration.

Privacy: this extension collects nothing. It has no servers, no analytics, and no telemetry. It does not read page content — the only text it ever touches is what you selected, at the moment you click a menu item, and it is used solely to build the URL it opens. The single permission it requests, contextMenus, is what draws the right-click entries.

Open source (MIT): https://github.com/canmenzo/ThreatIntelSearch
Also available for Firefox.
```

**Category**: Developer Tools (alternate: Workflow & Planning)
**Language**: English

## Privacy tab

**Single purpose**
```
Provides a right-click context menu that opens threat intelligence lookups for text the user has selected.
```

**Permission justification — contextMenus**
```
Required to add the "IP Address", "Domain", and "Hash" entries to the browser's right-click menu. This is the extension's entire user interface; without it there is no way to trigger a lookup.
```

**Host permissions**: none requested.

**Remote code**: No, I am not using remote code.

**Data usage**: check nothing. The extension collects no user data.

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
- Screenshot: 1280x800 or 640x400 PNG, at least one required. Use a real capture
  of the right-click menu open over a selected indicator — Google rejects mockups
  and stock imagery.
