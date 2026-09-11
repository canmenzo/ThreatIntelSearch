# Privacy Policy: Threat Intel Search

Last updated: 2026-09-10

Threat Intel Search does **not** collect, store on any server, transmit to its
author, or sell any user data. It has no servers, no analytics, and no telemetry.

## What the extension touches

- **The text you select**, at the moment you pick one of its right-click menu
  entries. It does not read page content otherwise.
- **API keys you choose to enter** in its settings (optional).

## What stays in your browser

Stored in the browser's local extension storage, never sent to the author:

- Your optional VirusTotal, AbuseIPDB, and AlienVault OTX API keys, and whether
  each vendor last accepted or rejected them.
- Your "fetch a score" setting.
- Recent score results (the indicator and a one-line summary per vendor) for 30
  minutes, so repeat lookups don't use up your API quota. The settings page has
  a button to clear them, and uninstalling the extension removes everything.

## What leaves your browser, and only when you ask

- **Link buttons** open the third-party site you clicked (VirusTotal, AlienVault
  OTX, AbuseIPDB, MaxMind, GreyNoise, Shodan InternetDB, urlscan.io,
  SecurityTrails, Whois.com, crt.sh, MalwareBazaar, or Hybrid Analysis) in a new
  tab with the indicator in the URL, exactly as if you had typed it into that
  site yourself.
- **Scores**, only if you have added API keys: when you open a lookup, the
  indicator and the matching key are sent directly from your browser to the API
  of each vendor you configured (VirusTotal, AbuseIPDB, AlienVault OTX). Nothing
  is sent to vendors you have not added a key for. These requests carry no
  cookies. You can turn scoring off in settings while keeping your keys.

Each vendor's handling of those requests is governed by its own privacy policy.

## Permissions

- `contextMenus`: adds the right-click entries.
- `storage`: keeps the settings, keys, and short-lived cache described above.
- `tabs` (Firefox build only, unchanged from earlier versions): opens lookups in
  new tabs.
- Optional access to `www.virustotal.com`, `api.abuseipdb.com`, and
  `otx.alienvault.com`: requested only when you save a key for that vendor, and
  released again if you remove the key. Used only to call those vendors' APIs.

The score is a convenience heuristic, not a verdict.

Questions or concerns: https://github.com/canmenzo/ThreatIntelSearch/issues
