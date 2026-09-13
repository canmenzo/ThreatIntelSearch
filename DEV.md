# Development

No build step. Plain HTML, CSS, and JavaScript.

## Layout

| Path | Build |
|---|---|
| repo root | Firefox / LibreWolf, Manifest V2 |
| `chrome/` | Chrome / Edge / Brave / Opera, Manifest V3 |

Shared files exist in both places and must stay **byte-identical**:
`common.js`, `icons.js`, `ui.css`, `panel.html`, `panel.js`, `options.html`, `options.js`.
Edit one, copy it to the other. Check with:

```sh
for f in common.js icons.js ui.css panel.html panel.js options.html options.js; do cmp -s "$f" "chrome/$f" || echo "out of sync: $f"; done
```

```powershell
'common.js','icons.js','ui.css','panel.html','panel.js','options.html','options.js' | % { if ((Get-FileHash $_).Hash -ne (Get-FileHash "chrome\$_").Hash) { "out of sync: $_" } }
```

Per build: `manifest.json` and `background.js`. The two `background.js` files differ
only in how `common.js` is loaded (`importScripts` vs the manifest's script list) and
when menus are registered (`onInstalled`/`onStartup` vs top level).

## Load unpacked

**Chrome / Edge / Brave / Opera**
1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Enable **Developer mode**.
3. **Load unpacked** and pick the `chrome/` folder.
4. After editing, hit the reload icon on the extension card.
   Service worker logs: **Inspect views: service worker** on the card.

**Firefox / LibreWolf**
1. Open `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on** and pick `manifest.json` at the repo root.
3. After editing, click **Reload**. Background logs: **Inspect**.
   Temporary add-ons are removed when the browser closes.

## Manual test

1. Select `8.8.8.8` on any page, right-click, **Threat Intel Search > I (IP Address)**.
   A small panel window opens: IP badge, gray circle with a dash, "not enough data",
   7 source buttons, **Open all · IP** highlighted, the other two dimmed.
2. Click one source: one tab opens in the original window. Click **Open all · IP**: 7 tabs.
3. Select `hxxps://evil[.]com/login`, right-click, **I (IP Address)**: the panel
   reuses its window, shows `evil.com`, and warns it looks like a domain. Click
   **Switch to DOMAIN**.
4. Select a SHA256 or MD5, use the top **Threat Intel Search** entry: HASH is
   auto-selected and the algorithm shows next to the badge.
5. Gear icon > settings. Paste a dummy key (e.g. `test`) into VirusTotal and click
   **Save and test keys**. Accept the site access prompt. The status should read
   **key rejected**. Look up an IP again: the breakdown says `VT key rejected`, the
   circle stays gray, links still work.
6. With a real free key: the circle fills in, a confidence line appears, and an
   evidence row reads like `VirusTotal 0/94 engines`. A second lookup of the same
   indicator within 30 minutes says "cached N min ago"; **refresh** re-queries.
   Press `1` to open the first source, `D` to copy the indicator defanged.
7. Untick **Fetch a score when I open a lookup**: no API requests at all.

## Package

Uses Windows' built-in `tar.exe` (bsdtar), which writes forward-slash zip paths.
PowerShell 5.1's `Compress-Archive` writes backslashes, which the stores can reject.

```powershell
# Firefox / AMO
tar.exe --format zip -cf threat_intel_search-2.0.0.xpi manifest.json background.js common.js icons.js ui.css panel.html panel.js options.html options.js

# Chrome Web Store (leaves out chrome/store/)
tar.exe --format zip -cf threat_intel_search-chrome-2.0.0.zip -C chrome manifest.json background.js common.js icons.js ui.css panel.html panel.js options.html options.js icons
```

`npx web-ext lint --source-dir . --ignore-files "chrome/**" "*.md" LICENSE` runs Mozilla's
validator on the Firefox build.
