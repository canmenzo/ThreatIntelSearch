// Mirrors chrome/background.js. The two differ only in how common.js is loaded and when the
// menus are registered (MV2 event page here, MV3 service worker there). Keep the rest identical.

const MENU = [
  { id: "auto", title: "🔎 Threat Intel Search" },
  { id: "sep", type: "separator" },
  { id: "ip", title: "🔎 I (IP Address)" },
  { id: "domain", title: "🔎 D (Domain)" },
  { id: "hash", title: "🔎 H (Hash)" }
];
const PANEL_WIDTH = 380;
const PANEL_HEIGHT = 640;

function createMenus() {
  api.contextMenus.removeAll(() => {
    for (const item of MENU) api.contextMenus.create({ ...item, contexts: ["selection"] });
  });
}

async function openPanel(query, windowId) {
  // Reuse the open panel if there is one; it answers with its window id.
  const open = await api.runtime.sendMessage({ showPanel: query }).catch(() => null);
  if (open) {
    if (open.windowId != null) api.windows.update(open.windowId, { focused: true });
    return;
  }
  const opts = { url: api.runtime.getURL(`panel.html?${query}`), type: "popup", width: PANEL_WIDTH, height: PANEL_HEIGHT };
  const w = windowId != null && (await api.windows.get(windowId).catch(() => null));
  if (w) {
    opts.left = w.left + w.width - PANEL_WIDTH - 24;
    opts.top = w.top + 80;
  }
  api.windows.create(opts);
}

api.contextMenus.onClicked.addListener((info, tab) => {
  const type = TYPES.includes(info.menuItemId) ? info.menuItemId : "";
  const raw = (info.selectionText || "").trim();
  const query = new URLSearchParams({ ioc: normalize(raw, type), type, raw: raw.slice(0, 300), win: tab?.windowId ?? "" });
  openPanel(query.toString(), tab?.windowId);
});

createMenus();
