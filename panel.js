// Shared file: identical copies live at the repo root (Firefox, MV2) and in chrome/ (Chrome, MV3). Edit both.

const params = new URLSearchParams(location.search);
const ioc = params.get("ioc") || "";
const raw = params.get("raw") || "";
const originWindow = params.get("win") ? Number(params.get("win")) : null;
const detected = detect(ioc);
const ARTICLE = { ip: "an IP address", domain: "a domain", hash: "a file hash" };
const CIRC = 2 * Math.PI * 42;
const $ = (id) => document.getElementById(id);

let current = TYPES.includes(params.get("type")) ? params.get("type") : detected;
let myWindowId = null;

// One panel at a time: the background hands new lookups to this window instead of opening another.
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg.showPanel) return;
  sendResponse({ windowId: myWindowId });
  location.search = msg.showPanel;
});

api.windows.getCurrent().then((w) => {
  if (w.type !== "popup") return;
  myWindowId = w.id;
  const frame = window.outerHeight - window.innerHeight;
  api.windows.update(w.id, { height: Math.min(screen.availHeight, $("panel").offsetHeight + frame) });
});

addEventListener("keydown", (e) => { if (e.key === "Escape") window.close(); });

function linkButton(text, onclick) {
  const b = document.createElement("button");
  b.className = "link";
  b.textContent = text;
  b.onclick = onclick;
  return b;
}

async function openTabs(urls) {
  for (const [i, url] of urls.entries()) {
    const opts = { url, active: i === 0 };
    // Open in the window the lookup came from; if it's gone, let the browser pick.
    await api.tabs.create(originWindow != null ? { ...opts, windowId: originWindow } : opts).catch(() => api.tabs.create(opts));
  }
}

function setType(type) {
  current = type;
  for (const b of $("types").querySelectorAll("button")) b.classList.toggle("active", b.dataset.type === type);
  $("algo").textContent = type === "hash" && detected === "hash" ? hashAlgo(ioc).toUpperCase() : "";
  for (const b of $("openall").querySelectorAll("button")) {
    b.disabled = !ioc || (type != null && b.dataset.type !== type);
    b.classList.toggle("primary", b.dataset.type === type);
  }
  renderWarning();
  renderSources();
  show(null, "");
}

function renderWarning() {
  let msg = "";
  if (!ioc) msg = "Nothing usable in the selection.";
  else if (!current) msg = "Couldn't tell what this is. Pick a type above.";
  else if (detected && detected !== current) msg = `This looks like ${ARTICLE[detected]}, not ${ARTICLE[current]}. `;
  else if (!detected) msg = `This doesn't look like ${ARTICLE[current]}. Lookups may come back empty.`;
  else if (current === "ip" && isPrivateIp(ioc)) msg = "Private or reserved address. Public intel sources won't know it.";
  $("warn-text").replaceChildren(msg);
  if (current && detected && detected !== current) {
    $("warn-text").append(linkButton(`Switch to ${detected.toUpperCase()}`, () => setType(detected)));
  }
  $("warn").hidden = !msg;
}

function renderSources() {
  const box = $("sources");
  box.replaceChildren();
  if (!current || !ioc) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Pick a type to see sources.";
    box.append(p);
    return;
  }
  for (const target of SEARCH_TARGETS[current]) {
    const url = buildUrl(target, ioc);
    const b = document.createElement("button");
    b.className = "src";
    b.title = url;
    b.append(target.name, icon("ArrowUp"));
    b.onclick = () => openTabs([url]);
    box.append(b);
  }
}

function show(result, text) {
  const s = result?.score;
  $("score").className = `score ${s == null ? "none" : s < 25 ? "clean" : s < 60 ? "sus" : "mal"}`;
  $("arc").style.strokeDashoffset = s == null ? CIRC : CIRC * (1 - Math.max(s, 2) / 100);
  $("pct").textContent = s == null ? "—" : `${s}%`;
  $("label").textContent = verdict(s) + (result?.sources === 1 ? " · 1 source" : "");
  $("breakdown").replaceChildren(text);
}

$("ioc").textContent = ioc || "(nothing selected)";
if (raw && raw.trim().toLowerCase() !== ioc) {
  $("raw").textContent = `from: ${raw}`;
  $("raw").hidden = false;
}
document.title = ioc ? `${ioc} · Threat Intel Search` : "Threat Intel Search";

$("copy").onclick = async () => {
  await navigator.clipboard.writeText(ioc);
  $("copy").replaceChildren(icon("TickSquare"));
  setTimeout(() => $("copy").replaceChildren(icon("Document")), 1200);
};
for (const b of $("types").querySelectorAll("button")) b.onclick = () => setType(b.dataset.type);
for (const b of $("openall").querySelectorAll("button")) {
  b.onclick = () => openTabs(SEARCH_TARGETS[b.dataset.type].map((t) => buildUrl(t, ioc)));
}

setType(current);
