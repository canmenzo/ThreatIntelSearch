// Shared file: identical copies live at the repo root (Firefox, MV2) and in chrome/ (Chrome, MV3). Edit both.

const params = new URLSearchParams(location.search);
const ioc = params.get("ioc") || "";
const raw = params.get("raw") || "";
const originWindow = params.get("win") ? Number(params.get("win")) : null;
const detected = detect(ioc);
const ARTICLE = { ip: "an IP address", domain: "a domain", hash: "a file hash" };
const PLURAL = { ip: "IPs", domain: "domains", hash: "hashes" };
const VERDICT_ICON = { clean: "ShieldDone", sus: "Danger", mal: "ShieldFail" };
const CIRC = 2 * Math.PI * 42;
const HOW_URL = "https://github.com/canmenzo/ThreatIntelSearch#how-the-score-works";
const $ = (id) => document.getElementById(id);

let current = TYPES.includes(params.get("type")) ? params.get("type") : detected;
let myWindowId = null;
let run = 0;
let shownPct = 0;

// One panel at a time: the background hands new lookups to this window instead of opening another.
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg.showPanel) return;
  sendResponse({ windowId: myWindowId });
  location.search = msg.showPanel;
});

api.windows.getCurrent().then((w) => {
  if (w.type !== "popup") return;
  myWindowId = w.id;
  fit();
});

function fit() {
  if (myWindowId == null) return;
  const height = Math.min(screen.availHeight, $("panel").offsetHeight + window.outerHeight - window.innerHeight);
  if (Math.abs(height - window.outerHeight) > 4) api.windows.update(myWindowId, { height });
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function linkButton(text, onclick) {
  const b = el("button", "link", text);
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

let toastTimer;
async function copy(text, message) {
  await navigator.clipboard.writeText(text);
  $("toast").textContent = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("toast").textContent = ""; }, 1400);
}

const defanged = () => ioc.replace(/\./g, "[.]").replace(/:/g, "[:]");

function setType(type) {
  current = type;
  for (const b of $("types").querySelectorAll("button")) b.classList.toggle("active", b.dataset.type === type);
  $("algo").textContent = type === "hash" && detected === "hash" ? hashAlgo(ioc).toUpperCase() : "";
  $("defang").hidden = !ioc || type === "hash";
  for (const b of $("openall").querySelectorAll("button")) {
    b.disabled = !ioc || (type != null && b.dataset.type !== type);
    b.classList.toggle("primary", b.dataset.type === type);
    b.title = `Opens ${SEARCH_TARGETS[b.dataset.type].length} tabs`;
  }
  renderWarning();
  renderSources();
  score();
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
    box.append(el("p", "muted", "Pick a type to see sources."));
    return;
  }
  SEARCH_TARGETS[current].forEach((target, i) => {
    const url = buildUrl(target, ioc);
    const b = el("button", "src");
    b.title = `${url}\nShortcut: ${i + 1}`;
    b.append(el("kbd", null, String(i + 1)), el("span", "src-name", target.name), icon("ArrowUp"));
    b.onclick = () => openTabs([url]);
    box.append(b);
  });
}

function vendorUrl(id) {
  const target = SEARCH_TARGETS[current]?.find((t) => t.name === API_SOURCES[id].name);
  return target && buildUrl(target, ioc);
}

function countUp(to) {
  const from = shownPct;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / 700);
    shownPct = Math.round(from + (to - from) * (1 - (1 - t) ** 3));
    $("pct").textContent = `${shownPct}%`;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function evidenceRow(id, r) {
  const row = el("button", "ev-row");
  const url = vendorUrl(id);
  if (url) {
    row.title = `Open ${API_SOURCES[id].name}`;
    row.onclick = () => openTabs([url]);
  }
  const finding = r ? el("span", "ev-finding", r.finding) : el("span", "ev-finding skel");
  if (r) finding.title = r.finding;
  row.append(el("span", `dot ${r ? tone(r) : "none"}`), el("span", "ev-name", API_SOURCES[id].name), finding);
  return row;
}

// state: "none" | "loading" | a combine() result (or null) with rows
function show(state, { note = "", action, rows = [], ids = [], checkedAt } = {}) {
  const s = state && state !== "loading" && state !== "none" ? state.score : null;
  const cls = state === "loading" ? "loading" : s == null ? "none" : s < 25 ? "clean" : s < 60 ? "sus" : "mal";
  $("score").className = `score ${cls}`;
  $("arc").style.strokeDashoffset = state === "loading" ? CIRC * 0.75 : s == null ? CIRC : CIRC * (1 - Math.max(s, 2) / 100);

  if (s == null) {
    shownPct = 0;
    $("pct").textContent = state === "loading" ? "…" : "—";
  } else {
    countUp(s);
  }
  $("label").textContent = state === "loading" ? "checking…" : verdict(s);
  $("verdict-icon").replaceChildren(...(VERDICT_ICON[cls] ? [icon(VERDICT_ICON[cls])] : []));

  const conf = $("confidence");
  conf.replaceChildren(note);
  if (s != null) {
    const n = plural(state.sources, "source");
    conf.textContent = state.confidence === "mixed" ? `sources disagree · ${n}` : `${state.confidence} confidence · ${n}${state.capped ? " · capped" : ""}`;
    conf.title = state.capped ? "Only one vendor had evidence and it was weak, so the score is held at 59." : "";
  }
  if (action) conf.append(el("br"), linkButton(action, () => api.runtime.openOptionsPage()));

  $("evidence").replaceChildren(...(state === "loading" ? ids.map((id) => evidenceRow(id)) : rows.map((r) => evidenceRow(r.id, r))));
  $("score-foot").hidden = !checkedAt;
  if (checkedAt) {
    const mins = Math.floor((Date.now() - checkedAt) / 60000);
    $("cached").replaceChildren(icon("TimeCircle"), mins < 1 ? "checked just now" : `cached ${mins} min ago`);
  }
  fit();
}

async function score(fresh = false) {
  const my = ++run;
  const type = current;
  const { keys = {}, scoring = true, keyStatus = {} } = await api.storage.local.get(["keys", "scoring", "keyStatus"]);
  if (my !== run) return;
  if (!type || detected !== type) return show("none");
  if (type === "ip" && isPrivateIp(ioc)) return show("none", { note: "Private address, nothing to look up." });
  if (!scoring) return show("none", { note: "Scoring is turned off.", action: "Settings" });
  const ids = Object.keys(API_SOURCES).filter((id) => keys[id] && API_SOURCES[id].types.includes(type));
  if (!ids.length) {
    return Object.keys(keys).length
      ? show("none", { note: `None of your API keys cover ${PLURAL[type]}.`, action: "Settings" })
      : show("none", { note: "Links only. Add free API keys for a score.", action: "Add keys" });
  }
  show("loading", { ids });
  const rows = await lookupAll(ids, type, keys, keyStatus, fresh);
  if (my !== run) return;
  const checkedAt = Math.min(...rows.map((r) => r.at || Date.now()));
  show(combine(rows), { rows, checkedAt });
}

async function lookupAll(ids, type, keys, keyStatus, fresh) {
  const now = Date.now();
  const { cache = {} } = await api.storage.local.get("cache");
  for (const k in cache) if (!k.startsWith(`${CACHE_VERSION}|`) || now - cache[k].at > CACHE_MS) delete cache[k];

  const rows = await Promise.all(ids.map(async (id) => {
    const k = `${CACHE_VERSION}|${id}|${type}|${ioc}`;
    if (cache[k] && !fresh) return { id, at: cache[k].at, ...cache[k].r };
    if (keyStatus[id] === "rejected") return { id, finding: "key rejected", error: true };
    if (!(await api.permissions.contains({ origins: [API_SOURCES[id].origin] }))) return { id, finding: "needs site access", error: true };
    try {
      const r = await lookup(id, type, ioc, keys[id]);
      cache[k] = { at: now, r };
      keyStatus[id] = "ok";
      return { id, at: now, ...r };
    } catch (e) {
      if (!(e instanceof LookupError)) return { id, finding: "bad response", error: true };
      if (e.status !== "error") keyStatus[id] = e.status;
      return { id, finding: e.message, error: true };
    }
  }));

  await api.storage.local.set({ cache, keyStatus });
  return rows;
}

$("ioc").textContent = ioc || "(nothing selected)";
if (raw && raw.trim().toLowerCase() !== ioc) {
  $("raw").textContent = `from: ${raw}`;
  $("raw").hidden = false;
}
document.title = ioc ? `${ioc} · Threat Intel Search` : "Threat Intel Search";

$("settings").onclick = () => api.runtime.openOptionsPage();
$("how").onclick = () => openTabs([HOW_URL]);
$("refresh").onclick = () => score(true);
$("copy").onclick = () => copy(ioc, "copied");
$("defang").onclick = () => copy(defanged(), "copied defanged");
for (const b of $("types").querySelectorAll("button")) b.onclick = () => setType(b.dataset.type);
for (const b of $("openall").querySelectorAll("button")) {
  b.onclick = () => openTabs(SEARCH_TARGETS[b.dataset.type].map((t) => buildUrl(t, ioc)));
}

addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "Escape") window.close();
  else if (e.key === "c" && ioc) copy(ioc, "copied");
  else if (e.key === "d" && ioc && current !== "hash") copy(defanged(), "copied defanged");
  else if (/^[1-9]$/.test(e.key)) document.querySelectorAll(".src")[e.key - 1]?.click();
});

setType(current);
