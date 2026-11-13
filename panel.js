// Shared file: identical copies live at the repo root (Firefox, MV2) and in chrome/ (Chrome, MV3). Edit both.

const params = new URLSearchParams(location.search);
const ioc = params.get("ioc") || "";
const raw = params.get("raw") || "";
const originWindow = params.get("win") ? Number(params.get("win")) : null;
const detected = detect(ioc);
const ARTICLE = { ip: "an IP address", domain: "a domain", hash: "a file hash" };
const PLURAL = { ip: "IPs", domain: "domains", hash: "hashes" };
const NAME = { ip: "IP", domain: "domain", hash: "hash" };
const ALGO = { md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" };
const CIRC = 2 * Math.PI * 44;
const METER_FULL = 4; // log-odds that fill a vendor's meter
const HOW_URL = "https://github.com/canmenzo/ThreatIntelSearch#how-the-score-works";
const $ = (id) => document.getElementById(id);
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

let current = TYPES.includes(params.get("type")) ? params.get("type") : detected;
let myWindowId = null;
let run = 0;
let shownScore = 0;
let countFrame = 0;
let scored = false;

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

const capital = (s) => s[0].toUpperCase() + s.slice(1);

async function openTabs(urls) {
  for (const [i, url] of urls.entries()) {
    const opts = { url, active: i === 0 };
    // Open in the window the lookup came from; if it's gone, let the browser pick.
    await api.tabs.create(originWindow != null ? { ...opts, windowId: originWindow } : opts).catch(() => api.tabs.create(opts));
  }
}

let toastTimer;
async function copy(text, message, button) {
  let ok = true;
  try { await navigator.clipboard.writeText(text); } catch { ok = false; }
  $("toast").textContent = ok ? message : "Copy failed";
  $("toast").classList.add("show");
  if (ok) button.classList.add("done");
  if (ok && button === $("copy")) button.replaceChildren(icon("TickSquare"));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    $("toast").classList.remove("show");
    for (const b of [$("copy"), $("defang")]) b.classList.remove("done");
    $("copy").replaceChildren(icon("Document"));
  }, 1400);
}

const defanged = () => ioc.replace(/\./g, "[.]").replace(/:/g, "[:]");

function setType(type) {
  current = type;
  for (const b of $("types").querySelectorAll("button")) b.classList.toggle("active", b.dataset.type === type);
  $("algo").textContent = type === "hash" && detected === "hash" ? ALGO[hashAlgo(ioc)] : "";
  $("defang").hidden = $("hint-defang").hidden = !ioc || type === "hash";
  $("openall").hidden = !ioc || !type;
  if (type) $("open-all-label").textContent = `Open all ${SEARCH_TARGETS[type].length} ${NAME[type]} sources`;
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
    $("warn-text").append(linkButton(`Switch to ${NAME[detected]}`, () => setType(detected)));
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
  cancelAnimationFrame(countFrame);
  if (REDUCED_MOTION) {
    shownScore = to;
    $("pct").textContent = to;
    return;
  }
  const from = shownScore;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, Math.max(0, now - start) / 500);
    shownScore = Math.round(from + (to - from) * (1 - (1 - t) ** 3));
    $("pct").textContent = shownScore;
    if (t < 1) countFrame = requestAnimationFrame(step);
  };
  countFrame = requestAnimationFrame(step);
}

function evidenceRow(id, r) {
  const row = el("button", r ? "ev-row" : "ev-row pending");
  const url = vendorUrl(id);
  if (url) {
    row.title = `Open ${API_SOURCES[id].name}`;
    row.onclick = () => openTabs([url]);
  }
  const t = r ? tone(r) : "none";
  row.append(el("span", `dot ${t}`), el("span", "ev-name", API_SOURCES[id].name));
  if (!r) {
    row.append(el("span"), el("span", "skel"));
    return row;
  }
  const llr = r.llr || 0;
  const meter = el("span", `meter ${t}${llr < 0 ? " good" : ""}`);
  meter.style.setProperty("--w", Math.min(1, Math.abs(llr) / METER_FULL).toFixed(2));
  if (!r.error) meter.title = Math.abs(llr) < 0.05 ? "Doesn't move the score" : `Pushes the score toward ${llr > 0 ? "malicious" : "clean"}`;
  row.append(meter, el("span", "ev-finding", r.finding), el("span", "ev-detail", r.detail || ""));
  return row;
}

// state: "empty" (nothing was looked up) | "loading" | a combine() result, or null when no vendor had evidence
function show(state, { title = "", note = "", action, rows = [], ids = [], checkedAt } = {}) {
  const ran = state !== "empty" && state !== "loading";
  const s = ran && state ? state.score : null;
  const cls = !ran ? state : s == null ? "none" : s < 25 ? "clean" : s < 60 ? "sus" : "mal";
  scored = ran;
  $("score").className = `score ${cls}`;
  const arc = $("arc");
  if (s != null) {
    // Empty the ring without a transition so every result sweeps in from the top.
    arc.style.transition = "none";
    arc.style.strokeDashoffset = CIRC;
    arc.getBoundingClientRect();
    arc.style.transition = "";
  }
  arc.style.strokeDashoffset = state === "loading" ? CIRC * 0.75 : s == null ? CIRC : CIRC * (1 - Math.max(s, 2) / 100);

  if (s == null) {
    cancelAnimationFrame(countFrame);
    shownScore = 0;
    $("pct").textContent = "--";
  } else {
    countUp(s);
  }
  $("label").textContent = state === "loading" ? "Analyzing…" : ran ? verdict(s) : title;

  const conf = $("confidence");
  conf.title = "";
  if (state === "loading") {
    conf.textContent = `Querying ${plural(ids.length, "vendor")}`;
  } else if (!ran) {
    conf.textContent = note;
  } else if (s == null) {
    conf.textContent = rows.every((r) => r.error) ? "No vendor answered." : "No vendor has a record of it. Unknown is not the same as clean.";
  } else {
    const n = plural(state.sources, "source");
    conf.textContent = state.confidence === "mixed" ? `Sources disagree · ${n}` : `${capital(state.confidence)} confidence · ${n}`;
    if (state.capped) {
      conf.textContent += ` · capped at ${SINGLE_SOURCE_CAP}`;
      conf.title = "Only one vendor had evidence and it was weak, so the score stops short of malicious.";
    } else if (state.floored) {
      conf.textContent += ` · held at ${CONFLICT_FLOOR}`;
      conf.title = "One vendor has a strong detection that another contradicts, so the score is not allowed to read as clean.";
    }
  }
  $("score-action").hidden = !action;
  $("score-action").textContent = action || "";

  if (state !== "loading") {
    const facts = mergeFacts(rows);
    $("facts").textContent = facts.join(" · ");
    $("facts").hidden = !facts.length;
  }
  $("evidence").replaceChildren(...(state === "loading" ? ids.map((id) => evidenceRow(id)) : rows.map((r) => evidenceRow(r.id, r))));
  $("score-foot").hidden = !checkedAt;
  if (checkedAt) {
    const mins = Math.floor((Date.now() - checkedAt) / 60000);
    $("cached").textContent = mins < 1 ? "Checked just now" : `Cached ${mins} min ago`;
  }
  fit();
}

async function score(fresh = false) {
  const my = ++run;
  const type = current;
  const { keys = {}, scoring = true, keyStatus = {} } = await api.storage.local.get(["keys", "scoring", "keyStatus"]);
  if (my !== run) return;
  if (!type || detected !== type) return show("empty", { title: "No score", note: "The type has to match the indicator." });
  if (type === "ip" && isPrivateIp(ioc)) return show("empty", { title: "No score", note: "Private address, nothing to look up." });
  if (!scoring) return show("empty", { title: "Scoring is off", note: "Links only.", action: "Settings" });
  const ids = Object.keys(API_SOURCES).filter((id) => keys[id] && API_SOURCES[id].types.includes(type));
  if (!ids.length) {
    return Object.keys(keys).length
      ? show("empty", { title: "No score", note: `None of your API keys cover ${PLURAL[type]}.`, action: "Settings" })
      : show("empty", { title: "No score yet", note: "Add a free API key to get one.", action: "Add keys" });
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
    if (keyStatus[id] === "rejected") return { id, finding: "Key rejected", error: true };
    if (!(await api.permissions.contains({ origins: [API_SOURCES[id].origin], ...DATA_COLLECTION }))) return { id, finding: "Needs site access", error: true };
    try {
      const r = await lookup(id, type, ioc, keys[id]);
      cache[k] = { at: now, r };
      keyStatus[id] = "ok";
      return { id, at: now, ...r };
    } catch (e) {
      if (!(e instanceof LookupError)) return { id, finding: "Bad response", error: true };
      if (e.status !== "error") keyStatus[id] = e.status;
      return { id, finding: e.message, error: true };
    }
  }));

  await api.storage.local.set({ cache, keyStatus });
  return rows;
}

const lookUp = (indicator) => { location.search = new URLSearchParams({ ioc: indicator, type: "", raw, win: params.get("win") || "" }); };

$("ioc").textContent = ioc || "(Nothing selected)";
if (raw && raw.trim().toLowerCase() !== ioc) {
  $("raw").textContent = `From: ${raw}`;
  $("raw").title = raw;
  $("raw").hidden = false;
}
// A selected log line can hold several indicators; the rest are one click away.
const others = extract(raw).filter((t) => t !== ioc).slice(0, 4);
if (others.length) {
  $("others").append("Also selected", ...others.map((t) => linkButton(t, () => lookUp(t))));
  $("others").hidden = false;
}
document.title = ioc ? `${ioc} · Threat Intel Search` : "Threat Intel Search";

$("settings").onclick = () => api.runtime.openOptionsPage();
$("score-action").onclick = () => api.runtime.openOptionsPage();
$("how").onclick = () => openTabs([HOW_URL]);
$("refresh").onclick = () => score(true);
$("copy").onclick = () => copy(ioc, "Copied", $("copy"));
$("defang").onclick = () => copy(defanged(), "Copied defanged", $("defang"));
for (const b of $("types").querySelectorAll("button")) b.onclick = () => setType(b.dataset.type);
$("open-all").onclick = () => openTabs(SEARCH_TARGETS[current].map((t) => buildUrl(t, ioc)));

addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const key = e.key.toLowerCase();
  if (key === "escape") window.close();
  else if (key === "c" && ioc) copy(ioc, "Copied", $("copy"));
  else if (key === "d" && ioc && current !== "hash") copy(defanged(), "Copied defanged", $("defang"));
  else if (key === "r" && scored) score(true);
  else if (key === "o" && ioc && current) $("open-all").click();
  else if (/^[1-9]$/.test(key)) document.querySelectorAll(".src")[key - 1]?.click();
});

setType(current);
