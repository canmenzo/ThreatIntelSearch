// Shared file: identical copies live at the repo root (Firefox, MV2) and in chrome/ (Chrome, MV3). Edit both.

const $ = (id) => document.getElementById(id);

const STATUS = {
  unset: ["not set", ""],
  saved: ["saved, not tested yet", ""],
  testing: ["testing…", ""],
  ok: ["key OK", "ok"],
  rejected: ["key rejected", "bad"],
  limited: ["rate limited (key accepted)", "warnc"],
  permission: ["site access not granted", "bad"],
  error: ["couldn't reach the vendor", "warnc"]
};

function setStatus(id, status) {
  const [text, cls] = STATUS[status] || STATUS.unset;
  $(`status-${id}`).textContent = text;
  $(`status-${id}`).className = `status ${cls}`;
}

function keyCard(id, src) {
  const label = document.createElement("label");
  label.htmlFor = `key-${id}`;
  label.textContent = `${src.name} API key `;
  const covers = document.createElement("span");
  covers.className = "muted";
  covers.textContent = `· ${src.types.join(", ")}`;
  label.append(covers);

  const input = document.createElement("input");
  input.id = `key-${id}`;
  input.type = "password";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.placeholder = "optional";

  const reveal = document.createElement("button");
  reveal.className = "icon-btn";
  reveal.title = "Show or hide";
  reveal.append(icon("Show"));
  reveal.onclick = () => {
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    reveal.replaceChildren(icon(hidden ? "Hide" : "Show"));
  };

  const row = document.createElement("div");
  row.className = "key-row";
  row.append(input, reveal);

  const status = document.createElement("span");
  status.id = `status-${id}`;
  const get = document.createElement("a");
  get.href = src.keyPage;
  get.target = "_blank";
  get.rel = "noreferrer";
  get.textContent = "Get a free key";
  const foot = document.createElement("div");
  foot.className = "card-foot";
  foot.append(status, get);

  const card = document.createElement("div");
  card.className = "card";
  card.append(label, row, foot);
  return card;
}

async function save(keys, granted) {
  const unused = Object.keys(API_SOURCES).filter((id) => !keys[id]).map((id) => API_SOURCES[id].origin);
  if (unused.length) await api.permissions.remove({ origins: unused });
  await api.storage.local.set({ keys, keyStatus: {} });
  $("saved").textContent = "Saved.";

  const keyStatus = {};
  await Promise.all(Object.keys(API_SOURCES).map(async (id) => {
    if (!keys[id]) return setStatus(id, "unset");
    if (!granted) return setStatus(id, "permission");
    setStatus(id, "testing");
    try {
      await testKey(id, keys[id]);
      keyStatus[id] = "ok";
    } catch (e) {
      keyStatus[id] = e instanceof LookupError ? e.status : "error";
    }
    setStatus(id, keyStatus[id]);
  }));
  await api.storage.local.set({ keyStatus });
}

$("save").onclick = () => {
  const keys = {};
  for (const id in API_SOURCES) {
    const value = $(`key-${id}`).value.trim();
    if (value) keys[id] = value;
  }
  const origins = Object.keys(keys).map((id) => API_SOURCES[id].origin);
  // Firefox only honours permissions.request() when it is called directly from the click.
  const granted = origins.length ? api.permissions.request({ origins }) : Promise.resolve(true);
  granted.then((ok) => save(keys, ok), () => save(keys, false));
};

$("scoring").onchange = () => api.storage.local.set({ scoring: $("scoring").checked });

$("clear-cache").onclick = async () => {
  await api.storage.local.remove("cache");
  $("saved").textContent = "Cached scores cleared.";
};

for (const [id, src] of Object.entries(API_SOURCES)) $("keys").append(keyCard(id, src));

api.storage.local.get(["keys", "scoring", "keyStatus"]).then(({ keys = {}, scoring = true, keyStatus = {} }) => {
  $("scoring").checked = scoring;
  for (const id in API_SOURCES) {
    $(`key-${id}`).value = keys[id] || "";
    setStatus(id, keys[id] ? keyStatus[id] || "saved" : "unset");
  }
});
