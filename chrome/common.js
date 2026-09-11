// Shared file: identical copies live at the repo root (Firefox, MV2) and in chrome/ (Chrome, MV3).
// Edit both. DEV.md has the one-liner that checks they still match.

const api = globalThis.browser ?? globalThis.chrome;

const TYPES = ["ip", "domain", "hash"];

// %s = the indicator, %a = hash algorithm (md5 / sha1 / sha256)
const SEARCH_TARGETS = {
  ip: [
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/ip-address/%s/detection/" },
    { name: "AlienVault OTX", url: "https://otx.alienvault.com/indicator/ip/%s" },
    { name: "AbuseIPDB", url: "https://www.abuseipdb.com/check/%s" },
    { name: "MaxMind", url: "https://www.maxmind.com/en/geoip-web-services-demo?ip_address=%s" },
    { name: "GreyNoise", url: "https://viz.greynoise.io/ip/%s" },
    { name: "Shodan InternetDB", url: "https://internetdb.shodan.io/%s" },
    { name: "urlscan.io", url: "https://urlscan.io/ip/%s" }
  ],
  domain: [
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/domain/%s/detection" },
    { name: "AlienVault OTX", url: "https://otx.alienvault.com/indicator/domain/%s" },
    { name: "AbuseIPDB", url: "https://www.abuseipdb.com/check/%s" },
    { name: "urlscan.io", url: "https://urlscan.io/domain/%s" },
    { name: "SecurityTrails", url: "https://securitytrails.com/domain/%s/dns" },
    { name: "Whois", url: "https://www.whois.com/whois/%s" },
    { name: "crt.sh", url: "https://crt.sh/?q=%s" }
  ],
  hash: [
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/file/%s/detection" },
    { name: "AlienVault OTX", url: "https://otx.alienvault.com/indicator/file/%s" },
    { name: "MalwareBazaar", url: "https://bazaar.abuse.ch/browse.php?search=%a%3A%s" },
    { name: "Hybrid Analysis", url: "https://hybrid-analysis.com/search?query=%s" }
  ]
};

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DOMAIN = /^(?=.{4,253}$)(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;
const PRIVATE_IP = /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/i;

function isIPv6(s) {
  if (!s.includes(":") || !/^[0-9a-f:.]+$/i.test(s)) return false;
  try { new URL(`http://[${s}]/`); return true; } catch { return false; }
}

function detect(s) {
  if (IPV4.test(s) || isIPv6(s)) return "ip";
  if (HASH.test(s)) return "hash";
  if (DOMAIN.test(s)) return "domain";
  return null;
}

const isPrivateIp = (ip) => PRIVATE_IP.test(ip);
const hashAlgo = (h) => ({ 32: "md5", 40: "sha1", 64: "sha256" })[h.length] || "sha256";

// Trim, strip quotes, refang (evil[.]com, hxxp), and reduce a URL to its host.
function clean(s) {
  s = s.trim()
    .replace(/^["'`“”‘’<(]+|["'`“”‘’>),;!?]+$/g, "")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/^hxxp/i, "http")
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
    .replace(/^[^/?#@]*@/, "")
    .split(/[/?#]/)[0];
  const v6 = s.match(/^\[([0-9a-f:.]+)\](?::\d+)?$/i);
  if (v6) s = v6[1];
  else s = s.replace(/^\[|\]$/g, "").replace(/^([^:]+):\d+$/, "$1");
  if (/[^\x00-\x7f]/.test(s)) {
    try { s = new URL(`http://${s}/`).hostname; } catch {}
  }
  return s.replace(/\.$/, "").toLowerCase();
}

// Whole selection first; if that isn't an indicator, the first token that is (preferring the picked type).
function normalize(raw, preferred) {
  const whole = clean(raw);
  if (detect(whole)) return whole;
  const found = raw.split(/[\s,;|]+/).map(clean).filter(detect);
  return found.find((t) => detect(t) === preferred) || found[0] || whole;
}

function buildUrl(target, ioc) {
  return target.url.replace(/%a/g, hashAlgo(ioc)).replace(/%s/g, encodeURIComponent(ioc));
}

// ---- Optional scoring (only runs when the user has saved API keys) ----

const TIMEOUT_MS = 8000;
const CACHE_MS = 30 * 60 * 1000;
const SINGLE_SOURCE_CAP = 59; // one source alone can reach "suspicious", never "malicious"
const OTX_ALLOWLIST = ["whitelist", "false_positive", "akamai", "alexa", "majestic"];

class LookupError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function getJson(url, headers) {
  let res;
  try {
    res = await fetch(url, { headers, credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    throw new LookupError(e.name === "TimeoutError" ? "timed out" : "unreachable", "error");
  }
  if (res.status === 401 || res.status === 403) throw new LookupError("key rejected", "rejected");
  if (res.status === 429) throw new LookupError("rate limited", "limited");
  if (res.status === 404) return null;
  if (!res.ok) throw new LookupError(`HTTP ${res.status}`, "error");
  return res.json();
}

const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

// read() returns { score 0-100, weight, text }, or just { text } when the source has nothing to say.
const API_SOURCES = {
  vt: {
    name: "VirusTotal",
    short: "VT",
    types: ["ip", "domain", "hash"],
    origin: "https://www.virustotal.com/*",
    keyPage: "https://www.virustotal.com/gui/my-apikey",
    headers: (key) => ({ "x-apikey": key }),
    url: (type, ioc) => `https://www.virustotal.com/api/v3/${{ ip: "ip_addresses", domain: "domains", hash: "files" }[type]}/${encodeURIComponent(ioc)}`,
    testUrl: "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
    read(j) {
      const s = j.data?.attributes?.last_analysis_stats;
      const total = s ? s.malicious + s.suspicious + s.harmless + s.undetected : 0;
      if (!total) return { text: "VT no analysis" };
      return { score: (s.malicious / total) * 100, weight: 3, text: `VT ${s.malicious}/${total}` };
    }
  },
  abuseipdb: {
    name: "AbuseIPDB",
    short: "AbuseIPDB",
    types: ["ip"],
    origin: "https://api.abuseipdb.com/*",
    keyPage: "https://www.abuseipdb.com/api.html",
    headers: (key) => ({ Key: key, Accept: "application/json" }),
    url: (type, ioc) => `https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=${encodeURIComponent(ioc)}`,
    testUrl: "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
    read(j) {
      const d = j.data;
      if (!d || !d.totalReports) return { text: "AbuseIPDB 0 reports" };
      const n = d.totalReports;
      return { score: d.abuseConfidenceScore, weight: n >= 5 ? 2 : 1, text: `AbuseIPDB ${d.abuseConfidenceScore} (${plural(n, "report")})` };
    }
  },
  otx: {
    name: "AlienVault OTX",
    short: "OTX",
    types: ["ip", "domain", "hash"],
    origin: "https://otx.alienvault.com/*",
    keyPage: "https://otx.alienvault.com/api",
    headers: (key) => ({ "X-OTX-API-KEY": key }),
    url: (type, ioc) => `https://otx.alienvault.com/api/v1/indicators/${type === "hash" ? "file" : type === "domain" ? "domain" : ioc.includes(":") ? "IPv6" : "IPv4"}/${encodeURIComponent(ioc)}/general`,
    // Indicator lookups ignore bad keys, so validate against the account endpoint instead.
    testUrl: "https://otx.alienvault.com/api/v1/users/me",
    read(j) {
      if ((j.validation || []).some((v) => OTX_ALLOWLIST.includes(v.source))) return { score: 0, weight: 1, text: "OTX allowlisted" };
      const pulses = j.pulse_info?.count || 0;
      if (!pulses) return { text: "OTX 0 pulses" };
      const rel = j.pulse_info.related || {};
      const families = [...new Set([...(rel.alienvault?.malware_families || []), ...(rel.other?.malware_families || [])]
        .map((f) => (typeof f === "string" ? f : f.display_name)).filter(Boolean))];
      const score = Math.min(80, 20 + pulses * 10) + (families.length ? 20 : 0);
      return { score, weight: 1, text: `OTX ${plural(pulses, "pulse")}${families.length ? ` (${families.slice(0, 2).join(", ")})` : ""}` };
    }
  }
};

async function lookup(id, type, ioc, key) {
  const src = API_SOURCES[id];
  const j = await getJson(src.url(type, ioc), src.headers(key));
  return j ? src.read(j) : { text: `${src.short} not found` };
}

const testKey = (id, key) => getJson(API_SOURCES[id].testUrl, API_SOURCES[id].headers(key));

function combine(results) {
  const scored = results.filter((r) => r.score != null);
  if (!scored.length) return null;
  const weight = scored.reduce((a, r) => a + r.weight, 0);
  let score = Math.round(scored.reduce((a, r) => a + r.score * r.weight, 0) / weight);
  if (scored.length === 1) score = Math.min(score, SINGLE_SOURCE_CAP);
  return { score, sources: scored.length };
}

function verdict(score) {
  if (score == null) return "not enough data";
  return score < 25 ? "likely clean" : score < 60 ? "suspicious" : "malicious";
}
