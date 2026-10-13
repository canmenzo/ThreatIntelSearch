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
// File names that would otherwise pass as domains (none of these are real TLDs).
const FILE_NAME = /\.(?:exe|dll|sys|scr|msi|lnk|bat|cmd|vbs|hta|js|jar|txt|log|tmp|dat|bin|ini|cfg|json|xml|pdf|docx?|xlsx?|pptx?)$/i;
// Private, loopback, link-local, CGNAT, documentation (TEST-NET), benchmarking, multicast/reserved,
// and IPv4-mapped IPv6 (::ffff:a.b.c.d, which clean() turns into ::ffff:xxxx:xxxx).
const PRIVATE_IP = /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|192\.0\.[02]\.|198\.51\.100\.|203\.0\.113\.|198\.1[89]\.|2(?:2[4-9]|[3-5]\d)\.|::1?$|::ffff:|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:|ff[0-9a-f]{2}:|2001:db8:)/i;

function isIPv6(s) {
  if (!s.includes(":") || !/^[0-9a-f:.]+$/i.test(s)) return false;
  try { new URL(`http://[${s}]/`); return true; } catch { return false; }
}

function detect(s) {
  if (IPV4.test(s) || isIPv6(s)) return "ip";
  if (HASH.test(s)) return "hash";
  if (DOMAIN.test(s) && !FILE_NAME.test(s)) return "domain";
  return null;
}

const isPrivateIp = (ip) => PRIVATE_IP.test(ip);
const hashAlgo = (h) => ({ 32: "md5", 40: "sha1", 64: "sha256" })[h.length] || "sha256";

// Trim, strip quotes, refang (evil[.]com, hxxp), and reduce a URL to its host.
function clean(s) {
  s = s.trim()
    // The lookbehind keeps the trailing match linear: without it a long run of "," is O(n^2).
    .replace(/^["'`“”‘’<(]+|(?<!["'`“”‘’>),;!?])["'`“”‘’>),;!?]+$/g, "")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/^hxxp/i, "http")
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
    .replace(/^[^/?#@]*@/, "")
    .split(/[/?#]/)[0];
  const v6 = s.match(/^\[([0-9a-f:.]+)\](?::\d+)?$/i);
  if (v6) s = v6[1];
  else s = s.replace(/^\[|\]$/g, "").replace(/^([^:]+):\d+$/, "$1");
  // Canonical IPv6 (2001:0DB8:0::1 -> 2001:db8::1) so range checks and cache keys line up.
  if (isIPv6(s)) s = new URL(`http://[${s}]/`).hostname.slice(1, -1);
  else if (/[^\x00-\x7f]/.test(s)) {
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
//
// Each vendor turns its answer into evidence measured in log-odds: positive pushes toward
// malicious, negative toward clean, near zero means "doesn't say much". The pieces are added
// to a prior and squashed into 0-100 (naive Bayes). Strong evidence from one vendor is not
// averaged away by another vendor having never seen the indicator, and several weak signals
// that agree add up.

const TIMEOUT_MS = 8000;
const CACHE_MS = 30 * 60 * 1000;
const CACHE_VERSION = "4";
const PRIOR = Math.log(0.15 / 0.85); // things analysts right-click are more often bad than random traffic
const SINGLE_SOURCE_CAP = 59; // one vendor with only weak evidence can reach "suspicious", never "malicious"
const STRONG = 2.5; // log-odds a single vendor needs before it may speak alone (e.g. 6+ VT engines on a domain)
const YEAR_S = 365 * 86400;
const OTX_ALLOWLIST = ["whitelist", "false_positive", "majestic"];

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
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));

// Log curve for engine counts: a*ln(n) + b from one hit up, straight line from `zero` below that,
// so half a hit (one "suspicious") lands between zero hits and one hit instead of below zero.
const logCurve = (n, zero, a, b) => (n >= 1 ? a * Math.log(n) + b : zero + n * (b - zero));

// read(json, type) returns { finding, llr, evidence }. evidence: false means the vendor had
// nothing substantive (its small llr still counts once some other vendor has evidence).
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
    read(j, type) {
      const a = j.data?.attributes || {};
      const s = a.last_analysis_stats;
      const total = s ? s.malicious + s.suspicious + s.harmless + s.undetected : 0;
      if (!total) return { finding: "never analysed", llr: 0 };
      // Engine counts, not ratios: most engines never rate infrastructure, so 5/94 on an IP is
      // a real signal. Files get more skepticism for 1-2 hits (generic heuristics misfire).
      const eff = s.malicious + s.suspicious / 2;
      let llr = type === "hash" ? logCurve(eff, -1.2, 1.6, -0.6) : logCurve(eff, -0.6, 1.2, 0.5);
      const parts = [`${s.malicious}/${total} engines`];
      // IPs and domains change hands, so a verdict from a scan over a year old counts half.
      const scanAge = Date.now() / 1000 - a.last_analysis_date;
      if (type !== "hash" && scanAge > YEAR_S) {
        llr /= 2;
        parts.push(`scanned ${Math.floor(scanAge / YEAR_S)}y ago`);
      }
      if (a.reputation) llr += clamp(-a.reputation / 50, -1, 1) * 0.8;
      const rank = Math.min(...Object.values(a.popularity_ranks || {}).map((r) => r.rank));
      if (rank <= 10000) llr -= 1.5;
      else if (rank <= 100000) llr -= 0.8;
      // Newly registered domains are a staple of phishing and C2.
      const age = Date.now() / 1000 - a.creation_date;
      if (type === "domain" && age >= 0 && age < 30 * 86400) {
        llr += 1;
        parts.push(`registered ${Math.floor(age / 86400)}d ago`);
      }
      const label = a.popular_threat_classification?.suggested_threat_label;
      if (label) parts.push(label);
      else if (rank <= 100000) parts.push(`top ${rank <= 10000 ? "10k" : "100k"} site`);
      return { finding: parts.join(" · "), llr: clamp(llr, -3, 5.5), evidence: true };
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
      if (!d) return { finding: "no data", llr: 0 };
      if (d.isWhitelisted) return { finding: "allowlisted", llr: -2.5, evidence: true };
      if (!d.totalReports) return { finding: "0 reports", llr: -0.3 };
      // Starts where "0 reports" does: being reported at 0% confidence is not a sign of clean.
      let llr = -0.3 + 4.5 * (d.abuseConfidenceScore / 100);
      if (llr > 0 && d.numDistinctUsers <= 1) llr /= 2; // one reporter can be a grudge or a misconfig
      const parts = [`${d.abuseConfidenceScore}%`, plural(d.totalReports, "report")];
      if (d.numDistinctUsers <= 1) parts.push("1 reporter");
      if (d.isTor) parts.push("Tor exit");
      return { finding: parts.join(" · "), llr, evidence: true };
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
    read(j, type) {
      const validation = j.validation || [];
      // Domain allowlist entries are inherited from the registered domain (evil.duckdns.org comes
      // back "Whitelisted domain duckdns.org"), so they only count when they name this domain.
      // "Known False Positive" is per indicator.
      const named = (v) => {
        const host = (v.message || "").split(" ").pop();
        return host === j.indicator || `www.${host}` === j.indicator;
      };
      if (validation.some((v) => OTX_ALLOWLIST.includes(v.source) && (type !== "domain" || v.source === "false_positive" || named(v)))) {
        return { finding: "allowlisted", llr: -2.5, evidence: true };
      }
      const pulses = j.pulse_info?.count || 0;
      if (!pulses) return { finding: "0 pulses", llr: -0.2 };
      // A CDN address fronts thousands of sites, so pulses on the IP itself say nothing.
      if (type === "ip" && validation.some((v) => v.source === "cdn")) return { finding: `${plural(pulses, "pulse")} · CDN range`, llr: 0 };
      const rel = j.pulse_info.related || {};
      const names = (key) => [...(rel.alienvault?.[key] || []), ...(rel.other?.[key] || [])]
        .map((f) => (typeof f === "string" ? f : f.display_name || f.name)).filter(Boolean);
      const families = [...new Set(names("malware_families"))];
      const adversaries = [...new Set(names("adversary"))];
      // Pulses are community feeds of mixed quality, so OTX alone is capped below STRONG.
      let llr = Math.min(2.2, 0.7 * Math.log(1 + pulses) + (families.length ? 0.8 : 0) + (adversaries.length ? 0.5 : 0));
      const parts = [plural(pulses, "pulse")];
      if (type !== "hash") {
        // Sandbox runs put every host a sample touches into pulses, so shared infrastructure (cloud
        // front doors, code hosting, link shorteners) piles up pulses from dozens of unrelated families.
        if (families.length > 10) {
          llr *= 0.3;
          parts.push(`${families.length} unrelated families`);
        }
        const newest = Math.max(...(j.pulse_info.pulses || []).map((p) => Date.parse(p.modified?.slice(0, 19))));
        if (newest > 0 && Date.now() - newest > YEAR_S * 1000) {
          llr /= 2;
          parts.push(`last pulse ${Math.floor((Date.now() - newest) / YEAR_S / 1000)}y ago`);
        }
      }
      if (parts.length === 1) parts.push(...[...adversaries, ...families].slice(0, 2));
      return { finding: parts.join(" · "), llr, evidence: true };
    }
  }
};

async function lookup(id, type, ioc, key) {
  const j = await getJson(API_SOURCES[id].url(type, ioc), API_SOURCES[id].headers(key));
  return j ? API_SOURCES[id].read(j, type) : { finding: "not found", llr: 0 };
}

const testKey = (id, key) => getJson(API_SOURCES[id].testUrl, API_SOURCES[id].headers(key));

// results: [{ llr, evidence }]. Returns null when no vendor had evidence.
function combine(results) {
  const ev = results.filter((r) => r.evidence);
  if (!ev.length) return null;
  const sum = results.reduce((a, r) => a + (r.llr || 0), 0);
  let score = Math.round(100 / (1 + Math.exp(-(PRIOR + sum))));
  const strong = ev.some((r) => Math.abs(r.llr) >= STRONG);
  const capped = ev.length === 1 && !strong && score > SINGLE_SOURCE_CAP;
  if (capped) score = SINGLE_SOURCE_CAP;
  const bad = ev.some((r) => r.llr >= 1);
  const good = ev.some((r) => r.llr <= -1);
  // "high" needs corroboration: two vendors each leaning the way the total does.
  const agree = ev.filter((r) => r.llr * Math.sign(sum) >= 0.5).length;
  const confidence = bad && good ? "mixed"
    : agree >= 2 && Math.abs(sum) >= 2 ? "high"
    : strong || ev.length >= 2 ? "medium" : "low";
  return { score, sources: ev.length, confidence, capped };
}

// Per-vendor tone for the evidence list.
function tone(r) {
  if (r.error) return "error";
  if (r.llr >= 1.5) return "mal";
  if (r.llr > 0.3) return "sus";
  if (r.evidence && r.llr <= -0.5) return "clean";
  return "none";
}

function verdict(score) {
  if (score == null) return "not enough data";
  return score < 25 ? "likely clean" : score < 60 ? "suspicious" : "malicious";
}
