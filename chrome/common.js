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

function verdict(score) {
  if (score == null) return "not enough data";
  return score < 25 ? "likely clean" : score < 60 ? "suspicious" : "malicious";
}
