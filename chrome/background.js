const searchTargets = {
  ip: [
    "https://www.virustotal.com/gui/ip-address/%s/detection/",
    "https://otx.alienvault.com/indicator/ip/%s",
    "https://www.abuseipdb.com/check/%s",
    "https://www.maxmind.com/en/geoip-web-services-demo?ip_address=%s"
  ],
  domain: [
    "https://www.virustotal.com/gui/domain/%s/detection",
    "https://otx.alienvault.com/indicator/domain/%s",
    "https://www.abuseipdb.com/check/%s"
  ],
  hash: [
    "https://www.virustotal.com/gui/file/%s/detection"
  ]
};

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "ip",
      title: "🔎 I (IP Address)",
      contexts: ["selection"]
    });

    chrome.contextMenus.create({
      id: "domain",
      title: "🔎 D (Domain)",
      contexts: ["selection"]
    });

    chrome.contextMenus.create({
      id: "hash",
      title: "🔎 H (Hash)",
      contexts: ["selection"]
    });
  });
}

chrome.runtime.onInstalled.addListener(createMenus);
chrome.runtime.onStartup.addListener(createMenus);

chrome.contextMenus.onClicked.addListener((info) => {
  const query = encodeURIComponent(info.selectionText.trim());
  const targets = searchTargets[info.menuItemId];
  if (!targets) return;

  for (const url of targets) {
    chrome.tabs.create({ url: url.replace(/%s/g, query) });
  }
});
