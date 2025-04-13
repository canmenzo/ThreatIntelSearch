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
  browser.contextMenus.removeAll(() => {
    browser.contextMenus.create({
      id: "ip",
      title: "🔎 I (IP Address)",
      contexts: ["selection"]
    });

    browser.contextMenus.create({
      id: "domain",
      title: "🔎 D (Domain)",
      contexts: ["selection"]
    });

    browser.contextMenus.create({
      id: "hash",
      title: "🔎 H (Hash)",
      contexts: ["selection"]
    });
  });
}

browser.contextMenus.onClicked.addListener((info) => {
  const query = encodeURIComponent(info.selectionText.trim());
  const targets = searchTargets[info.menuItemId];
  if (!targets) return;

  for (const url of targets) {
    const finalUrl = url.replace(/%s/g, query);
    browser.tabs.create({ url: finalUrl });
  }
});

createMenus();
