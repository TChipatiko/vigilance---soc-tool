chrome.runtime.onInstalled.addListener(() => {
  const menuItems = [
      { id: "hash_check", title: "Hash Reputation Checker" },
      { id: "ip_reputation", title: "IP Reputation Checker" },
      { id: "ip_info", title: "IP Info Checker" },
      { id: "info_search", title: "Info Search" }
  ];

  menuItems.forEach(item => {
      chrome.contextMenus.create({
          id: item.id,
          title: item.title,
          contexts: ["selection"]
      });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId) {
      const selectedText = info.selectionText.trim();
      if (selectedText) {
          handleInvestigation(info.menuItemId, selectedText);
      }
  }
});

function handleInvestigation(type, query) {
  let urls = [];
  switch (type) {
      case "hash_check":
          urls = [
              `https://www.virustotal.com/gui/search/${query}`,
              `https://metadefender.com/results/hash/${query}`,
              `https://opentip.kaspersky.com/${query}`,
              `https://exchange.xforce.ibmcloud.com/malware/${query}`,
              `https://talosintelligence.com/talos_file_reputation?s=${query}`,
              `https://otx.alienvault.com/indicator/file/${query}`,
              `https://bazaar.abuse.ch/browse.php?search=sha256:${query}`
          ];
          break;
      case "ip_reputation":
          urls = [
              `https://www.virustotal.com/gui/ip-address/${query}`,
              `https://www.abuseipdb.com/check/${query}`,
              `https://talosintelligence.com/reputation_center/lookup?search=${query}`,
              `https://exchange.xforce.ibmcloud.com/ip/${query}`,
              `https://otx.alienvault.com/indicator/ip/${query}`,
          ];
          break;
      case "ip_info":
          urls = [
              `https://stat.ripe.net/${query}`,
              `https://bgp.he.net/ip/${query}#_whois`,
              `https://ipinfo.io/${query}`,
              `https://whatismyipaddress.com/ip/${query}`,
              `https://www.shodan.io/host/${query}`,
              `https://dnschecker.org/ip-whois-lookup.php?query=${query}`
          ];
          break;
      case "completed info_search":
          urls = [
              `https://www.file.net/process/${query}.html`
              `https://www.google.com/search?q="${query}"`
              `https://www.processlibrary.com/en/search?q="${query}"`
          ];
          break;
  }
  urls.forEach(url => chrome.tabs.create({ url }));
}