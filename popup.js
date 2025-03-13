document.getElementById("searchBtn").addEventListener("click", function() {
    let query = document.getElementById("searchQuery").value.trim();
    if (query) {
        chrome.runtime.sendMessage({ action: "investigate", query });
    }
});

chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "investigate") {
        handleInvestigation("info_search", message.query);
    }
});
