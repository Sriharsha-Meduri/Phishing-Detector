chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "showWarning") {
        let banner = document.createElement("div");
        banner.style.background = "red";
        banner.style.color = "white";
        banner.style.padding = "10px";
        banner.style.position = "fixed";
        banner.style.top = "0";
        banner.style.width = "100%";
        banner.style.textAlign = "center";
        banner.style.zIndex = "10000";
        banner.innerText = "⚠️ WARNING: This site is flagged as phishing!";
        document.body.prepend(banner);
    }
});
