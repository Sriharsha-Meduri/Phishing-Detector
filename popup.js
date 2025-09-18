document.getElementById("scanButton").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (tabs.length === 0) return;

        let url = tabs[0].url;
        chrome.runtime.sendMessage({ action: "checkPhishing", url: url }, response => {
            if (response && response.isPhishing) {
                document.getElementById("result").innerText = "⚠️ This site is phishing!";
            } else {
                document.getElementById("result").innerText = "✅ This site is safe.";
            }
        });
    });
});
