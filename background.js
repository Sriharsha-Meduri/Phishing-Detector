// --- Replace GOOGLE_SAFE_BROWSING_API_KEY usage with VirusTotal ---
const VIRUSTOTAL_API_KEY = "0cfdaba1d57f45d0d15ebc3cf82c4f63769d093c9ef8e47f8cf6049a9f0e7385";
const OPEN_PHISH_FEED_URL = "https://openphish.com/feed.txt";

// Convert URL to VirusTotal URL id (base64 url-safe, no padding)
function urlToVirusTotalId(url) {
    // btoa(encodeURIComponent(...)) safe conversion
    try {
        const utf8Bytes = unescape(encodeURIComponent(url));
        const b64 = btoa(utf8Bytes);
        // make it url-safe and strip padding
        return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } catch (err) {
        console.error("Error encoding URL for VirusTotal:", err);
        return null;
    }
}

async function fetchJson(url, opts = {}) {
    const response = await fetch(url, opts);
    if (!response.ok) {
        const text = await response.text().catch(() => "");
        const err = new Error(`HTTP ${response.status}: ${text}`);
        err.status = response.status;
        throw err;
    }
    return response.json();
}

// Primary VirusTotal check: lookup URL info; if absent, submit for scan and poll analysis
async function checkVirusTotal(url) {
    const vtBase = "https://www.virustotal.com/api/v3";
    const headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    };

    const vtId = urlToVirusTotalId(url);
    if (!vtId) return false;

    try {
        // 1) Try a simple lookup
        const lookup = await fetchJson(`${vtBase}/urls/${vtId}`, { headers });
        const stats = lookup?.data?.attributes?.last_analysis_stats;
        if (stats) {
            const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);
            return maliciousCount > 0;
        }
    } catch (err) {
        // If 404: URL unknown to VT — submit it for scanning. If other errors, log and continue.
        if (err.status !== 404) {
            console.warn("VirusTotal lookup error (non-404):", err);
            // continue to attempt submitting for scan below
        }
    }

    try {
        // 2) Submit URL for analysis
        const form = new URLSearchParams();
        form.append("url", url);

        const submitResp = await fetch(`${vtBase}/urls`, {
            method: "POST",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: form.toString()
        });

        if (!submitResp.ok) {
            // If rate-limited or other error, don't crash — treat as non-malicious for now
            console.warn("VirusTotal submit response not OK:", submitResp.status);
            return false;
        }

        const submitJson = await submitResp.json();
        // The POST returns a data.id which is analysis id for /analyses/{id}
        const analysisId = submitJson?.data?.id;
        if (!analysisId) return false;

        // 3) Poll analysis endpoint a few times (best-effort)
        const maxPolls = 5;
        const pollDelayMs = 1000;
        for (let i = 0; i < maxPolls; i++) {
            // eslint-disable-next-line no-await-in-loop
            const analysis = await fetchJson(`${vtBase}/analyses/${analysisId}`, { headers });
            const status = analysis?.data?.attributes?.status;
            if (status === "completed") {
                // After completion, try lookup again to get last_analysis_stats
                const finalLookup = await fetchJson(`${vtBase}/urls/${vtId}`, { headers });
                const finalStats = finalLookup?.data?.attributes?.last_analysis_stats;
                const maliciousCount = (finalStats?.malicious || 0) + (finalStats?.suspicious || 0);
                return maliciousCount > 0;
            }
            // eslint-disable-next-line no-await-in-loop
            await new Promise(r => setTimeout(r, pollDelayMs));
        }

        // If polling didn't finish: conservative approach => treat as non-malicious for now
        return false;
    } catch (error) {
        console.error("VirusTotal check error:", error);
        return false;
    }
}

function normalizeUrl(url) {
    try {
        let u = new URL(url);
        return u.origin + u.pathname;
    } catch {
        return url;
    }
}

async function checkOpenPhish(url) {
    try {
        let response = await fetch(OPEN_PHISH_FEED_URL);
        let text = await response.text();
        let phishingUrls = text.split("\n").map(line => normalizeUrl(line.trim()));
        return phishingUrls.includes(normalizeUrl(url));
    } catch (error) {
        console.error("OpenPhish fetch error:", error);
        return false;
    }
}

async function checkPhishing(url) {
    if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
        return false;
    }

    let vtResult = await checkVirusTotal(url);
    let openPhishResult = await checkOpenPhish(url);
    return vtResult || openPhishResult;
}

// --- existing extension listeners (unchanged) ---
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        checkPhishing(tab.url).then(isPhishing => {
            if (isPhishing) {
                chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    function: showWarningBanner
                });

                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icons/icon48.png",
                    title: "⚠️ Phishing Alert",
                    message: "This site has been flagged as phishing!",
                    priority: 2
                });
            }
        });
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkPhishing") {
        checkPhishing(request.url).then(isPhishing => {
            sendResponse({ isPhishing: isPhishing });
            if (isPhishing && sender?.tab?.id) {
                chrome.scripting.executeScript({
                    target: { tabId: sender.tab.id },
                    function: showWarningBanner
                });
            }
        }).catch(error => {
            console.error("Error checking phishing:", error);
            sendResponse({ error: error.message });
        });
        return true;
    }
});

function showWarningBanner() {
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
