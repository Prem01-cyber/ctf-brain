// Service worker: the only component that talks to the aggregator. host_permissions
// for localhost:7331 let these fetches bypass page CORS. Fire-and-forget; failures
// (aggregator down) are swallowed so browsing is never affected.

const DEFAULT_AGG = "http://localhost:7331";

async function aggUrl() {
  try {
    const { aggUrl } = await chrome.storage.local.get("aggUrl");
    return aggUrl || DEFAULT_AGG;
  } catch (_) {
    return DEFAULT_AGG;
  }
}

async function post(path, body) {
  const base = await aggUrl();
  try {
    await fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (_) {
    // Aggregator not running — ignore.
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return;
  if (msg.type === "snapshot") {
    post("/browser", msg.data);
  } else if (msg.type === "xhr") {
    post("/xhr", msg.data);
  }
  // No async response needed.
});
