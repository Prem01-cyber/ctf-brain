// Service worker: the only component that talks to the aggregator. host_permissions
// for localhost:7331 let these fetches bypass page CORS. Fire-and-forget; failures
// (aggregator down) are logged but never affect browsing.

// Use 127.0.0.1 (not "localhost"): the aggregator binds IPv4, but browsers often
// resolve "localhost" to ::1 (IPv6) first, which would silently fail to connect.
const DEFAULT_AGG = "http://127.0.0.1:7331";

const LOG = "[ctf-brain bg]";

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
    const res = await fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    console.debug(`${LOG} POST ${base}${path} -> ${res.status}`);
  } catch (e) {
    console.warn(`${LOG} POST ${base}${path} FAILED:`, e.message);
  }
}

console.log(`${LOG} service worker started; aggregator = ${DEFAULT_AGG}`);

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || !msg.type) return;
  const from = sender.tab ? sender.tab.url : "?";
  if (msg.type === "snapshot") {
    console.debug(`${LOG} snapshot from ${from} url=${msg.data && msg.data.url}`);
    post("/browser", msg.data);
  } else if (msg.type === "flow") {
    console.debug(`${LOG} flow ${msg.data && msg.data.method} ${msg.data && msg.data.url} ` +
                  `(${msg.data && msg.data.status})`);
    post("/flow", msg.data);
  } else if (msg.type === "xhr") {
    post("/xhr", msg.data); // legacy
  }
});
