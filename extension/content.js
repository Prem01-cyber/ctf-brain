// Isolated-world content script.
//  1. Periodically snapshots the visible page and sends it to the service worker.
//  2. Relays fetch/XHR events from inject.js (MAIN world) to the service worker.
// The service worker is what actually POSTs to localhost (host_permissions there
// bypass page CORS), so nothing here ever touches the network directly.
(function () {
  "use strict";

  const SNAPSHOT_INTERVAL_MS = 3000;
  const LOG = "[ctf-brain cs]";

  // Don't snapshot the ctf-brain UI itself — otherwise viewing the chat tab
  // would overwrite the target page's context with the aggregator's own URL.
  const AGG_HOSTS = ["127.0.0.1:7331", "localhost:7331"];
  let aggHostExtra = null;
  try {
    chrome.storage.local.get("aggUrl", ({ aggUrl }) => {
      if (aggUrl) {
        try {
          aggHostExtra = new URL(aggUrl).host;
        } catch (_) {
          /* ignore */
        }
      }
    });
  } catch (_) {
    /* extension context */
  }
  function isAggregator() {
    return AGG_HOSTS.includes(location.host) || location.host === aggHostExtra;
  }

  function snapshot() {
    let selected = "";
    try {
      selected = String(window.getSelection() || "");
    } catch (_) {
      /* some pages restrict this */
    }
    return {
      url: location.href,
      title: document.title,
      selected: selected.slice(0, 1500),
      bodyText: (document.body ? document.body.innerText : "").slice(0, 6000),
      cookies: document.cookie.slice(0, 2000),
      timestamp: Date.now(),
    };
  }

  function send(msg) {
    try {
      chrome.runtime.sendMessage(msg, () => void chrome.runtime.lastError);
    } catch (_) {
      // Extension context invalidated (reloaded) — stop quietly.
    }
  }

  // Relay HTTP flows from the MAIN-world hook — but never from the aggregator's
  // own UI tab (its /health & /status polling is not target traffic).
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (isAggregator()) return;
    const d = event.data;
    if (!d || d.source !== "ctfbrain-inject" || !d.payload) return;
    send({ type: "flow", data: d.payload });
  });

  // Send a snapshot promptly, then on an interval. Skip when tab is hidden to
  // avoid spamming stale background tabs.
  function tick() {
    if (isAggregator()) {
      return; // never report the ctf-brain UI tab itself
    }
    if (document.visibilityState !== "visible") {
      return; // only snapshot the foreground tab
    }
    const snap = snapshot();
    console.debug(`${LOG} sending snapshot for ${snap.url}`);
    send({ type: "snapshot", data: snap });
  }

  console.log(`${LOG} loaded on ${location.host} (aggregator tab: ${isAggregator()})`);
  tick();
  setInterval(tick, SNAPSHOT_INTERVAL_MS);
  document.addEventListener("visibilitychange", tick);
})();
