// Isolated-world content script.
//  1. Periodically snapshots the visible page and sends it to the service worker.
//  2. Relays fetch/XHR events from inject.js (MAIN world) to the service worker.
// The service worker is what actually POSTs to localhost (host_permissions there
// bypass page CORS), so nothing here ever touches the network directly.
(function () {
  "use strict";

  const SNAPSHOT_INTERVAL_MS = 3000;

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

  // Relay request events from the MAIN-world hook.
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.source !== "ctfbrain-inject" || !d.payload) return;
    send({ type: "xhr", data: d.payload });
  });

  // Send a snapshot promptly, then on an interval. Skip when tab is hidden to
  // avoid spamming stale background tabs.
  function tick() {
    if (document.visibilityState === "visible") {
      send({ type: "snapshot", data: snapshot() });
    }
  }
  tick();
  setInterval(tick, SNAPSHOT_INTERVAL_MS);
  document.addEventListener("visibilitychange", tick);
})();
