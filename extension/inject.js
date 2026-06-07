// Runs in the page's MAIN world (document_start) so it can wrap the page's own
// fetch / XMLHttpRequest. It can't talk to localhost itself (and shouldn't —
// that would taint the page), so it forwards request metadata to the isolated
// content script via window.postMessage, which relays to the service worker.
(function () {
  "use strict";

  // Avoid double-install if injected twice.
  if (window.__ctfbrainHooked) return;
  window.__ctfbrainHooked = true;

  function report(method, url, status) {
    try {
      const u = String(url || "");
      // Don't report the collector's own traffic.
      if (u.includes(":7331/")) return;
      window.postMessage(
        {
          source: "ctfbrain-inject",
          payload: {
            method: String(method || "GET").toUpperCase(),
            url: u.slice(0, 500),
            status: status ?? null,
            t: Date.now(),
          },
        },
        "*"
      );
    } catch (_) {
      /* ignore */
    }
  }

  // --- fetch ---
  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (...args) {
      const input = args[0];
      const url = typeof input === "string" ? input : input && input.url;
      const method =
        (args[1] && args[1].method) ||
        (input && typeof input === "object" && input.method) ||
        "GET";
      const p = origFetch.apply(this, args);
      p.then(
        (res) => report(method, url, res && res.status),
        () => report(method, url, "error")
      );
      return p;
    };
  }

  // --- XMLHttpRequest ---
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__ctf = { method, url };
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    const info = this.__ctf;
    if (info) {
      this.addEventListener("loadend", () =>
        report(info.method, info.url, this.status)
      );
    }
    return origSend.apply(this, arguments);
  };
})();
