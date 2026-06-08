// Runs in the page's MAIN world (document_start) so it can wrap the page's own
// fetch / XMLHttpRequest and read request + response BODIES (which webRequest in
// MV3 can't). It forwards a compact flow record to the isolated content script
// via window.postMessage, which relays it to the service worker → aggregator
// /flow, where the detection engine scans it.
(function () {
  "use strict";

  if (window.__ctfbrainHooked) return;
  window.__ctfbrainHooked = true;

  const MAX_BODY = 65536; // cap body capture to keep messaging light
  const TEXTY = /(json|text|html|xml|javascript|x-www-form-urlencoded|csv|graphql)/i;
  // Only CORS-safelisted response headers are readable from page JS; attempting
  // others (Server, X-Powered-By, CORS, Set-Cookie…) just logs "Refused to get
  // unsafe header". For full header coverage use the mitmproxy addon.
  const HDRS = ["content-type"];

  function clip(s) {
    return typeof s === "string" ? s.slice(0, MAX_BODY) : undefined;
  }

  function emit(flow) {
    try {
      if (String(flow.url || "").includes(":7331/")) return; // skip aggregator
      window.postMessage({ source: "ctfbrain-inject", payload: flow }, "*");
    } catch (_) {
      /* ignore */
    }
  }

  function pickHeaders(getter) {
    const out = {};
    for (const h of HDRS) {
      try {
        const v = getter(h);
        if (v) out[h] = v;
      } catch (_) {
        /* ignore */
      }
    }
    return out;
  }

  // --- fetch ---
  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (...args) {
      const input = args[0];
      const init = args[1] || {};
      const url = typeof input === "string" ? input : input && input.url;
      const method = (init.method || (input && input.method) || "GET").toUpperCase();
      const reqBody = typeof init.body === "string" ? init.body : undefined;
      const p = origFetch.apply(this, args);
      p.then(
        async (res) => {
          let respBody;
          const ct = res.headers.get("content-type") || "";
          if (TEXTY.test(ct)) {
            try {
              respBody = clip(await res.clone().text());
            } catch (_) {
              /* body already consumed / opaque */
            }
          }
          emit({
            source: "browser", method, url, status: res.status,
            req_body: clip(reqBody),
            resp_body: respBody,
            resp_headers: pickHeaders((h) => res.headers.get(h)),
            t: Date.now(),
          });
        },
        () => emit({ source: "browser", method, url, status: "error", t: Date.now() })
      );
      return p;
    };
  }

  // --- XMLHttpRequest ---
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__ctf = { method: String(method || "GET").toUpperCase(), url };
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    const info = this.__ctf;
    if (info) {
      const reqBody = typeof body === "string" ? body : undefined;
      this.addEventListener("loadend", () => {
        let respBody;
        const ct = this.getResponseHeader("content-type") || "";
        if (TEXTY.test(ct) && (this.responseType === "" || this.responseType === "text")) {
          try {
            respBody = clip(this.responseText);
          } catch (_) {
            /* ignore */
          }
        }
        emit({
          source: "browser", method: info.method, url: info.url, status: this.status,
          req_body: clip(reqBody),
          resp_body: respBody,
          resp_headers: pickHeaders((h) => this.getResponseHeader(h)),
          t: Date.now(),
        });
      });
    }
    return origSend.apply(this, arguments);
  };
})();
