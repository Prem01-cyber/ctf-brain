"""mitmproxy addon — Burp-level proxy feed for ctf-brain.

Run it as an intercepting proxy in front of your browser; every request/response
(headers + bodies, TLS-decrypted) is POSTed to the aggregator's /flow endpoint,
where the detection engine scans it. This sees everything the in-browser hook
can't: top-level navigations, non-XHR resources, and JS-hidden headers like
Set-Cookie and the full CORS set.

Setup:
    pip install mitmproxy
    mitmdump -s proxy/ctf_addon.py --listen-host 127.0.0.1 --listen-port 8080
    # point your browser's HTTP/HTTPS proxy at 127.0.0.1:8080
    # install mitmproxy's CA: browse to http://mitm.it and follow the steps

Config via env: CTF_AGG_URL (default http://127.0.0.1:7331).
POSTs run on a background worker so the proxy event loop never blocks.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import urllib.parse
import urllib.request

AGG_URL = os.environ.get("CTF_AGG_URL", "http://127.0.0.1:7331")
MAX_BODY = 200_000
_TEXTY = ("json", "text", "html", "xml", "javascript", "x-www-form-urlencoded",
          "csv", "graphql")
# Don't feed the aggregator's own traffic or the mitmproxy onboarding host.
_SKIP_HOSTS = ("mitm.it",)


def _texty(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in _TEXTY)


class CtfBrain:
    def __init__(self) -> None:
        self._q: queue.Queue[dict] = queue.Queue(maxsize=2000)
        self._agg_host = urllib.parse.urlsplit(AGG_URL).netloc
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def _worker(self) -> None:
        while True:
            flow = self._q.get()
            try:
                data = json.dumps(flow).encode()
                req = urllib.request.Request(
                    f"{AGG_URL}/flow", data=data,
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                urllib.request.urlopen(req, timeout=5).close()
            except Exception:
                pass  # aggregator down — drop the flow
            finally:
                self._q.task_done()

    def response(self, flow) -> None:  # mitmproxy hook
        try:
            url = flow.request.pretty_url
            host = flow.request.host or ""
            if self._agg_host and self._agg_host in url:
                return
            if any(h in host for h in _SKIP_HOSTS):
                return

            req_ct = flow.request.headers.get("content-type", "")
            resp_ct = flow.response.headers.get("content-type", "")

            req_body = None
            if _texty(req_ct):
                try:
                    req_body = flow.request.get_text(strict=False)
                except Exception:
                    req_body = None
            resp_body = None
            if _texty(resp_ct):
                try:
                    resp_body = flow.response.get_text(strict=False)
                except Exception:
                    resp_body = None

            resp_headers = {k: v for k, v in flow.response.headers.items()}
            # Preserve all Set-Cookie values for the cookie-flag checks.
            cookies = flow.response.headers.get_all("Set-Cookie")
            if cookies:
                resp_headers["Set-Cookie"] = "\n".join(cookies)

            record = {
                "source": "mitmproxy",
                "method": flow.request.method,
                "url": url,
                "status": flow.response.status_code,
                "req_headers": {k: v for k, v in flow.request.headers.items()},
                "resp_headers": resp_headers,
                "req_body": req_body[:MAX_BODY] if req_body else None,
                "resp_body": resp_body[:MAX_BODY] if resp_body else None,
            }
            try:
                self._q.put_nowait(record)
            except queue.Full:
                pass
        except Exception:
            pass  # never break the proxy


addons = [CtfBrain()]
