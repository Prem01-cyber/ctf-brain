"""Recon inventory — passive site map + parameter mining from observed traffic.

Pure helpers; the aggregator State accumulates the results across flows. Builds:
  - an endpoint tree (host/path → methods, statuses, params seen)
  - the set of all parameters (query + form/JSON body keys) — injection candidates
  - links/paths discovered inside HTML/JS bodies (passive crawl)
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

# Quoted absolute URLs and root-relative paths inside HTML/JS.
_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)["']"""
                      r"""|["'](/[A-Za-z0-9_\-./]{1,120})["']"""
                      r"""|(https?://[A-Za-z0-9_\-./?=&%:]{4,200})""")
_STATIC = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|map)(?:$|\?)", re.I)


def endpoint_key(url: str) -> tuple[str, str]:
    p = urllib.parse.urlsplit(url)
    return p.netloc, (p.path or "/")


def query_params(url: str) -> set[str]:
    p = urllib.parse.urlsplit(url)
    return set(urllib.parse.parse_qs(p.query).keys())


def body_params(body: str | None) -> set[str]:
    if not body:
        return set()
    body = body.strip()
    if body.startswith("{"):
        try:
            obj = json.loads(body)
            return set(map(str, obj.keys())) if isinstance(obj, dict) else set()
        except Exception:
            return set()
    if "=" in body and "\n" not in body[:200]:
        try:
            return set(urllib.parse.parse_qs(body).keys())
        except Exception:
            return set()
    return set()


def extract_links(body: str | None, limit: int = 200) -> set[str]:
    if not body:
        return set()
    out: set[str] = set()
    for m in _LINK_RE.finditer(body[:200_000]):
        link = m.group(1) or m.group(2) or m.group(3)
        if not link or _STATIC.search(link):
            continue
        if link.startswith(("data:", "javascript:", "#", "mailto:")):
            continue
        out.add(link[:200])
        if len(out) >= limit:
            break
    return out
