"""Vulnerability intelligence — map discovered software + version to known CVEs.

Strategy (precise + always current, no multi-GB bundle):
  - **NVD API** queried live by product+version, results cached to disk.
  - **CISA KEV** ("known exploited vulnerabilities") catalog downloaded in full
    (~1.5MB) and auto-refreshed; CVEs that appear there are confirmed
    exploited-in-the-wild and carry remediation guidance.

Results are merged: NVD gives version-matched coverage + CVSS; KEV flags the ones
actually being exploited (the highest-value targets) and adds the required action.
Network failures degrade gracefully to whatever is cached on disk.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import httpx

from . import config

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_kev_by_cve: dict[str, dict[str, Any]] = {}
_kev_loaded_at: float = 0.0


# --- CISA KEV --------------------------------------------------------------
def _kev_path() -> str:
    return os.path.join(config.VULN_DIR, "kev.json")


def _index_kev(data: dict[str, Any]) -> None:
    global _kev_by_cve
    idx = {}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            idx[cid.upper()] = v
    _kev_by_cve = idx


def load_kev_from_disk() -> bool:
    try:
        with open(_kev_path()) as f:
            _index_kev(json.load(f))
        return True
    except (OSError, ValueError):
        return False


async def refresh_kev(force: bool = False) -> int:
    """Download the KEV catalog if stale; return entry count. Falls back to disk."""
    global _kev_loaded_at
    path = _kev_path()
    fresh = os.path.exists(path) and \
        (time.time() - os.path.getmtime(path)) < config.KEV_REFRESH_HOURS * 3600
    if fresh and not force:
        if not _kev_by_cve:
            load_kev_from_disk()
        return len(_kev_by_cve)
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(KEV_URL)
            r.raise_for_status()
            data = r.json()
        os.makedirs(config.VULN_DIR, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)
        _index_kev(data)
        _kev_loaded_at = time.time()
    except Exception:
        load_kev_from_disk()  # use stale cache if the download fails
    return len(_kev_by_cve)


# --- NVD --------------------------------------------------------------------
def _nvd_cache_path(product: str, version: str) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in f"{product}_{version}".lower())[:80]
    return os.path.join(config.VULN_DIR, f"nvd_{safe}.json")


def _parse_nvd(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        score, sev = None, ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                data = metrics[key][0].get("cvssData", {})
                score = data.get("baseScore")
                sev = data.get("baseSeverity") or metrics[key][0].get("baseSeverity", "")
                break
        refs = [r.get("url") for r in cve.get("references", [])][:4]
        out.append({"id": cve.get("id"), "summary": desc[:400], "cvss": score,
                    "severity": (sev or "").upper(), "refs": refs})
    out.sort(key=lambda c: (c["cvss"] or 0), reverse=True)
    return out


# Tokens in a service banner that hurt NVD keyword matching (it ANDs all words).
_NOISE = {"httpd", "server", "unix", "linux", "ubuntu", "debian", "win32", "win64",
          "protocol", "daemon", "ssh", "ftpd", "smtpd", "or", "later"}
_VER_RE = re.compile(r"\d+\.[\w.\-]+")


def _keyword_candidates(banner: str, version: str) -> list[str]:
    """Ordered NVD keyword queries to try — raw banner, denoised, then product+version.
    NVD requires every word to appear, so 'Apache httpd 2.4.49' matches nothing while
    'Apache 2.4.49' matches."""
    banner = banner.strip()
    base = f"{banner} {version}".strip()
    cands = [base]
    words = [w for w in re.split(r"[\s()/,]+", base) if w]
    denoised = " ".join(w for w in words if w.lower() not in _NOISE)
    if denoised and denoised != base:
        cands.append(denoised)
    ver = _VER_RE.search(base)
    product = next((w for w in words if any(ch.isalpha() for ch in w)
                    and w.lower() not in _NOISE), "")
    if ver and product:
        cands.append(f"{product} {ver.group(0)}")
    return list(dict.fromkeys(c for c in cands if c))[:3]


async def nvd_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Query NVD for a product+version, caching results to disk. Tries normalized
    keyword variants until one matches."""
    path = _nvd_cache_path(product, version)
    if os.path.exists(path) and \
            (time.time() - os.path.getmtime(path)) < config.NVD_CACHE_DAYS * 86400:
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError):
            pass
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    cves: list[dict[str, Any]] = []
    got_response = False
    try:
        async with httpx.AsyncClient(timeout=25) as c:
            for kw in _keyword_candidates(product, version):
                r = await c.get(NVD_URL, headers=headers,
                                params={"keywordSearch": kw, "resultsPerPage": 30})
                r.raise_for_status()
                got_response = True
                cves = _parse_nvd(r.json())
                if cves:
                    break
    except Exception:
        if not got_response:
            return []  # network/rate-limit; don't cache, retry later
    os.makedirs(config.VULN_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump(cves, f)
    return cves


# --- combined lookup --------------------------------------------------------
async def lookup(product: str, version: str = "") -> dict[str, Any]:
    """Version -> CVEs, annotated with KEV (exploited-in-wild) status + action."""
    if not _kev_by_cve:
        load_kev_from_disk()
    cves = await nvd_lookup(product, version)
    for c in cves:
        kev = _kev_by_cve.get((c.get("id") or "").upper())
        if kev:
            c["kev"] = True
            c["exploit"] = kev.get("requiredAction") or kev.get("shortDescription", "")
            c["ransomware"] = kev.get("knownRansomwareCampaignUse") == "Known"
        else:
            c["kev"] = False
    # KEV-first, then CVSS.
    cves.sort(key=lambda c: (not c.get("kev"), -(c.get("cvss") or 0)))
    return {"product": product, "version": version, "checked_at": time.time(),
            "cves": cves[:15], "kev_count": sum(1 for c in cves if c.get("kev"))}


def stats() -> dict[str, Any]:
    return {"kev_entries": len(_kev_by_cve),
            "nvd_cached": len([f for f in os.listdir(config.VULN_DIR)
                               if f.startswith("nvd_")]) if os.path.isdir(config.VULN_DIR) else 0}
