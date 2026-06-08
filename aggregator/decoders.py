"""Decoding helpers — JWTs and a CyberChef-"magic"-style multi-decoder.

We don't reinvent crypto: JWTs go through PyJWT, and the magic decoder chains
Python's stdlib codecs (base64/base32/hex/url/rot13/gzip/zlib). It tries each
transform, keeps the ones that yield mostly-printable output, and recurses a
couple levels — surfacing the readable result (and flagging it if it contains a
flag).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import urllib.parse
import zlib
from typing import Any

import jwt as pyjwt

_FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[^}\n;:\s]{3,200}\}")


# --- JWT -------------------------------------------------------------------
def decode_jwt(token: str) -> dict[str, Any] | None:
    """Decode a JWT without verifying the signature; flag common weaknesses."""
    token = token.strip()
    try:
        header = pyjwt.get_unverified_header(token)
        payload = pyjwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None

    issues: list[str] = []
    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        issues.append("alg=none — signature not enforced; forge claims freely")
    elif alg.startswith("hs"):
        issues.append(f"{header.get('alg')} (HMAC) — crackable if the secret is weak "
                      "(try jwt_tool / hashcat mode 16500)")
    if "exp" not in payload:
        issues.append("no 'exp' claim — token may never expire")
    for claim in ("admin", "role", "is_admin", "isAdmin", "user", "sub"):
        if claim in payload:
            issues.append(f"claim '{claim}'={payload[claim]!r} — candidate to tamper")
    return {"header": header, "payload": payload, "issues": issues}


# --- magic multi-decoder ---------------------------------------------------
def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126)
    return printable / len(b)


def _try(name: str, fn) -> tuple[str, str] | None:
    try:
        out = fn()
    except Exception:
        return None
    if isinstance(out, bytes):
        if _printable_ratio(out) < 0.85:
            return None
        out = out.decode("utf-8", "replace")
    out = out.strip()
    return (name, out) if out else None


def _transforms(s: str) -> list[tuple[str, str]]:
    res: list[tuple[str, str]] = []
    compact = re.sub(r"\s+", "", s)

    def b64(x):
        return base64.b64decode(x + "=" * (-len(x) % 4))

    def b64url(x):
        return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

    candidates = [
        ("base64", lambda: b64(compact)) if re.fullmatch(r"[A-Za-z0-9+/=]{4,}", compact) else None,
        ("base64url", lambda: b64url(compact)) if re.fullmatch(r"[A-Za-z0-9\-_=]{4,}", compact) else None,
        ("base32", lambda: base64.b32decode(compact + "=" * (-len(compact) % 8)))
        if re.fullmatch(r"[A-Z2-7=]{8,}", compact) else None,
        ("hex", lambda: binascii.unhexlify(compact)) if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", compact) else None,
        ("url", lambda: urllib.parse.unquote(s)) if "%" in s else None,
        ("rot13", lambda: codecs.decode(s, "rot13")) if s.isascii() else None,
        ("gzip", lambda: gzip.decompress(b64(compact))) if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", compact) else None,
        ("zlib", lambda: zlib.decompress(b64(compact))) if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", compact) else None,
    ]
    seen = set()
    for c in candidates:
        if not c:
            continue
        r = _try(*c)
        if r and r[1] != s and r[1] not in seen:
            seen.add(r[1])
            res.append(r)
    return res


def magic(text: str, depth: int = 2) -> list[dict[str, Any]]:
    """Return candidate decodings, best-effort, recursing up to `depth` levels."""
    text = (text or "").strip()
    if not text or len(text) > 100_000:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = {text}

    def walk(s: str, recipe: list[str], level: int) -> None:
        if level > depth:
            return
        for name, decoded in _transforms(s):
            if decoded in seen:
                continue
            seen.add(decoded)
            chain = recipe + [name]
            entry = {"recipe": " → ".join(chain), "output": decoded[:2000],
                     "flag": bool(_FLAG_RE.search(decoded))}
            out.append(entry)
            walk(decoded, chain, level + 1)

    walk(text, [], 1)
    # Flag-bearing results first, then by recipe length (simpler decodings first).
    out.sort(key=lambda e: (not e["flag"], e["recipe"].count("→")))
    return out[:12]
