"""Detection engine — scans HTTP flows for CTF / web-enumeration signals.

Pure, dependency-free, and shared by every collector (browser extension, mitmproxy
addon). Given a flow dict, it returns a list of findings. Each finding carries a
stable ``key`` so the aggregator can dedupe repeats across thousands of requests.

A "flow" is a dict with any of:
    method, url, status, source,
    req_headers (dict), resp_headers (dict),
    req_body (str), resp_body (str)

Findings are intentionally tuned for *recall* (surface anything interesting) over
precision — they're hints for a human + LLM, not alerts. Severity lets the UI and
context renderer prioritize.
"""
from __future__ import annotations

import re
from typing import Any

from . import decoders

# Signature segment may be empty (alg=none tokens) — keep it optional.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")

# Cap how much body we regex-scan, to keep latency bounded on huge responses.
MAX_SCAN_CHARS = 200_000
_EVIDENCE_PAD = 60  # chars of context around a regex match


# CTF flags are handled separately (see _FLAG_RE) so we can reject code blocks.
# Each rule: (name, title, severity, category, compiled_regex)
# Scanned against URL + request body + response body unless noted.
_RULES: list[tuple[str, str, str, str, re.Pattern[str]]] = [
    ("private_key", "Private key", "high", "secret",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", "AWS access key id", "high", "secret",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", "Google API key", "high", "secret",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", "Slack token", "high", "secret",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github_token", "GitHub token", "high", "secret",
     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    # JWTs handled separately (see _scan_jwt) so we can decode + flag weaknesses.
    # Require a real :/= separator so prose like "password preferences" doesn't hit.
    ("secret_assignment", "Secret-looking assignment", "medium", "secret",
     re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|"
                r"auth[_-]?token)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+]{6,}")),
    ("sql_error", "SQL error (possible injection point)", "high", "error",
     re.compile(r"(?i)(SQL syntax|mysql_fetch|you have an error in your sql|"
                r"ORA-\d{5}|PostgreSQL.{0,20}ERROR|SQLite/JDBCDriver|"
                r"Unclosed quotation mark|quoted string not properly terminated|"
                r"Microsoft OLE DB Provider for SQL Server)")),
    ("stack_trace", "Stack trace / verbose error", "medium", "error",
     re.compile(r"(Traceback \(most recent call last\)|Fatal error:|"
                r"Warning: .{0,40} on line \d+|Exception in thread|"
                r"\bat [\w.$]+\([\w$]+\.java:\d+\)|System\.[\w.]+Exception)")),
    ("debug_page", "Framework debug page enabled", "high", "error",
     re.compile(r"(?i)(Whoops, looks like something went wrong|Werkzeug Debugger|"
                r"DEBUG\s*=\s*True|Symfony.{0,40}Exception|"
                r"Whitelabel Error Page|Rails\.application)")),
    ("dir_listing", "Directory listing", "medium", "disclosure",
     re.compile(r"(?i)<title>\s*Index of /")),
    ("private_ip", "Internal IP address", "low", "disclosure",
     re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
                r"\.\d{1,3}\.\d{1,3}\b")),
    ("email", "Email address", "info", "pii",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]

# URL-path rules — interesting endpoints worth probing.
_URL_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("exposed_vcs", "Exposed VCS/metadata", "high",
     re.compile(r"/\.(?:git|svn|hg|bzr)(?:/|$)|/\.git/config|/\.DS_Store")),
    ("exposed_env", "Exposed config/secrets file", "high",
     re.compile(r"/\.env\b|/\.htpasswd|/\.htaccess|/web\.config|/id_rsa\b|"
                r"/\.aws/|/config\.(?:php|json|yml|yaml)\b|/wp-config\.php")),
    ("backup_file", "Backup/old file", "medium",
     re.compile(r"\.(?:bak|old|orig|save|swp|tar|tar\.gz|tgz|zip|sql|dump)(?:$|\?)")),
    ("admin_panel", "Admin / management endpoint", "medium",
     re.compile(r"(?i)/(?:admin|administrator|wp-admin|phpmyadmin|manager/html|"
                r"server-status|actuator(?:/|$)|console)\b")),
    ("api_docs", "API surface / docs", "low",
     re.compile(r"(?i)/(?:swagger|api-docs|openapi\.json|graphql|graphiql|"
                r"\.well-known/|api/v\d)")),
    ("info_leak_file", "Info-leak file", "medium",
     re.compile(r"(?i)/(?:phpinfo\.php|info\.php|robots\.txt|sitemap\.xml|"
                r"crossdomain\.xml|\.well-known/security\.txt)")),
]


# Flag detection: label{body}. We reject labels that are code keywords so
# minified JS (`try{...}`, `else{...}`) doesn't masquerade as flags, and require
# the body to be free of spaces/colons/semicolons (rules out CSS and JS objects).
_FLAG_RE = re.compile(r"\b([A-Za-z0-9_]{2,20})\{([^}\n;:\s]{3,200})\}")
_FLAG_LABEL_BLOCK = frozenset({
    "try", "else", "do", "finally", "return", "in", "of", "new", "void", "case",
    "typeof", "delete", "yield", "await", "with", "function", "if", "for", "while",
    "switch", "catch", "var", "let", "const", "class", "enum", "struct", "default",
})


def _scan_jwt(text: str, where: str, flow: dict[str, Any], out: list[dict[str, Any]]) -> None:
    if not text:
        return
    for m in _JWT_RE.finditer(text[:MAX_SCAN_CHARS]):
        token = m.group(0)
        decoded = decoders.decode_jwt(token)
        if not decoded:
            continue
        sev = "high" if any("alg=none" in i for i in decoded["issues"]) else "medium"
        ev = f"alg={decoded['header'].get('alg')} payload={decoded['payload']}"
        if decoded["issues"]:
            ev += " | " + "; ".join(decoded["issues"])
        out.append(_finding(sev, "secret", "jwt", "JWT (decoded)", ev[:300], where, flow))
        return  # one per field


def _scan_flags(text: str, where: str, flow: dict[str, Any], out: list[dict[str, Any]]) -> None:
    if not text:
        return
    for m in _FLAG_RE.finditer(text[:MAX_SCAN_CHARS]):
        if m.group(1).lower() in _FLAG_LABEL_BLOCK:
            continue
        out.append(_finding("high", "flag", "flag", "CTF flag pattern",
                            _evidence(text, m), where, flow))
        return  # one flag finding per field is enough


def _evidence(text: str, m: re.Match[str]) -> str:
    start = max(0, m.start() - _EVIDENCE_PAD)
    end = min(len(text), m.end() + _EVIDENCE_PAD)
    snippet = text[start:end].replace("\n", " ").strip()
    return (("…" if start else "") + snippet + ("…" if end < len(text) else ""))[:200]


def _finding(severity, category, rule, title, evidence, where, flow,
             dedup_url: bool = True) -> dict[str, Any]:
    url = flow.get("url", "")
    f = {
        "severity": severity,
        "category": category,
        "rule": rule,
        "title": title,
        "evidence": evidence,
        "where": where,
        "url": url,
        "method": flow.get("method", ""),
        "source": flow.get("source", ""),
    }
    # Dedupe identical hits across repeated requests. Header/tech findings dedupe
    # by value only (one "Server: ESF" total, not one per endpoint).
    path = url.split("?")[0] if dedup_url else ""
    f["key"] = f"{rule}|{where}|{evidence[:80]}|{path}"
    return f


def _scan_text(text: str, where: str, flow: dict[str, Any], out: list[dict[str, Any]]) -> None:
    if not text:
        return
    text = text[:MAX_SCAN_CHARS]
    for name, title, sev, cat, rx in _RULES:
        m = rx.search(text)
        if m:
            out.append(_finding(sev, cat, name, title, _evidence(text, m), where, flow))


def _scan_headers(headers: dict[str, str], side: str, flow: dict[str, Any],
                  out: list[dict[str, Any]]) -> None:
    if not headers:
        return
    lower = {k.lower(): v for k, v in headers.items()}
    url = flow.get("url", "")
    is_https = url.startswith("https://")

    # Version / tech disclosure.
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime"):
        if h in lower and lower[h].strip():
            out.append(_finding("info", "disclosure", f"header_{h.replace('-', '_')}",
                                f"Tech disclosure ({h})", f"{h}: {lower[h]}",
                                f"{side}_header:{h}", flow, dedup_url=False))

    # CORS misconfiguration.
    if side == "resp":
        acao = lower.get("access-control-allow-origin")
        acac = lower.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            out.append(_finding("high", "misconfig", "cors_wildcard_creds",
                                "CORS: wildcard origin with credentials",
                                "ACAO:* + ACAC:true", "resp_header:cors", flow))
        elif acao and acao not in ("*", url):
            out.append(_finding("low", "misconfig", "cors_reflected",
                                "CORS: reflected/permissive origin",
                                f"ACAO: {acao}", "resp_header:cors", flow, dedup_url=False))

        # Insecure cookies (dedupe by cookie name, not endpoint).
        setc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
        if setc:
            flags = setc.lower()
            name = setc.split("=")[0][:60]
            if "httponly" not in flags:
                out.append(_finding("low", "misconfig", "cookie_no_httponly",
                                    "Cookie without HttpOnly", name,
                                    "resp_header:set-cookie", flow, dedup_url=False))
            if is_https and "secure" not in flags:
                out.append(_finding("low", "misconfig", "cookie_no_secure",
                                    "Cookie without Secure (HTTPS)", name,
                                    "resp_header:set-cookie", flow, dedup_url=False))


def scan_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings for a single HTTP flow (deduped by caller via finding['key'])."""
    out: list[dict[str, Any]] = []
    url = flow.get("url", "") or ""

    # URL-path endpoint rules.
    for name, title, sev, rx in _URL_RULES:
        m = rx.search(url)
        if m:
            out.append(_finding(sev, "endpoint", name, title, _evidence(url, m), "url", flow))

    # Content rules over URL, request body, response body.
    req_body = flow.get("req_body", "") or ""
    resp_body = flow.get("resp_body", "") or ""
    _scan_text(url, "url", flow, out)
    _scan_text(req_body, "req_body", flow, out)
    _scan_text(resp_body, "resp_body", flow, out)

    # Flags (dedicated matcher that rejects code-block labels).
    _scan_flags(url, "url", flow, out)
    _scan_flags(req_body, "req_body", flow, out)
    _scan_flags(resp_body, "resp_body", flow, out)

    # JWTs — decode + flag weaknesses.
    _scan_jwt(url, "url", flow, out)
    _scan_jwt(req_body, "req_body", flow, out)
    _scan_jwt(resp_body, "resp_body", flow, out)
    for side in ("req_headers", "resp_headers"):
        auth = (flow.get(side) or {}).get("Authorization") or (flow.get(side) or {}).get("authorization")
        if auth:
            _scan_jwt(auth, f"{side}:authorization", flow, out)

    # Header rules.
    _scan_headers(flow.get("req_headers") or {}, "req", flow, out)
    _scan_headers(flow.get("resp_headers") or {}, "resp", flow, out)

    return out


_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def severity_rank(severity: str) -> int:
    return _SEV_ORDER.get(severity, 9)
