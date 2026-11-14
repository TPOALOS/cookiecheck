#!/usr/bin/env python3
"""cookiecheck: offline lint of Set-Cookie header lines.

Reads Set-Cookie lines from arguments, files, stdin, a pasted HTTP response or
a HAR file, parses the attributes and reports risky or invalid settings.
It never makes a network request and never executes anything it reads.

Exit codes: 0 clean, 1 findings, 2 usage or input error.
"""
import argparse
import base64
import binascii
import datetime
import json
import os
import re
import stat
import sys
from email.utils import parsedate_to_datetime
from urllib.parse import unquote

VERSION = "1.0.0"
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_COOKIES = 5000
MAX_COOKIE_BYTES = 4096        # name + value limit used by browsers
MAX_ATTR_VALUE = 1024
LONG_LIFETIME_DAYS = 400       # cap applied by current browsers
SESSION_LIFETIME_DAYS = 30

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3}

KNOWN_ATTRS = {"expires", "max-age", "domain", "path", "secure", "httponly",
               "samesite", "priority", "partitioned"}
FLAG_ATTRS = {"secure", "httponly", "partitioned"}

TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
SESSION_RE = re.compile(
    r"(sess|sid$|^sid|session|auth|token|jwt|login|logon|credential|"
    r"remember|access|refresh|csrf|xsrf|userid|user_id|identity|sso)", re.I)
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$")
CTRL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
PUBLIC_SUFFIXES = {
    "com", "org", "net", "edu", "gov", "io", "co", "uk", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "de", "fr", "nl", "ru", "cn", "jp", "br", "com.br",
    "com.au", "net.au", "org.au", "co.jp", "co.nz", "co.in", "co.za", "app",
    "dev", "xyz", "info", "biz", "me", "us", "eu", "ca", "in", "github.io",
    "herokuapp.com", "azurewebsites.net", "appspot.com", "cloudfront.net",
    "test", "example", "localhost",
}


def clean(s, limit=80):
    """Make hostile text safe to print on one line."""
    s = "".join(ch if (ch.isprintable() and ch not in "\r\n") else "?" for ch in s)
    return s if len(s) <= limit else s[:limit - 3] + "..."


def mask_value(v):
    if v == "":
        return "(empty)"
    shown = clean(v[:4], 4)
    return "%s... (%d chars)" % (shown, len(v)) if len(v) > 4 else "%s (%d chars)" % (shown, len(v))


class Finding(object):
    def __init__(self, code, severity, message):
        self.code, self.severity, self.message = code, severity, message

    def to_dict(self):
        return {"code": self.code, "severity": self.severity, "message": self.message}


class Cookie(object):
    def __init__(self, raw, source):
        self.raw = raw
        self.source = source
        self.name = ""
        self.value = ""
        self.attrs = []          # list of (lowercase name, value or None)
        self.findings = []
        self.parse_ok = True

    def attr(self, name):
        for k, v in self.attrs:
            if k == name:
                return True if v is None else v
        return None

    def has(self, name):
        return any(k == name for k, _ in self.attrs)

    def add(self, code, sev, msg):
        self.findings.append(Finding(code, sev, msg))


def parse_cookie(raw, source="arg"):
    c = Cookie(raw, source)
    text = raw.strip()
    parts = text.split(";")
    first = parts[0]
    if "=" in first:
        name, value = first.split("=", 1)
    else:
        name, value = "", first
        c.parse_ok = False
    c.name = name.strip()
    c.value = value.strip()
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            c.attrs.append((k.strip().lower(), v.strip()))
        else:
            c.attrs.append((part.lower(), None))
    return c


def parse_expiry(value):
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def b64_json(value):
    """Return True if the value is base64 text that decodes to a JSON object/array."""
    v = unquote(value)
    if len(v) < 8 or not re.match(r"^[A-Za-z0-9+/_\-=]+$", v):
        return False
    pad = v + "=" * (-len(v) % 4)
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = dec(pad)
            txt = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        t = txt.strip()
        if t[:1] in "{[":
            try:
                json.loads(t)
                return True
            except ValueError:
                pass
    return False


def lint(c, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    raw = c.raw
    name = c.name
    low = name.lower()
    add = c.add

    if CTRL_RE.search(raw):
        add("control-chars", "high", "header line contains control characters (possible header injection)")
    if any(ord(ch) > 126 for ch in raw):
        add("non-ascii", "low", "non-ASCII characters in the cookie line; behaviour differs between browsers")
    if not c.parse_ok:
        add("no-name", "high", "no name=value pair at the start; browsers may ignore or misread this cookie")
    elif name == "":
        add("empty-name", "medium", "empty cookie name")
    elif not TOKEN_RE.match(name):
        add("bad-name", "medium", "cookie name contains characters outside the RFC 6265 token set")
    if re.search(r'[\s",\\]', c.value.strip('"')):
        add("bad-value", "low", "value contains whitespace, comma, quote or backslash; encode it")
    if len(name.encode("utf-8", "replace")) + len(c.value.encode("utf-8", "replace")) > MAX_COOKIE_BYTES:
        add("oversize", "high", "name+value exceeds %d bytes; browsers drop it" % MAX_COOKIE_BYTES)
    elif len(raw.encode("utf-8", "replace")) > MAX_COOKIE_BYTES:
        add("oversize-line", "medium", "whole cookie line exceeds %d bytes" % MAX_COOKIE_BYTES)

    # attribute hygiene
    seen = {}
    for k, v in c.attrs:
        seen[k] = seen.get(k, 0) + 1
        if k not in KNOWN_ATTRS:
            add("unknown-attr", "low", "unknown attribute %r is ignored by browsers" % clean(k, 30))
        elif k in FLAG_ATTRS and v not in (None, ""):
            add("flag-with-value", "low", "%s takes no value (got %r)" % (k, clean(v, 20)))
        elif k not in FLAG_ATTRS and v is None:
            add("attr-no-value", "low", "attribute %s has no value" % k)
        if v and len(v) > MAX_ATTR_VALUE:
            add("attr-too-long", "medium", "attribute %s value exceeds %d bytes" % (k, MAX_ATTR_VALUE))
    for k, n in sorted(seen.items()):
        if n > 1:
            add("duplicate-attr", "medium", "attribute %s appears %d times; browsers differ on which wins" % (k, n))

    # deletion cookies get only structural checks
    deleting = False
    ma = c.attr("max-age")
    ma_int = None
    if ma is not None:
        if isinstance(ma, str) and re.match(r"^-?\d+$", ma):
            ma_int = int(ma)
            if ma_int <= 0:
                deleting = True
        else:
            add("bad-max-age", "medium", "Max-Age is not an integer (%r); it will be ignored" % clean(str(ma), 20))
    exp = c.attr("expires")
    exp_dt = None
    if exp is not None:
        exp_dt = parse_expiry(exp) if isinstance(exp, str) else None
        if exp_dt is None:
            add("bad-expires", "medium", "Expires is not a valid HTTP date (%r)" % clean(str(exp), 40))
        elif exp_dt <= now and ma_int is None:
            deleting = True
    if deleting:
        add("deletion", "info", "cookie is being deleted (Max-Age<=0 or Expires in the past); protection checks skipped")
        _prefix_checks(c, low)
        return

    session_like = bool(SESSION_RE.search(name)) and bool(name)
    is_jwt = bool(JWT_RE.match(unquote(c.value)))
    secure = c.has("secure")
    httponly = c.has("httponly")
    samesite = c.attr("samesite")
    sensitive = session_like or is_jwt

    if not secure:
        add("missing-secure", "high" if sensitive else "medium",
            "no Secure flag: the cookie is also sent over plain http")
    if not httponly:
        add("missing-httponly", "high" if sensitive else "medium",
            "no HttpOnly flag: page scripts (and XSS) can read it")
    if samesite is None:
        add("missing-samesite", "medium" if sensitive else "low",
            "no SameSite attribute: browser default applies (Lax in modern browsers, none in old ones)")
    elif not isinstance(samesite, str) or samesite.lower() not in ("strict", "lax", "none"):
        add("bad-samesite", "medium", "SameSite=%r is not Strict, Lax or None" % clean(str(samesite), 20))
    elif samesite.lower() == "none":
        if not secure:
            add("samesite-none-insecure", "high", "SameSite=None without Secure is rejected by modern browsers")
        else:
            add("samesite-none", "info", "SameSite=None allows cross-site sending; make sure that is intended")
    if session_like and not (secure and httponly):
        add("session-unprotected", "high",
            "name looks like a session/auth cookie but lacks %s" %
            " and ".join(x for x, ok in (("Secure", secure), ("HttpOnly", httponly)) if not ok))
    if c.has("partitioned") and not secure:
        add("partitioned-insecure", "medium", "Partitioned requires Secure")

    _prefix_checks(c, low)

    # domain
    dom = c.attr("domain")
    if dom is not None:
        d = dom.strip().lstrip(".").lower() if isinstance(dom, str) else ""
        if d == "":
            add("empty-domain", "low", "empty Domain attribute is ignored")
        elif d in PUBLIC_SUFFIXES or "." not in d:
            add("broad-domain", "high", "Domain=%s is a public suffix or single label; browsers reject it or it spans unrelated sites" % clean(d, 40))
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
            add("ip-domain", "medium", "Domain is an IP address; Domain only works for host names")
        elif d.count(".") == 1 and sensitive:
            add("wide-domain", "medium", "session-like cookie shared with every subdomain of %s" % clean(d, 40))
        elif sensitive:
            add("domain-subdomains", "low", "Domain attribute makes the cookie visible to all subdomains; omit it to bind to the exact host")
        if isinstance(dom, str) and dom.startswith("."):
            add("leading-dot", "info", "leading dot in Domain is ignored by modern browsers")

    # lifetime
    days = None
    if ma_int is not None:
        days = ma_int / 86400.0
    elif exp_dt is not None:
        days = (exp_dt - now).total_seconds() / 86400.0
    if days is not None:
        if days > LONG_LIFETIME_DAYS:
            add("long-lifetime", "medium", "lifetime of about %d days exceeds the %d-day cap browsers apply" % (days, LONG_LIFETIME_DAYS))
        elif sensitive and days > SESSION_LIFETIME_DAYS:
            add("long-session", "low", "session-like cookie lives about %d days" % days)

    # path
    path = c.attr("path")
    if path is not None:
        if not isinstance(path, str) or path == "":
            add("empty-path", "low", "empty Path attribute is ignored; default path applies")
        else:
            if not path.startswith("/"):
                add("bad-path", "medium", "Path=%r does not start with '/'; it is ignored" % clean(path, 40))
            if ".." in path.split("/"):
                add("path-traversal", "medium", "Path contains '..' segments")
            if re.search(r"\s", path):
                add("path-space", "low", "Path contains whitespace")
            if sensitive and path != "/":
                add("narrow-path", "info", "Path=%s is not a security boundary: other paths on the same host can still read or overwrite it" % clean(path, 40))

    # values
    val = unquote(c.value)
    if is_jwt and not httponly:
        add("jwt-readable", "high", "value looks like a JWT and the cookie lacks HttpOnly: scripts can steal the token")
    elif is_jwt:
        add("jwt-in-cookie", "info", "value looks like a JWT; check it is short-lived and verified server-side")
    elif val[:1] in "{[" and _is_json(val):
        add("unsigned-json", "high" if not httponly else "medium",
            "value is plain JSON user data with no visible signature; clients can tamper with it")
    elif b64_json(c.value):
        add("base64-json", "high" if not httponly else "medium",
            "value is base64-encoded JSON with no visible signature; clients can tamper with it")


def _is_json(text):
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


def _prefix_checks(c, low):
    name = c.name
    if low.startswith("__host-"):
        if name[:7] != "__Host-":
            c.add("prefix-case", "low", "prefix written with different letter case; some browsers do not enforce it")
        if not c.has("secure"):
            c.add("host-prefix-secure", "high", "__Host- cookie must have Secure; browsers will reject it")
        if c.attr("path") != "/":
            c.add("host-prefix-path", "high", "__Host- cookie must have Path=/; browsers will reject it")
        if c.has("domain"):
            c.add("host-prefix-domain", "high", "__Host- cookie must not have a Domain attribute; browsers will reject it")
    elif low.startswith("__secure-"):
        if name[:9] != "__Secure-":
            c.add("prefix-case", "low", "prefix written with different letter case; some browsers do not enforce it")
        if not c.has("secure"):
            c.add("secure-prefix-secure", "high", "__Secure- cookie must have Secure; browsers will reject it")


# --------------------------------------------------------------- input


def read_capped(path):
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("not a regular file")
    if st.st_size > MAX_FILE_BYTES:
        raise ValueError("file larger than %d bytes" % MAX_FILE_BYTES)
    with open(path, "rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("file larger than %d bytes" % MAX_FILE_BYTES)
    return data.decode("utf-8", "replace")


def extract_har(obj):
    """Yield Set-Cookie lines from a HAR object (response headers, else response.cookies)."""
    out = []
    try:
        entries = obj["log"]["entries"]
    except (KeyError, TypeError):
        return None
    if not isinstance(entries, list):
        return None
    for e in entries:
        if not isinstance(e, dict):
            continue
        resp = e.get("response")
        if not isinstance(resp, dict):
            continue
        found = False
        for h in resp.get("headers") or []:
            if isinstance(h, dict) and str(h.get("name", "")).lower() == "set-cookie":
                out.append(str(h.get("value", "")))
                found = True
        if found:
            continue
        for ck in resp.get("cookies") or []:
            if not isinstance(ck, dict):
                continue
            parts = ["%s=%s" % (ck.get("name", ""), ck.get("value", ""))]
            if ck.get("path"):
                parts.append("Path=%s" % ck["path"])
            if ck.get("domain"):
                parts.append("Domain=%s" % ck["domain"])
            if ck.get("expires"):
                parts.append("Expires=%s" % _har_expires(ck["expires"]))
            if ck.get("httpOnly"):
                parts.append("HttpOnly")
            if ck.get("secure"):
                parts.append("Secure")
            if ck.get("sameSite"):
                parts.append("SameSite=%s" % ck["sameSite"])
            out.append("; ".join(parts))
    return out


def _har_expires(v):
    try:
        dt = datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    except ValueError:
        return str(v)


def extract_lines(text):
    """Turn arbitrary text (raw lines, HTTP response, HAR) into cookie lines."""
    stripped = text.lstrip("﻿ \t\r\n")
    if stripped[:1] == "{":
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if obj is not None:
            har = extract_har(obj)
            if har is not None:
                return har
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    prefixed = [re.sub(r"^\s*set-cookie\s*:\s*", "", ln, flags=re.I)
                for ln in lines if re.match(r"^\s*set-cookie\s*:", ln, re.I)]
    if prefixed:
        return prefixed
    first = next((ln for ln in lines if ln.strip()), "")
    if first.startswith("HTTP/") or re.match(r"^(GET|POST|PUT|HEAD) ", first):
        return []   # an HTTP message without Set-Cookie headers
    return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def collect(inputs, stdin_text=None):
    """Return (cookies, errors)."""
    cookies, errors = [], []

    def feed(lines, source):
        for ln in lines:
            if len(cookies) >= MAX_COOKIES:
                if "cookie limit" not in " ".join(errors):
                    errors.append("cookie limit of %d reached; the rest was ignored" % MAX_COOKIES)
                return
            cookies.append(parse_cookie(ln, source))

    for item in inputs:
        if item == "-":
            text = stdin_text if stdin_text is not None else sys.stdin.read(MAX_FILE_BYTES + 1)[:MAX_FILE_BYTES]
            feed(extract_lines(text), "stdin")
            continue
        is_file = False
        try:
            is_file = os.path.exists(item)
        except (OSError, ValueError):
            pass
        if is_file:
            try:
                text = read_capped(item)
            except (OSError, ValueError) as exc:
                errors.append("%s: %s" % (clean(item, 60), exc))
                continue
            feed(extract_lines(text), clean(os.path.basename(item), 60))
        else:
            ls = extract_lines(item)
            if not ls and item.strip():
                ls = [item]
            feed(ls, "arg")
    return cookies, errors


def run(inputs, stdin_text=None, now=None):
    cookies, errors = collect(inputs, stdin_text)
    for c in cookies:
        lint(c, now)
    return cookies, errors


def cookie_dict(c):
    return {
        "source": c.source,
        "name": clean(c.name, 80),
        "value": mask_value(c.value),
        "attributes": [[clean(k, 40), None if v is None else clean(v, 80)] for k, v in c.attrs],
        "findings": [f.to_dict() for f in c.findings],
    }


def worst(cookies):
    w = -1
    for c in cookies:
        for f in c.findings:
            w = max(w, SEVERITIES[f.severity])
    return w


def render_text(cookies, errors, min_sev):
    out = []
    for c in cookies:
        fs = [f for f in c.findings if SEVERITIES[f.severity] >= min_sev]
        out.append("%s  [%s]" % (clean(c.name) or "(unnamed)", c.source))
        out.append("  value: %s" % mask_value(c.value))
        if not fs:
            out.append("  OK")
        for f in sorted(fs, key=lambda f: -SEVERITIES[f.severity]):
            out.append("  %-6s %-22s %s" % (f.severity.upper(), f.code, f.message))
    for e in errors:
        out.append("error: %s" % e)
    total = sum(1 for c in cookies for f in c.findings if SEVERITIES[f.severity] >= min_sev)
    out.append("%d cookie(s), %d finding(s)" % (len(cookies), total))
    return "\n".join(out)


def build_parser():
    p = argparse.ArgumentParser(
        prog="cookiecheck",
        description="Offline lint of Set-Cookie headers. Arguments may be Set-Cookie lines, "
                    "file paths (raw lines, HTTP response or HAR) or '-' for stdin. No network access.",
        epilog="Exit codes: 0 clean, 1 findings, 2 usage or input error.")
    p.add_argument("inputs", nargs="*", help="Set-Cookie line, file, or - for stdin")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high"], default="low",
                   help="hide findings below this level and ignore them for the exit code (default: low)")
    p.add_argument("--version", action="version", version="cookiecheck " + VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    inputs = list(args.inputs)
    if not inputs:
        if sys.stdin is None or sys.stdin.isatty():
            sys.stderr.write("cookiecheck: nothing to check (give a Set-Cookie line, a file or - for stdin)\n")
            return 2
        inputs = ["-"]
    cookies, errors = run(inputs)
    min_sev = SEVERITIES[args.min_severity]
    if not cookies:
        msg = "no cookies found in the input" + ("; " + "; ".join(errors) if errors else "")
        if args.json:
            print(json.dumps({"cookies": [], "errors": errors or ["no cookies found"], "findings": 0}))
        else:
            sys.stderr.write("cookiecheck: %s\n" % msg)
        return 2
    count = sum(1 for c in cookies for f in c.findings if SEVERITIES[f.severity] >= min_sev)
    if args.json:
        doc = {"tool": "cookiecheck", "version": VERSION, "cookies": [], "errors": errors, "findings": count}
        for c in cookies:
            d = cookie_dict(c)
            d["findings"] = [f for f in d["findings"] if SEVERITIES[f["severity"]] >= min_sev]
            doc["cookies"].append(d)
        print(json.dumps(doc, indent=2))
    else:
        print(render_text(cookies, errors, min_sev))
    if errors and not count:
        return 2
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
