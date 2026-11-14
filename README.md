# cookiecheck

**Find the cookie flag you forgot before an attacker does.** A session cookie without `Secure`, `HttpOnly` or `SameSite`, a `__Host-` cookie
that browsers will silently refuse, a `Domain=com`, a JWT readable by any script: these slip through review because they hide in a header
line. cookiecheck lints `Set-Cookie` lines you paste, save, or export in a HAR file and says what is wrong. It works fully offline and
never makes a network request.

```
$ cookiecheck 'Set-Cookie: sessionid=a1b2c3d4e5f6; Path=/'
sessionid  [arg]
  value: a1b2... (12 chars)
  HIGH   missing-secure         no Secure flag: the cookie is also sent over plain http
  HIGH   missing-httponly       no HttpOnly flag: page scripts (and XSS) can read it
  HIGH   session-unprotected    name looks like a session/auth cookie but lacks Secure and HttpOnly
  MEDIUM missing-samesite       no SameSite attribute: browser default applies (Lax in modern browsers, none in old ones)
1 cookie(s), 4 finding(s)
$ cookiecheck '__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app; Domain=example.com'
__Host-id  [arg]
  value: 1 (1 chars)
  HIGH   host-prefix-path       __Host- cookie must have Path=/; browsers will reject it
  HIGH   host-prefix-domain     __Host- cookie must not have a Domain attribute; browsers will reject it
1 cookie(s), 2 finding(s)
$ cookiecheck 'pref=%7B%22role%22%3A%22admin%22%7D; Secure; SameSite=None; Domain=com; Max-Age=99999999'
pref  [arg]
  value: %7B%... (30 chars)
  HIGH   broad-domain           Domain=com is a public suffix or single label; browsers reject it or it spans unrelated sites
  HIGH   unsigned-json          value is plain JSON user data with no visible signature; clients can tamper with it
  MEDIUM missing-httponly       no HttpOnly flag: page scripts (and XSS) can read it
  MEDIUM long-lifetime          lifetime of about 1157 days exceeds the 400-day cap browsers apply
1 cookie(s), 4 finding(s)
$ cookiecheck 'theme=dark; Secure; HttpOnly; SameSite=Lax; Path=/'
theme  [arg]
  value: dark (4 chars)
  OK
1 cookie(s), 0 finding(s)
```

One file, standard library only (Python 3.9+). Cookie values are never printed in full (only the first four characters and the length).

## Usage

```
cookiecheck 'Set-Cookie: id=abc; Path=/'      # a header line (the "Set-Cookie:" prefix is optional)
cookiecheck response.txt                      # pasted HTTP response, or one cookie per line
cookiecheck capture.har                       # HAR export: response Set-Cookie headers, else response.cookies
curl -si https://example.com | cookiecheck -  # stdin (you run curl, cookiecheck itself never connects)
cookiecheck --json --min-severity medium a.txt
```

Arguments that are existing files are read (5 MB cap, regular files only); anything else is treated as a cookie line.

## What it checks

- Missing `Secure`, `HttpOnly`, `SameSite`; `SameSite=None` without `Secure`; invalid `SameSite`; `Partitioned` without `Secure`
- Session-looking names (`sessionid`, `PHPSESSID`, `auth_token`, `csrftoken`, ...) without protections get higher severity
- `__Host-` and `__Secure-` prefix rules (Secure, `Path=/`, no Domain, letter case)
- `Domain` that is a public suffix, single label, IP, or too wide for a session cookie
- Lifetimes over 400 days (browser cap), long-lived session cookies, invalid `Max-Age` or `Expires`; deletion cookies are recognised
- `Path` oddities (relative, `..`, empty, narrow path presented as a boundary)
- Unknown or duplicated attributes, flags with values, control characters, non-ASCII, oversize cookies (4096 bytes) and attributes (1024)
- Values that look like a JWT (high without `HttpOnly`), plain JSON, or base64 JSON with no visible signature

Severities: `high`, `medium`, `low`, `info`. `--min-severity` (default `low`) hides lower ones and ignores them for the exit code.

## Exit codes

`0` clean, `1` findings, `2` usage or input error (nothing to check, unreadable input, no cookies found).

## Limits

- It judges the header line only. It cannot tell whether a cookie is really a session cookie; "session-looking" is a name heuristic and will miss
  oddly named ones and flag harmless ones.
- The public-suffix list is a short built-in sample, not the full Public Suffix List.
- Browser behaviour changes (SameSite defaults, lifetime caps, prefix case sensitivity); thresholds follow current common behaviour and may age.
- "Unsigned JSON/base64" is a visible-structure guess. An encrypted or signed opaque value is not inspected, and a JWT signature is not verified.
- It does not see cookies set by JavaScript, nor how the server validates them.
- HAR files are read with the standard `json` module; very large exports over 5 MB are refused rather than streamed.

## Tests

```
python3 -m unittest -v
```

Synthetic data only. MIT licence.

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [mailauth-lint](https://github.com/TPOALOS/mailauth-lint) · [dmarc-report](https://github.com/TPOALOS/dmarc-report) · [nginxcheck](https://github.com/TPOALOS/nginxcheck) · [all 51 tools](https://tpoalos.github.io)
