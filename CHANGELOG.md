# Changelog

## 1.0.0

First release.

- Lints Set-Cookie lines from arguments, files, stdin, pasted HTTP responses and HAR files
- Checks Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes, Domain scope, lifetime, Path, duplicates, size and risky values (JWT, JSON, base64 JSON)
- Text and `--json` output; cookie values are never printed in full; never makes a network request
