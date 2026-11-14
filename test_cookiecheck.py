import base64
import contextlib
import datetime
import io
import json
import os
import tempfile
import unittest

import cookiecheck as cc

NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
GOOD = "id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJl"  # secretscan:ignore


def lint(line):
    c = cc.parse_cookie(line)
    cc.lint(c, NOW)
    return c


def codes(line):
    return {f.code for f in lint(line).findings}


def sev(line, code):
    for f in lint(line).findings:
        if f.code == code:
            return f.severity
    return None


def run_cli(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    old = cc.sys.stdin
    if stdin is not None:
        cc.sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cc.main(argv)
            except SystemExit as e:
                rc = e.code
    finally:
        cc.sys.stdin = old
    return rc, out.getvalue(), err.getvalue()


class ParseTests(unittest.TestCase):
    def test_name_value(self):
        c = cc.parse_cookie("a=b; Secure")
        self.assertEqual((c.name, c.value), ("a", "b"))

    def test_value_with_equals(self):
        c = cc.parse_cookie("a=b=c==; Path=/")
        self.assertEqual(c.value, "b=c==")

    def test_attrs_lowercased(self):
        c = cc.parse_cookie("a=b; SECURE; SameSite=Lax")
        self.assertTrue(c.has("secure"))
        self.assertEqual(c.attr("samesite"), "Lax")

    def test_no_name(self):
        self.assertIn("no-name", codes("justavalue; Secure; HttpOnly"))

    def test_empty_name(self):
        self.assertIn("empty-name", codes("=v; Secure; HttpOnly; SameSite=Lax"))

    def test_bad_name_chars(self):
        self.assertIn("bad-name", codes("a b=v; Secure; HttpOnly; SameSite=Lax"))

    def test_mask_value_hides_secret(self):
        self.assertNotIn("supersecret", cc.mask_value("supersecretvalue"))

    def test_clean_strips_control(self):
        self.assertNotIn("\x1b", cc.clean("a\x1b[31mb"))


class FlagTests(unittest.TestCase):
    def test_good_cookie_clean(self):
        self.assertEqual(codes(GOOD), set())

    def test_missing_secure(self):
        self.assertIn("missing-secure", codes("id=1; HttpOnly; SameSite=Lax"))

    def test_missing_httponly(self):
        self.assertIn("missing-httponly", codes("id=1; Secure; SameSite=Lax"))

    def test_missing_samesite(self):
        self.assertIn("missing-samesite", codes("id=1; Secure; HttpOnly"))

    def test_samesite_none_without_secure(self):
        self.assertEqual(sev("id=1; HttpOnly; SameSite=None", "samesite-none-insecure"), "high")

    def test_samesite_none_with_secure_info(self):
        self.assertEqual(sev("id=1; Secure; HttpOnly; SameSite=None", "samesite-none"), "info")

    def test_bad_samesite(self):
        self.assertIn("bad-samesite", codes("id=1; Secure; HttpOnly; SameSite=Sometimes"))

    def test_session_name_unprotected_high(self):
        self.assertEqual(sev("PHPSESSID=abc", "session-unprotected"), "high")
        self.assertEqual(sev("PHPSESSID=abc", "missing-secure"), "high")

    def test_plain_name_unprotected_medium(self):
        self.assertEqual(sev("theme=dark", "missing-secure"), "medium")

    def test_session_names(self):
        for n in ("sessionid", "connect.sid", "auth_token", "JSESSIONID", "csrftoken"):
            self.assertIn("session-unprotected", codes("%s=x" % n), n)

    def test_partitioned_needs_secure(self):
        self.assertIn("partitioned-insecure", codes("a=b; HttpOnly; SameSite=None; Partitioned"))


class PrefixTests(unittest.TestCase):
    def test_host_ok(self):
        self.assertEqual(codes("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/"), set())

    def test_host_missing_secure(self):
        self.assertIn("host-prefix-secure", codes("__Host-id=1; HttpOnly; SameSite=Lax; Path=/"))

    def test_host_bad_path(self):
        self.assertIn("host-prefix-path", codes("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app"))

    def test_host_no_path(self):
        self.assertIn("host-prefix-path", codes("__Host-id=1; Secure; HttpOnly; SameSite=Lax"))

    def test_host_with_domain(self):
        self.assertIn("host-prefix-domain", codes("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com"))

    def test_secure_prefix_ok(self):
        self.assertNotIn("secure-prefix-secure", codes("__Secure-id=1; Secure; HttpOnly; SameSite=Lax"))

    def test_secure_prefix_violation(self):
        self.assertIn("secure-prefix-secure", codes("__Secure-id=1; HttpOnly; SameSite=Lax"))

    def test_prefix_case(self):
        self.assertIn("prefix-case", codes("__host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/"))

    def test_prefix_checked_on_deletion(self):
        self.assertIn("host-prefix-secure", codes("__Host-id=; Max-Age=0; Path=/"))


class DomainLifetimePathTests(unittest.TestCase):
    def test_public_suffix_domain(self):
        self.assertIn("broad-domain", codes(GOOD + "; Domain=com"))
        self.assertIn("broad-domain", codes(GOOD + "; Domain=.co.uk"))

    def test_single_label_domain(self):
        self.assertIn("broad-domain", codes(GOOD + "; Domain=intranet"))

    def test_ip_domain(self):
        self.assertIn("ip-domain", codes(GOOD + "; Domain=192.0.2.5"))

    def test_session_wide_domain(self):
        self.assertIn("wide-domain", codes("sessionid=1; Secure; HttpOnly; SameSite=Lax; Domain=example.com"))

    def test_leading_dot_info(self):
        self.assertIn("leading-dot", codes(GOOD + "; Domain=.www.example.com"))

    def test_long_max_age(self):
        self.assertIn("long-lifetime", codes(GOOD + "; Max-Age=99999999"))

    def test_max_age_ok(self):
        self.assertNotIn("long-lifetime", codes(GOOD + "; Max-Age=3600"))

    def test_long_expires(self):
        self.assertIn("long-lifetime", codes(GOOD + "; Expires=Fri, 31 Dec 2099 23:59:59 GMT"))

    def test_session_cookie_long_session(self):
        self.assertIn("long-session", codes("sessionid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=%d" % (90 * 86400)))

    def test_bad_expires(self):
        self.assertIn("bad-expires", codes(GOOD + "; Expires=tomorrow-ish"))

    def test_bad_max_age(self):
        self.assertIn("bad-max-age", codes(GOOD + "; Max-Age=abc"))

    def test_deletion_cookie(self):
        c = codes("sessionid=; Max-Age=0; Path=/")
        self.assertIn("deletion", c)
        self.assertNotIn("missing-secure", c)

    def test_expired_date_is_deletion(self):
        self.assertIn("deletion", codes("a=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"))

    def test_path_relative(self):
        self.assertIn("bad-path", codes(GOOD.replace("Path=/", "Path=app")))

    def test_path_traversal(self):
        self.assertIn("path-traversal", codes(GOOD.replace("Path=/", "Path=/a/../b")))

    def test_empty_path(self):
        self.assertIn("empty-path", codes("id=1; Secure; HttpOnly; SameSite=Lax; Path="))

    def test_narrow_path_session(self):
        self.assertIn("narrow-path", codes("sessionid=1; Secure; HttpOnly; SameSite=Lax; Path=/admin"))


class AttributeTests(unittest.TestCase):
    def test_unknown_attr(self):
        self.assertIn("unknown-attr", codes(GOOD + "; Foo=bar"))

    def test_duplicate_attr(self):
        self.assertIn("duplicate-attr", codes(GOOD + "; Secure"))

    def test_flag_with_value(self):
        self.assertIn("flag-with-value", codes("id=1; Secure=yes; HttpOnly; SameSite=Lax"))

    def test_attr_no_value(self):
        self.assertIn("attr-no-value", codes("id=1; Secure; HttpOnly; SameSite; Path"))

    def test_oversize(self):
        self.assertIn("oversize", codes("id=%s; Secure; HttpOnly; SameSite=Lax" % ("A" * 5000)))

    def test_attr_too_long(self):
        self.assertIn("attr-too-long", codes(GOOD + "; Path=/" + "a" * 1100))

    def test_control_chars(self):
        self.assertIn("control-chars", codes("id=1\x00; Secure"))

    def test_non_ascii(self):
        self.assertIn("non-ascii", codes("id=café; Secure; HttpOnly; SameSite=Lax"))

    def test_bad_value_chars(self):
        self.assertIn("bad-value", codes('id=a b,c; Secure; HttpOnly; SameSite=Lax'))


class ValueTests(unittest.TestCase):
    def test_jwt_no_httponly(self):
        self.assertEqual(sev("t=%s; Secure; SameSite=Lax" % JWT, "jwt-readable"), "high")

    def test_jwt_with_httponly_info(self):
        self.assertEqual(sev("t=%s; Secure; HttpOnly; SameSite=Lax" % JWT, "jwt-in-cookie"), "info")

    def test_plain_json(self):
        self.assertIn("unsigned-json", codes('p={"role":"admin"}; Secure; HttpOnly; SameSite=Lax'))

    def test_urlencoded_json(self):
        self.assertIn("unsigned-json", codes("p=%7B%22role%22%3A%22admin%22%7D; Secure; HttpOnly; SameSite=Lax"))

    def test_base64_json(self):
        v = base64.b64encode(b'{"user":"bob","admin":true}').decode()
        self.assertIn("base64-json", codes("p=%s; Secure; HttpOnly; SameSite=Lax" % v.rstrip("=")))

    def test_random_base64_not_json(self):
        v = base64.b64encode(os.urandom(24)).decode()
        self.assertNotIn("base64-json", codes("p=%s; Secure; HttpOnly; SameSite=Lax" % v))

    def test_plain_value_clean(self):
        self.assertEqual(codes("lang=en; Secure; HttpOnly; SameSite=Lax"), set())


class InputTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def path(self, name, data, mode="w"):
        p = os.path.join(self.d.name, name)
        with open(p, mode) as f:
            f.write(data)
        return p

    def test_http_response(self):
        text = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1; Secure\r\nSet-Cookie: b=2\r\n\r\nbody=1"
        cookies, _ = cc.run([self.path("r.txt", text)], now=NOW)
        self.assertEqual([c.name for c in cookies], ["a", "b"])

    def test_http_without_cookies(self):
        cookies, _ = cc.collect([self.path("r.txt", "HTTP/1.1 200 OK\nX: y\n")])
        self.assertEqual(cookies, [])

    def test_raw_lines_and_comments(self):
        cookies, _ = cc.collect([self.path("r.txt", "# note\na=1\n\nb=2\n")])
        self.assertEqual(len(cookies), 2)

    def test_prefixed_arg(self):
        cookies, _ = cc.collect(["Set-Cookie: a=1; Secure"])
        self.assertEqual(cookies[0].name, "a")

    def test_har_headers(self):
        har = {"log": {"entries": [{"response": {"headers": [
            {"name": "Set-Cookie", "value": "a=1; Secure"}, {"name": "X", "value": "y"}]}}]}}
        cookies, _ = cc.collect([self.path("h.har", json.dumps(har))])
        self.assertEqual(len(cookies), 1)

    def test_har_cookies_objects(self):
        har = {"log": {"entries": [{"response": {"cookies": [
            {"name": "sid", "value": "x", "path": "/", "httpOnly": True, "secure": False,
             "expires": "2099-01-01T00:00:00Z"}]}}]}}
        cookies, _ = cc.run([self.path("h.har", json.dumps(har))], now=NOW)
        self.assertIn("missing-secure", {f.code for f in cookies[0].findings})
        self.assertIn("long-lifetime", {f.code for f in cookies[0].findings})

    def test_har_garbage_entries(self):
        har = {"log": {"entries": [1, None, {"response": 5}, {"response": {"headers": [None, 3]}}]}}
        cookies, errs = cc.collect([self.path("h.har", json.dumps(har))])
        self.assertEqual(cookies, [])

    def test_missing_file_treated_as_line(self):
        cookies, _ = cc.collect(["/no/such/file=1"])
        self.assertEqual(cookies[0].name, "/no/such/file")

    def test_directory_error(self):
        cookies, errs = cc.collect([self.d.name])
        self.assertTrue(errs)

    def test_binary_file(self):
        p = self.path("b.bin", os.urandom(2000), "wb")
        cookies, errs = cc.run([p], now=NOW)
        self.assertIsInstance(cookies, list)

    def test_huge_file_rejected(self):
        p = self.path("big.txt", "")
        with open(p, "wb") as f:
            f.truncate(cc.MAX_FILE_BYTES + 10)
        cookies, errs = cc.collect([p])
        self.assertTrue(errs)

    def test_symlink_followed_safely(self):
        p = self.path("t.txt", "a=1\n")
        link = os.path.join(self.d.name, "l.txt")
        os.symlink(p, link)
        cookies, _ = cc.collect([link])
        self.assertEqual(len(cookies), 1)

    def test_dangling_symlink_no_crash(self):
        link = os.path.join(self.d.name, "dangling")
        os.symlink("/nonexistent/zzz", link)
        cc.collect([link])

    def test_control_chars_in_filename(self):
        cookies, _ = cc.collect(["a\x00b=1"])
        self.assertEqual(len(cookies), 1)

    def test_cookie_limit(self):
        text = "\n".join("c%d=1" % i for i in range(cc.MAX_COOKIES + 50))
        cookies, errs = cc.collect([self.path("m.txt", text)])
        self.assertEqual(len(cookies), cc.MAX_COOKIES)
        self.assertTrue(errs)

    def test_bad_utf8(self):
        p = self.path("u.txt", b"a=\xff\xfe; Secure\n", "wb")
        cookies, _ = cc.run([p], now=NOW)
        self.assertEqual(len(cookies), 1)


class CliTests(unittest.TestCase):
    def test_clean_exit_0(self):
        rc, out, _ = run_cli([GOOD])
        self.assertEqual(rc, 0)
        self.assertIn("OK", out)

    def test_findings_exit_1(self):
        rc, out, _ = run_cli(["sessionid=abc"])
        self.assertEqual(rc, 1)
        self.assertIn("session-unprotected", out)

    def test_no_input_nothing_found_exit_2(self):
        rc, _, err = run_cli(["-"], stdin="HTTP/1.1 200 OK\n\n")
        self.assertEqual(rc, 2)

    def test_stdin_dash(self):
        rc, out, _ = run_cli(["-"], stdin="Set-Cookie: a=1\n")
        self.assertEqual(rc, 1)

    def test_stdin_implicit(self):
        rc, out, _ = run_cli([], stdin="a=1; Secure; HttpOnly; SameSite=Lax\n")
        self.assertEqual(rc, 0)

    def test_json_output(self):
        rc, out, _ = run_cli(["--json", "sessionid=abc"])
        doc = json.loads(out)
        self.assertEqual(rc, 1)
        self.assertGreater(doc["findings"], 0)
        self.assertEqual(doc["cookies"][0]["name"], "sessionid")

    def test_json_does_not_leak_value(self):
        _, out, _ = run_cli(["--json", "sessionid=topsecretvalue123"])
        self.assertNotIn("topsecretvalue123", out)

    def test_text_does_not_leak_value(self):
        _, out, _ = run_cli(["sessionid=topsecretvalue123"])
        self.assertNotIn("topsecretvalue123", out)

    def test_min_severity_filters(self):
        rc, out, _ = run_cli(["--min-severity", "high", "theme=dark; Secure; HttpOnly"])
        self.assertEqual(rc, 0)

    def test_usage_error(self):
        rc, _, _ = run_cli(["--bogus"])
        self.assertEqual(rc, 2)

    def test_multiple_args(self):
        rc, out, _ = run_cli(["a=1", "b=2"])
        self.assertIn("2 cookie(s)", out)

    def test_hostile_name_printed_safely(self):
        _, out, _ = run_cli(["\x1b[31mevil=1"])
        self.assertNotIn("\x1b", out)

    def test_no_network_modules(self):
        with open(cc.__file__) as f:
            src = f.read()
        for mod in ("socket", "urllib.request", "http.client", "requests"):
            self.assertNotIn("import " + mod, src)


if __name__ == "__main__":
    unittest.main()
