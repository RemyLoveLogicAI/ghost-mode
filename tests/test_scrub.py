import unittest

from ghost_mode.scrub import Options, Scrubber


def scrub(text, **kw):
    env = kw.pop("env", {})
    home = kw.pop("home", None)
    if home is False:  # option, not a path
        kw["home"], home = False, None
    s = Scrubber(Options(**kw), env=env, home=home)
    out = "".join(s.scrub_line(line) for line in text.splitlines(keepends=True))
    return out, s


GH = "ghp_" + "A1b2C3d4" * 5  # 40 chars after prefix, fake
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
ANT = "sk-ant-" + "api03-" + "x9Y8z7" * 6
OAI = "sk-" + "proj-" + "Qw3rTy" * 8


class RuleTests(unittest.TestCase):
    def test_github_token_redacted_and_context_kept(self):
        out, _ = scrub(f"export X={GH} # done\n")
        self.assertNotIn(GH, out)
        self.assertIn("[REDACTED:github-token]", out)
        self.assertTrue(out.endswith(" # done\n"))

    def test_aws_access_key(self):
        out, _ = scrub(f"key {AWS}\n")
        self.assertEqual(out, "key [REDACTED:aws-access-key]\n")

    def test_anthropic_wins_over_openai_shape(self):
        out, s = scrub(f"{ANT}\n")
        self.assertEqual(out, "[REDACTED:anthropic-key]\n")
        self.assertEqual([f.rule for f in s.findings], ["anthropic-key"])

    def test_openai_key(self):
        out, _ = scrub(f"{OAI}\n")
        self.assertEqual(out, "[REDACTED:openai-key]\n")

    def test_generic_assignment_keeps_name(self):
        out, _ = scrub("DB_PASSWORD=hunter2hunter2\n")
        self.assertEqual(out, "DB_PASSWORD=[REDACTED:assignment]\n")

    def test_assignment_skips_numbers_and_variable_refs(self):
        text = "TOKEN_COUNT=100000\nAPI_KEY=$MY_KEY\nAUTH_ENABLED=true\n"
        out, s = scrub(text)
        self.assertEqual(out, text)
        self.assertEqual(s.findings, [])

    def test_json_style_secret(self):
        out, _ = scrub('{"api_key": "abcd1234efgh5678", "name": "bob"}\n')
        self.assertIn('"api_key": "[REDACTED:json-secret]"', out)
        self.assertIn('"name": "bob"', out)

    def test_bearer_header(self):
        out, _ = scrub("Authorization: Bearer abcdefghijklmnop1234\n")
        self.assertEqual(out, "Authorization: Bearer [REDACTED:bearer]\n")

    def test_url_credentials_keep_user_and_host(self):
        out, _ = scrub("git clone https://alice:s3cretpass@example.com/r.git\n")
        self.assertEqual(
            out, "git clone https://alice:[REDACTED:url-password]@example.com/r.git\n"
        )

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "abcDEF123_-xyz"
        out, _ = scrub(f"t={jwt}\n")
        self.assertNotIn(jwt, out)

    def test_private_key_block_multiline(self):
        text = (
            "before\n-----BEGIN " "RSA PRIVATE KEY-----\nMIIEow\nABCDEF\n"
            "-----END " "RSA PRIVATE KEY-----\nafter\n"
        )
        out, s = scrub(text)
        self.assertEqual(out, "before\n[REDACTED:private-key]\nafter\n")
        self.assertEqual(len(s.findings), 1)

    def test_private_key_unterminated_stays_redacted(self):
        out, _ = scrub("-----BEGIN " "PRIVATE KEY-----\nMIIEow\nABCDEF\n")
        self.assertNotIn("MIIEow", out)
        self.assertNotIn("ABCDEF", out)

    def test_slack_webhook_and_stripe(self):
        hook = "https://hooks.slack.com/services/T0000/B0000/" + "X" * 24
        stripe = "sk_" + "live_" + "a1B2c3D4e5F6g7H8"
        out, _ = scrub(f"{hook} {stripe}\n")
        self.assertNotIn("hooks.slack.com/services/T0000", out)
        self.assertNotIn(stripe, out)


class DynamicTests(unittest.TestCase):
    def test_env_values_are_scrubbed_even_without_a_matching_rule(self):
        out, s = scrub("value is zebra-quartz-7731 ok\n", env={"MY_SECRET": "zebra-quartz-7731"})
        self.assertEqual(out, "value is [REDACTED:env:MY_SECRET] ok\n")
        self.assertEqual(s.findings[0].kind, "secret")

    def test_non_secret_env_names_are_ignored(self):
        out, _ = scrub("hello-world-12345\n", env={"GREETING": "hello-world-12345"})
        self.assertEqual(out, "hello-world-12345\n")

    def test_short_env_values_ignored(self):
        out, _ = scrub("pw is abc\n", env={"MY_PASSWORD": "abc"})
        self.assertEqual(out, "pw is abc\n")

    def test_home_path_becomes_tilde(self):
        out, s = scrub("/Users/jane/code/app.py\n", home="/Users/jane")
        self.assertEqual(out, "~/code/app.py\n")
        self.assertEqual(s.findings[0].kind, "privacy")

    def test_home_not_matched_inside_longer_name(self):
        out, _ = scrub("/Users/janet/x\n", home="/Users/jane")
        self.assertEqual(out, "/Users/janet/x\n")

    def test_extra_literals(self):
        out, _ = scrub("customer acme-internal-42\n", extra_literals=("acme-internal-42",))
        self.assertEqual(out, "customer [REDACTED:literal]\n")


class BehaviourTests(unittest.TestCase):
    def test_idempotent(self):
        text = f"A={GH}\nDB_PASSWORD=hunter2hunter2\n"
        once, _ = scrub(text)
        twice, s = scrub(once)
        self.assertEqual(once, twice)
        self.assertEqual(s.findings, [])

    def test_findings_never_contain_secret_text(self):
        _, s = scrub(f"{GH}\nDB_PASSWORD=hunter2hunter2\n")
        blob = repr(s.findings)
        self.assertNotIn(GH, blob)
        self.assertNotIn("hunter2", blob)
        self.assertEqual([f.line for f in s.findings], [1, 2])

    def test_strip_ansi(self):
        out, _ = scrub("\x1b[31mred\x1b[0m\n", strip_ansi=True)
        self.assertEqual(out, "red\n")

    def test_pii_email_opt_in(self):
        off, _ = scrub("mail jane@example.com\n")
        on, s = scrub("mail jane@example.com\n", pii=True)
        self.assertEqual(off, "mail jane@example.com\n")
        self.assertEqual(on, "mail [REDACTED:email]\n")
        self.assertEqual(s.findings[0].kind, "privacy")

    def test_crlf_preserved(self):
        out, _ = scrub(f"{AWS}\r\nnext\r\n")
        self.assertEqual(out, "[REDACTED:aws-access-key]\r\nnext\r\n")


class RegressionTests(unittest.TestCase):
    def test_no_catastrophic_backtracking(self):
        import time
        start = time.monotonic()
        scrub("a.b-" * 5000 + "\n")
        scrub("x@" + "a" * 20000 + "\n", pii=True)
        scrub("http://" + "a" * 20000 + "\n")
        self.assertLess(time.monotonic() - start, 2.0)

    def test_partial_overlap_does_not_leak_tail(self):
        out, _ = scrub(f"{AWS} and more\n", extra_literals=("7EXAMPLE and more",),
                       home=False, use_env=False)
        self.assertNotIn("and more", out)

    def test_ansi_code_inside_a_token_does_not_hide_it(self):
        out, _ = scrub("x ghp_\x1b[0m" + "Ab1Cd2Ef" * 5 + " y\n")
        self.assertEqual(out, "x [REDACTED:github-token] y\n")

    def test_ansi_colour_around_a_secret_is_kept(self):
        out, _ = scrub("\x1b[31m" + GH + "\x1b[0m\n")
        self.assertEqual(out, "\x1b[31m[REDACTED:github-token]\x1b[0m\n")

    def test_basic_auth_header(self):
        out, _ = scrub("Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==\n")
        self.assertNotIn("dXNlcjpw", out)

    def test_plain_english_basic_is_not_flagged(self):
        out, s = scrub("Basic configuration is required\n")
        self.assertEqual((out, s.findings), ("Basic configuration is required\n", []))

    def test_curl_user_password(self):
        out, _ = scrub("curl -s -u admin:hunter2hunter2 https://x.example\n")
        self.assertEqual(out, "curl -s -u admin:[REDACTED:curl-user] https://x.example\n")

    def test_quoted_value_with_spaces(self):
        out, _ = scrub('export DB_PASSWORD="my secret pass"\n')
        self.assertEqual(out, 'export DB_PASSWORD="[REDACTED:assignment]"\n')

    def test_quoted_value_single_quotes_and_yaml(self):
        out, _ = scrub("password: 'correct horse battery'\n")
        self.assertNotIn("horse", out)


if __name__ == "__main__":
    unittest.main()
