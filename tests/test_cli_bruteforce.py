import os
from contextlib import redirect_stderr
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

from subr3con.cli import (
    apply_bruteforce_limit,
    build_parser,
    choose_sources,
    normalize_domain,
    valid_domain,
)
from subr3con.config import PROFILES


class BruteforceCliTests(TestCase):
    def assert_parse_fails(self, arguments):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(arguments)

    def test_source_selection_is_mutually_exclusive(self):
        self.assert_parse_fails(["-d", "example.com", "-pF", "-pB"])

    def test_explicit_sources_are_deduplicated(self):
        args = build_parser().parse_args(["-d", "example.com", "--sources", "c99,C99,netcraft"])

        self.assertEqual(choose_sources(args), ["c99", "netcraft"])

    def test_negative_limits_and_zero_threads_are_rejected(self):
        self.assert_parse_fails(["-d", "example.com", "-pB", "-1"])
        self.assert_parse_fails(["-d", "example.com", "-pB", "--brute-threads", "0"])

    def test_domain_normalization_accepts_urls_ports_and_idna(self):
        self.assertEqual(normalize_domain("https://Example.COM.:443/path"), "example.com")
        self.assertEqual(normalize_domain("bücher.example"), "xn--bcher-kva.example")
        self.assertTrue(valid_domain("xn--bcher-kva.example"))
        self.assertFalse(valid_domain("bad_label.example"))

    def test_mixed_profile_is_the_complete_current_profile(self):
        args = build_parser().parse_args(["-d", "example.com", "-pX", "1000"])

        self.assertEqual(choose_sources(args), PROFILES["mixed"])
        self.assertIn("bruteforce", choose_sources(args))

    def test_all_profile_aliases_are_disabled(self):
        self.assertNotIn("all", PROFILES)
        self.assert_parse_fails(["-d", "example.com", "-pA"])
        self.assert_parse_fails(["-d", "example.com", "--profile", "all"])

    def test_timing_option_overrides_environment_tuning(self):
        args = build_parser().parse_args(["-d", "example.com", "-pB", "1000", "-T4"])
        environment = {
            "SUBR3CON_BRUTE_THREADS": "12",
            "SUBR3CON_DNS_TIMEOUT": "9",
            "SUBR3CON_DNS_LIFETIME": "10",
        }

        with patch.dict(os.environ, environment, clear=True):
            apply_bruteforce_limit(args)

            self.assertEqual(os.environ["SUBR3CON_TIMING"], "4")
            self.assertNotIn("SUBR3CON_BRUTE_THREADS", os.environ)
            self.assertNotIn("SUBR3CON_DNS_TIMEOUT", os.environ)
            self.assertNotIn("SUBR3CON_DNS_LIFETIME", os.environ)

    def test_explicit_threads_override_timing_profile(self):
        args = build_parser().parse_args(["-d", "example.com", "-pB", "-T2", "--brute-threads", "75"])

        with patch.dict(os.environ, {}, clear=True):
            apply_bruteforce_limit(args)

            self.assertEqual(os.environ["SUBR3CON_TIMING"], "2")
            self.assertEqual(os.environ["SUBR3CON_BRUTE_THREADS"], "75")

    def test_timing_zero_is_rejected(self):
        self.assert_parse_fails(["-d", "example.com", "-pB", "-T0"])

    def test_mutation_limit_enables_mutations(self):
        args = build_parser().parse_args(["-d", "example.com", "-pB", "--mutation-max", "250"])

        with patch.dict(os.environ, {}, clear=True):
            apply_bruteforce_limit(args)

            self.assertEqual(os.environ["SUBR3CON_MUTATIONS"], "1")
            self.assertEqual(os.environ["SUBR3CON_MUTATION_MAX"], "250")
