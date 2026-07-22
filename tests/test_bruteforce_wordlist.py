from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

import dns.resolver

from subr3con.sources.bruteforce import (
    generate_mutations,
    is_wildcard_answer,
    load_names,
    load_resolvers,
    qualify_name,
    read_resolver_file,
    resolve_addresses,
    validate_resolvers,
    wait_for_workers,
)


class LoadNamesTests(TestCase):
    def test_preserves_file_order_and_ignores_duplicates(self):
        with TemporaryDirectory() as directory:
            wordlist = Path(directory) / "names.txt"
            wordlist.write_text("# comment\nmail\nwww\nMAIL\napi,metadata\n*\nbad name\n\nportal\n", encoding="utf-8")

            self.assertEqual(load_names(wordlist), ["mail", "www", "api", "portal"])

    def test_names_are_always_scoped_to_the_target(self):
        self.assertEqual(qualify_name("api", "example.com"), "api.example.com")
        self.assertEqual(qualify_name("dev.example.com", "example.com"), "dev.example.com")
        self.assertEqual(qualify_name("api.outside.test", "example.com"), "api.outside.test.example.com")
        self.assertIsNone(qualify_name("example.com", "example.com"))

    def test_limit_selects_first_unique_names(self):
        with TemporaryDirectory() as directory:
            wordlist = Path(directory) / "names.txt"
            wordlist.write_text("www\nwww\nmail\napi\nportal\n", encoding="utf-8")

            self.assertEqual(load_names(wordlist, max_names=2), ["www", "mail"])


class MutationTests(TestCase):
    def test_mutations_follow_names_and_respect_limit(self):
        self.assertEqual(
            generate_mutations(["api", "mail"], max_mutations=4),
            ["api1", "api2", "api-dev", "api-test"],
        )

    def test_mutations_skip_existing_and_numbered_names(self):
        mutations = generate_mutations(["api", "api1", "mail2"], max_mutations=20)

        self.assertNotIn("api1", mutations)
        self.assertFalse(any(candidate.startswith("mail2") for candidate in mutations))


class ResolverTests(TestCase):
    def test_resolver_file_keeps_unique_ip_addresses(self):
        with TemporaryDirectory() as directory:
            resolver_file = Path(directory) / "resolvers.txt"
            resolver_file.write_text("# comment\n1.1.1.1\ninvalid\n1.1.1.1\n8.8.8.8\n", encoding="utf-8")

            self.assertEqual(read_resolver_file(resolver_file), ["1.1.1.1", "8.8.8.8"])

    def test_inline_resolvers_are_validated_and_deduplicated(self):
        self.assertEqual(load_resolvers("1.1.1.1,invalid,1.1.1.1,8.8.8.8"), ["1.1.1.1", "8.8.8.8"])

    @patch("subr3con.sources.bruteforce.probe_resolver")
    def test_validation_keeps_fastest_healthy_resolvers(self, probe):
        latencies = {"1.1.1.1": 0.04, "8.8.8.8": None, "9.9.9.10": 0.02}
        probe.side_effect = lambda address, timeout, host: latencies[address]

        result = validate_resolvers(list(latencies), max_resolvers=1)

        self.assertEqual(result, ["9.9.9.10"])


class WildcardAndInterruptTests(TestCase):
    def test_address_resolution_includes_ipv6_only_hosts(self):
        resolver = Mock()
        ipv6_record = Mock()
        ipv6_record.to_text.return_value = "2001:db8::10"
        resolver.resolve.side_effect = [dns.resolver.NoAnswer(), [ipv6_record]]

        self.assertEqual(resolve_addresses(resolver, "ipv6.example.com"), {"2001:db8::10"})

    def test_wildcard_requires_an_exact_observed_address_set(self):
        signatures = {frozenset({"192.0.2.1", "192.0.2.2"})}

        self.assertTrue(is_wildcard_answer({"192.0.2.1", "192.0.2.2"}, signatures))
        self.assertFalse(is_wildcard_answer({"192.0.2.1"}, signatures))
        self.assertFalse(is_wildcard_answer(set(), signatures))

    @patch("subr3con.sources.bruteforce.time.sleep", side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_stops_workers(self, _sleep):
        worker = Mock()
        worker.is_alive.return_value = True
        stop_event = Mock()

        interrupted = wait_for_workers([worker], stop_event)

        self.assertTrue(interrupted)
        stop_event.set.assert_called_once_with()
