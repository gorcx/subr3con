from unittest import TestCase
from unittest.mock import patch

from subr3con.enrich import enrich_ips
from subr3con.models import AggregatedResult


class IpEnrichmentTests(TestCase):
    @patch("subr3con.enrich.resolve_host_ips")
    def test_enrichment_adds_ipv4_and_ipv6_to_every_result(self, resolve):
        responses = {
            "api.example.com": {"192.0.2.10", "2001:db8::10"},
            "www.example.com": {"192.0.2.20"},
        }
        resolve.side_effect = lambda host, timeout: responses[host]
        results = [
            AggregatedResult(host="api.example.com"),
            AggregatedResult(host="www.example.com", ips={"192.0.2.21"}),
        ]

        enrich_ips(results, threads=2)

        self.assertEqual(results[0].ips, {"192.0.2.10", "2001:db8::10"})
        self.assertEqual(results[1].ips, {"192.0.2.20", "192.0.2.21"})

    @patch("subr3con.enrich.resolve_host_ips", return_value=set())
    def test_enrichment_keeps_results_when_dns_fails(self, _resolve):
        result = AggregatedResult(host="missing.example.com")

        enrich_ips([result])

        self.assertEqual(result.ips, set())
