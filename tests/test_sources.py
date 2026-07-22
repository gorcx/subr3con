import json
import os
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from subr3con.sources.base import SourceContext
from subr3con.sources.c99 import C99Source, load_cached_scan_date, save_cached_scan_date
from subr3con.sources.crtsh import CrtshSource
from subr3con.sources.ctlogs import CertificateTransparencySource
from subr3con.sources.dnsdumpster import DNSDumpsterSource
from subr3con.sources.netcraft import NetcraftSource
from subr3con.sources.virustotal import VirusTotalSource


class FakeResponse:
    def __init__(self, status_code=200, text="", data=None, headers=None):
        self.status_code = status_code
        self.text = text or (json.dumps(data) if data is not None else "")
        self._data = data
        self.headers = headers or {}
        self.content = self.text.encode()

    def json(self):
        if self._data is None:
            raise ValueError("not JSON")
        return self._data


class PassiveSourceTests(TestCase):
    def setUp(self):
        self.context = SourceContext(domain="example.com")

    def test_virustotal_parses_domain_entries(self):
        response = FakeResponse(
            data={
                "data": [
                    {"type": "domain", "id": "api.example.com"},
                    {"type": "domain", "id": "example.com"},
                    {"type": "url", "id": "ignored.example.com"},
                ],
                "links": {},
            }
        )
        source = VirusTotalSource(self.context)

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test", "VIRUSTOTAL_API_DELAY": "0"}, clear=True):
            with patch.object(source, "get", return_value=response):
                results = source.run()

        self.assertEqual([result.host for result in results], ["api.example.com"])

    def test_dnsdumpster_collects_nested_hosts(self):
        response = FakeResponse(
            data={
                "a": [{"host": "www.example.com"}, {"host": "outside.test"}],
                "mx": {
                    "records": [
                        {"host": "mail.example.com"},
                        {"host": "www.example.com"},
                        {"host": "notexample.com"},
                    ]
                },
            }
        )
        source = DNSDumpsterSource(self.context)

        with patch.dict(os.environ, {"DNSDUMPSTER_API_KEY": "test"}, clear=True):
            with patch.object(source, "get", return_value=response):
                results = source.run()

        self.assertEqual([result.host for result in results], ["mail.example.com", "www.example.com"])

    def test_virustotal_rejects_external_pagination_url(self):
        response = FakeResponse(
            data={
                "data": [{"type": "domain", "id": "api.example.com"}],
                "links": {"next": "https://outside.test/steal-key"},
            }
        )
        source = VirusTotalSource(self.context)

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test", "VIRUSTOTAL_API_DELAY": "0"}, clear=True):
            with patch.object(source, "get", return_value=response) as get:
                results = source.run()

        self.assertEqual([result.host for result in results], ["api.example.com"])
        self.assertEqual(get.call_count, 1)
        self.assertEqual(source.last_error, "invalid VirusTotal pagination URL")

    def test_crtsh_parses_json_and_deduplicates_hosts(self):
        response = FakeResponse(
            text=json.dumps(
                [
                    {"name_value": "api.example.com\n*.example.com", "common_name": "api.example.com"},
                    {"name_value": "outside.test"},
                ]
            )
        )
        source = CrtshSource(self.context)

        with patch.object(source, "get", return_value=response):
            results = source.run()

        self.assertEqual([result.host for result in results], ["api.example.com"])

    def test_netcraft_extracts_hosts_from_simulated_page(self):
        response = FakeResponse(
            text=(
                '<a class="results-table__host" href="https://api.example.com/path">api</a>'
                '<a class="results-table__host" href="https://outside.test/">outside</a>'
            )
        )
        source = NetcraftSource(self.context)

        with patch.object(source, "bootstrap_cookies", return_value={}):
            with patch.object(source, "get", return_value=response):
                results = source.run()

        self.assertEqual([result.host for result in results], ["api.example.com"])

    def test_netcraft_stops_repeated_pagination_url(self):
        response = FakeResponse(
            text=(
                '<a class="results-table__host" href="https://api.example.com/">api</a>'
                '<a href="/?restriction=site+ends+with&amp;host=example.com">Next Page</a>'
            )
        )
        source = NetcraftSource(self.context)

        with patch.object(source, "bootstrap_cookies", return_value={}):
            with patch.object(source, "get", return_value=response) as get:
                results = source.run()

        self.assertEqual([result.host for result in results], ["api.example.com"])
        self.assertEqual(get.call_count, 1)
        self.assertEqual(source.last_error, "pagination loop detected")

    def test_c99_missing_scan_is_empty_not_error(self):
        response = FakeResponse(status_code=404)
        source = C99Source(self.context)
        source.last_error = "HTTP 404"

        with patch.dict(os.environ, {"C99_SCAN_DATE": "2026-07-20"}, clear=True):
            with patch.object(source, "get", return_value=response):
                results = source.run()

        self.assertEqual(results, [])
        self.assertIsNone(source.last_error)

    def test_c99_parses_scan_entries_and_deduplicates(self):
        response = FakeResponse(
            text=(
                '<a class="sd">www.example.com</a>'
                '<a class="sd extra">api.example.com</a>'
                '<a class="sd">www.example.com</a>'
                '<a class="sd">outside.test</a>'
            )
        )
        source = C99Source(self.context)

        with patch.dict(os.environ, {"C99_SCAN_DATE": "2026-07-20", "C99_INCLUDE_HIDDEN": "0"}, clear=True):
            with patch.object(source, "get", return_value=response):
                results = source.run()

        self.assertEqual([result.host for result in results], ["www.example.com", "api.example.com"])

    def test_c99_remembers_the_last_valid_scan_date(self):
        with TemporaryDirectory() as directory:
            environment = {"SUBR3CON_CACHE_DIR": directory, "C99_DATE_CACHE_TTL": "60"}
            with patch.dict(os.environ, environment, clear=True):
                save_cached_scan_date("example.com", "2026-07-20")

                self.assertEqual(load_cached_scan_date("example.com"), "2026-07-20")
                self.assertIsNone(load_cached_scan_date("other.example"))

    def test_ctlogs_uses_shodan_results_first(self):
        source = CertificateTransparencySource(self.context)
        response = FakeResponse(data=["api.example.com", "*.example.com", "outside.test"])

        with patch.dict(os.environ, {"SUBR3CON_CT_PROVIDER": "auto"}, clear=True):
            with patch.object(source, "get", return_value=response) as get:
                results = source.run()

        self.assertEqual([result.host for result in results], ["api.example.com"])
        self.assertEqual(get.call_count, 1)

    def test_ctlogs_falls_back_to_certspotter(self):
        source = CertificateTransparencySource(self.context)
        shodan_response = FakeResponse(data=[])
        certspotter_response = FakeResponse(
            data=[
                {
                    "id": "last-id",
                    "dns_names": ["www.example.com", "api.example.com", "outside.test"],
                }
            ]
        )

        with patch.dict(os.environ, {"SUBR3CON_CT_PROVIDER": "auto", "CERTSPOTTER_MAX_PAGES": "1"}, clear=True):
            with patch.object(source, "get", side_effect=[shodan_response, certspotter_response]) as get:
                results = source.run()

        self.assertEqual([result.host for result in results], ["www.example.com", "api.example.com"])
        self.assertEqual(get.call_count, 2)
