import csv
import json
from io import StringIO
from unittest import TestCase

from subr3con.models import AggregatedResult, SubdomainResult
from subr3con.output import write_csv, write_json, write_txt
from subr3con.runner import merge_results


class AggregationTests(TestCase):
    def test_merge_deduplicates_hosts_and_combines_evidence(self):
        aggregate = {}
        merge_results(
            aggregate,
            [
                SubdomainResult("api.example.com", "crtsh", confidence="medium"),
                SubdomainResult("api.example.com", "virustotal", ip="192.0.2.10", confidence="high"),
            ],
        )

        result = aggregate["api.example.com"]
        self.assertEqual(result.sources, {"crtsh", "virustotal"})
        self.assertEqual(result.ips, {"192.0.2.10"})
        self.assertEqual(result.confidence, "high")


class ExportTests(TestCase):
    def setUp(self):
        self.result = AggregatedResult(
            host="api.example.com",
            ips={"192.0.2.10"},
            sources={"virustotal", "crtsh"},
            confidence="high",
        )

    def test_txt_export(self):
        output = StringIO()
        write_txt([self.result], output, show_ip=True, show_source=True, show_confidence=True)

        self.assertEqual(output.getvalue(), "api.example.com\t192.0.2.10\tcrtsh,virustotal\thigh\n")

    def test_json_export(self):
        output = StringIO()
        write_json([self.result], output)

        data = json.loads(output.getvalue())
        self.assertEqual(data[0]["host"], "api.example.com")
        self.assertEqual(data[0]["ips"], ["192.0.2.10"])
        self.assertEqual(data[0]["sources"], ["crtsh", "virustotal"])

    def test_csv_export(self):
        output = StringIO(newline="")
        write_csv([self.result], output)

        rows = list(csv.DictReader(StringIO(output.getvalue())))
        self.assertEqual(rows[0]["host"], "api.example.com")
        self.assertEqual(rows[0]["ips"], "192.0.2.10")
        self.assertEqual(rows[0]["sources"], "crtsh,virustotal")
