import threading
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

from subr3con.models import AggregatedResult, SubdomainResult
from subr3con.output import write_results
from subr3con.runner import run_sources
from subr3con.sources.base import Source


class DebugSource(Source):
    name = "debug-test"

    def run(self):
        self.debug("request details")
        return [SubdomainResult(host=f"www.{self.context.domain}", source=self.name)]


class OutputStreamTests(TestCase):
    def test_foreground_sources_run_on_the_calling_thread(self):
        observed_threads = []

        class ForegroundSource(DebugSource):
            name = "foreground-test"
            foreground = True

            def run(self):
                observed_threads.append(threading.get_ident())
                return super().run()

        with patch.dict("subr3con.runner.SOURCE_REGISTRY", {ForegroundSource.name: ForegroundSource}, clear=True):
            run_sources("example.com", [ForegroundSource.name])

        self.assertEqual(observed_threads, [threading.get_ident()])

    def test_source_diagnostics_use_stderr(self):
        stdout = StringIO()
        stderr = StringIO()

        with patch.dict("subr3con.runner.SOURCE_REGISTRY", {DebugSource.name: DebugSource}, clear=True):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                results = run_sources("example.com", [DebugSource.name], debug=True, sequential=True)
                write_results(results)

        self.assertEqual(stdout.getvalue(), "www.example.com\n")
        self.assertIn("[debug:debug-test] start", stderr.getvalue())
        self.assertIn("[debug:debug-test] request details", stderr.getvalue())
        self.assertIn("[debug:debug-test] finish", stderr.getvalue())

    def test_plain_results_do_not_write_diagnostics(self):
        result = AggregatedResult(host="api.example.com")
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            write_results([result])

        self.assertEqual(stdout.getvalue(), "api.example.com\n")
        self.assertEqual(stderr.getvalue(), "")

    def test_source_summary_uses_stderr(self):
        stdout = StringIO()
        stderr = StringIO()

        with patch.dict("subr3con.runner.SOURCE_REGISTRY", {DebugSource.name: DebugSource}, clear=True):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                results = run_sources("example.com", [DebugSource.name], sequential=True, summary=True)
                write_results(results)

        self.assertEqual(stdout.getvalue(), "www.example.com\n")
        self.assertIn("[summary] debug-test ok 1", stderr.getvalue())
