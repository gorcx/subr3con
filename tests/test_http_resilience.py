import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from subr3con.sources.base import Source, SourceContext


class DummySource(Source):
    name = "dummy"

    def run(self):
        return []


def response(status_code=200, text="ok", headers=None):
    value = Mock()
    value.status_code = status_code
    value.text = text
    value.content = text.encode()
    value.headers = headers or {}
    return value


class HttpResilienceTests(TestCase):
    def test_transient_status_is_retried(self):
        source = DummySource(SourceContext("example.com"))
        source.session.get = Mock(side_effect=[response(502, "bad gateway"), response(200, "success")])
        environment = {
            "SUBR3CON_HTTP_CACHE": "0",
            "SUBR3CON_HTTP_RETRIES": "2",
            "SUBR3CON_HTTP_BACKOFF": "0",
        }

        with patch.dict(os.environ, environment, clear=True):
            result = source.get("https://service.test/data")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(source.request_count, 2)
        self.assertIsNone(source.last_error)

    def test_cached_response_avoids_network_and_does_not_store_api_key(self):
        with TemporaryDirectory() as directory:
            environment = {
                "SUBR3CON_HTTP_CACHE": "1",
                "SUBR3CON_CACHE_DIR": directory,
                "SUBR3CON_CACHE_TTL": "60",
                "SUBR3CON_HTTP_RETRIES": "0",
            }
            headers = {"Authorization": "secret-api-key"}
            first = DummySource(SourceContext("example.com"))
            first.session.get = Mock(return_value=response(200, '{"value": 1}'))

            with patch.dict(os.environ, environment, clear=True):
                first_result = first.get("https://service.test/data", headers=headers)
                second = DummySource(SourceContext("example.com"))
                second.session.get = Mock()
                second_result = second.get("https://service.test/data", headers=headers)

            self.assertEqual(first_result.text, second_result.text)
            second.session.get.assert_not_called()
            self.assertEqual(second.cache_hits, 1)
            cache_contents = "".join(path.read_text(encoding="utf-8") for path in Path(directory).rglob("*.json"))
            self.assertNotIn("secret-api-key", cache_contents)

    def test_cached_headers_remain_case_insensitive(self):
        with TemporaryDirectory() as directory:
            environment = {
                "SUBR3CON_HTTP_CACHE": "1",
                "SUBR3CON_CACHE_DIR": directory,
                "SUBR3CON_CACHE_TTL": "60",
                "SUBR3CON_HTTP_RETRIES": "0",
            }
            first = DummySource(SourceContext("example.com"))
            first.session.get = Mock(return_value=response(200, "ok", {"Set-Cookie": "session=value"}))

            with patch.dict(os.environ, environment, clear=True):
                first.get("https://service.test/cookie")
                second = DummySource(SourceContext("example.com"))
                cached = second.get("https://service.test/cookie")

            self.assertEqual(cached.headers.get("set-cookie"), "session=value")
