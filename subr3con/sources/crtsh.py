from __future__ import annotations

import html
import json
import re

from .base import Source


class CrtshSource(Source):
    name = "crtsh"
    confidence = "medium"

    def run(self):
        results = []
        json_urls = [
            f"https://crt.sh/?q=%25.{self.context.domain}&output=json",
            f"https://crt.sh/?q={self.context.domain}&output=json",
        ]
        for url in json_urls:
            response = self.get(url)
            if not response or response.status_code >= 500:
                continue
            if response.status_code == 200:
                results.extend(self.parse_json(response.text))
                if results:
                    return results

        html_urls = [
            f"https://crt.sh/?q={self.context.domain}",
            f"https://crt.sh/?q=%25.{self.context.domain}",
        ]
        for url in html_urls:
            response = self.get(url)
            if response and response.status_code == 200:
                results.extend(self.parse_html(response.text))
                if results:
                    break
        return dedupe(results)

    def parse_json(self, text: str):
        results = []
        try:
            data = json.loads(text)
        except ValueError as exc:
            self.last_error = f"invalid JSON: {exc}"
            self.debug(f"invalid JSON: {exc}")
            return []
        for entry in data:
            for key in ("name_value", "common_name"):
                for host in str(entry.get(key, "")).splitlines():
                    result = self.result(host)
                    if result:
                        results.append(result)
        return dedupe(results)

    def parse_html(self, text: str):
        text = html.unescape(text)
        hosts = self.extract_hosts(re.sub(r"<br\s*/?>", "\n", text, flags=re.I))
        return [result for host in hosts if (result := self.result(host))]


def dedupe(results):
    seen = set()
    output = []
    for result in results:
        if result.host not in seen:
            seen.add(result.host)
            output.append(result)
    return output
