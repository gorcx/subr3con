from __future__ import annotations

import os
import time
from urllib.parse import urljoin, urlparse

from .base import Source


class VirusTotalSource(Source):
    name = "virustotal"
    confidence = "high"

    def run(self):
        api_key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
        if not api_key:
            return self.skip("missing VIRUSTOTAL_API_KEY")

        delay = float(os.environ.get("VIRUSTOTAL_API_DELAY", 16))
        max_pages = int(os.environ.get("VIRUSTOTAL_MAX_PAGES", 0))
        url = f"https://www.virustotal.com/api/v3/domains/{self.context.domain}/subdomains?limit=40"
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        results = []
        page = 0

        while url:
            page += 1
            response = self.get(url, headers=headers)
            if response is None:
                break
            if response.status_code >= 400:
                self.debug(f"error: {response.text[:200]}")
                break
            try:
                data = response.json()
            except ValueError as exc:
                self.last_error = f"invalid JSON: {exc}"
                self.debug(f"invalid JSON: {exc}")
                break

            for item in data.get("data", []):
                if item.get("type") == "domain":
                    result = self.result(item.get("id", ""))
                    if result:
                        results.append(result)

            self.debug(f"page {page} fetched, total={len(results)}")
            if max_pages and page >= max_pages:
                break
            url = valid_next_url(data.get("links", {}).get("next"))
            if data.get("links", {}).get("next") and not url:
                self.last_error = "invalid VirusTotal pagination URL"
                break
            if url and not getattr(response, "from_cache", False):
                time.sleep(delay)

        return results


def valid_next_url(value) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    url = urljoin("https://www.virustotal.com", value)
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.virustotal.com":
        return None
    return url
