from __future__ import annotations

import hashlib
import random
import re
import time
from html import unescape
from urllib.parse import unquote, urljoin, urlparse

from .base import Source


class NetcraftSource(Source):
    name = "netcraft"
    confidence = "medium"

    def run(self):
        cookies = self.bootstrap_cookies()
        url = f"https://searchdns.netcraft.com/?restriction=site+ends+with&host={self.context.domain}"
        results = []
        seen = set()
        visited_urls = set()
        max_pages = 20

        while url and url not in visited_urls and len(visited_urls) < max_pages:
            visited_urls.add(url)
            response = self.get(url, cookies=cookies)
            if response is None or response.status_code >= 400:
                break
            for host in self.extract_netcraft_hosts(response.text):
                result = self.result(host)
                if result and result.host not in seen:
                    seen.add(result.host)
                    results.append(result)
            url = self.next_url(response.text)
            if url and url not in visited_urls:
                time.sleep(random.uniform(1, 2))
        if url in visited_urls:
            self.last_error = "pagination loop detected"
        elif url and len(visited_urls) >= max_pages:
            self.last_error = f"pagination stopped after {max_pages} pages"
        return results

    def bootstrap_cookies(self):
        response = self.get("https://searchdns.netcraft.com/?restriction=site+ends+with&host=example.com")
        if response is None:
            return {}
        cookie = response.headers.get("set-cookie", "")
        if not cookie or "=" not in cookie:
            return {}
        key, value = cookie.split(";", 1)[0].split("=", 1)
        return {
            key: value,
            "netcraft_js_verification_response": hashlib.sha1(unquote(value).encode("utf-8")).hexdigest(),
        }

    def extract_netcraft_hosts(self, text):
        links = re.findall(r'<a class="results-table__host" href="(.*?)"', text)
        return [urlparse(link).netloc for link in links]

    def next_url(self, text):
        links = re.findall(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>\s*Next Page', text, re.IGNORECASE)
        if not links:
            return None
        url = urljoin("https://searchdns.netcraft.com", unescape(links[0]))
        return url if urlparse(url).hostname == "searchdns.netcraft.com" else None
