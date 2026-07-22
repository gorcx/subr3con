from __future__ import annotations

import os

from .base import Source


class DNSDumpsterSource(Source):
    name = "dnsdumpster"
    confidence = "high"

    def run(self):
        api_key = os.environ.get("DNSDUMPSTER_API_KEY")
        if not api_key:
            return self.skip("missing DNSDUMPSTER_API_KEY")

        url = f"https://api.dnsdumpster.com/domain/{self.context.domain}"
        response = self.get(url, headers={"X-API-Key": api_key, "Accept": "application/json"})
        if response is None:
            return []
        if response.status_code >= 400:
            self.debug(f"error: {response.text[:200]}")
            return []
        try:
            data = response.json()
        except ValueError as exc:
            self.last_error = f"invalid JSON: {exc}"
            self.debug(f"invalid JSON: {exc}")
            return []

        hosts = []
        collect_hosts(data, hosts)
        results = []
        for host in sorted(set(hosts)):
            result = self.result(host)
            if result:
                results.append(result)
        return results


def collect_hosts(value, hosts: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "host" and isinstance(item, str):
                hosts.append(item)
            else:
                collect_hosts(item, hosts)
    elif isinstance(value, list):
        for item in value:
            collect_hosts(item, hosts)
