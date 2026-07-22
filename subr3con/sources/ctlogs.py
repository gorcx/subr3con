from __future__ import annotations

import os

from .base import Source


class CertificateTransparencySource(Source):
    name = "ctlogs"
    confidence = "medium"

    def run(self):
        provider = os.environ.get("SUBR3CON_CT_PROVIDER", "auto").strip().lower()
        if provider not in {"auto", "shodan", "certspotter", "all"}:
            self.last_error = f"unknown CT provider: {provider}"
            return []

        results = []
        if provider in {"auto", "shodan", "all"}:
            results.extend(self.query_shodan())
            if provider == "auto" and results:
                return dedupe(results)

        if provider in {"auto", "certspotter", "all"}:
            results.extend(self.query_certspotter())
        return dedupe(results)

    def query_shodan(self):
        url = f"https://ctl.shodan.io/api/v1/domain/{self.context.domain}/hostnames"
        response = self.get(url, headers={"Accept": "application/json"})
        if response is None or response.status_code >= 400:
            return []
        try:
            data = response.json()
        except ValueError as exc:
            self.last_error = f"invalid Shodan CT JSON: {exc}"
            return []
        if not isinstance(data, list):
            self.last_error = "invalid Shodan CT response"
            return []
        results = [result for host in data if isinstance(host, str) and (result := self.result(host))]
        self.debug(f"Shodan CT results={len(results)}")
        return results

    def query_certspotter(self):
        headers = {"Accept": "application/json"}
        api_key = os.environ.get("CERTSPOTTER_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        max_pages = max(1, int(os.environ.get("CERTSPOTTER_MAX_PAGES", 1)))
        after = None
        results = []
        for page in range(1, max_pages + 1):
            params = {
                "domain": self.context.domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            }
            if after:
                params["after"] = after
            response = self.get("https://api.certspotter.com/v1/issuances", headers=headers, params=params)
            if response is None or response.status_code >= 400:
                break
            try:
                data = response.json()
            except ValueError as exc:
                self.last_error = f"invalid Cert Spotter JSON: {exc}"
                break
            if not isinstance(data, list) or not data:
                break
            for issuance in data:
                for host in issuance.get("dns_names", []):
                    result = self.result(host)
                    if result:
                        results.append(result)
            self.debug(f"Cert Spotter page={page} results={len(results)}")
            after = data[-1].get("id")
            if not after:
                break
        return results


def dedupe(results):
    output = []
    seen = set()
    for result in results:
        if result.host not in seen:
            seen.add(result.host)
            output.append(result)
    return output
