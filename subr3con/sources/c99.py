from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import date, timedelta

from .base import Source, cache_directory


class C99Source(Source):
    name = "c99"
    confidence = "medium"

    def run(self):
        configured_date = os.environ.get("C99_SCAN_DATE")
        if configured_date:
            scan_dates = [configured_date]
        else:
            cached_date = load_cached_scan_date(self.context.domain)
            scan_dates = unique_dates([cached_date, *self.recent_scan_dates()])
            if cached_date:
                self.debug(f"cached scan date={cached_date}")
        include_hidden = os.environ.get("C99_INCLUDE_HIDDEN", "1") != "0"

        response = None
        scan_date = None
        selected_text = ""
        request_failed = False
        for candidate_date in scan_dates:
            url = f"https://subdomainfinder.c99.nl/scans/{candidate_date}/{self.context.domain}"
            response = self.get(url)
            if response is None:
                request_failed = True
                continue
            if response.status_code == 404:
                self.debug(f"scan not found for date {candidate_date}")
                continue
            if response.status_code >= 400:
                request_failed = True
                self.debug(f"error for date {candidate_date}: {response.text[:200]}")
                continue
            raw_count = len(re.findall(r"<a[^>]+class=['\"][^'\"]*\bsd\b[^'\"]*['\"]", response.text, re.I))
            host_count = len(self.extract_hosts(response.text)) if include_hidden else raw_count
            self.debug(f"date {candidate_date} candidate raw={raw_count} hosts={host_count}")
            if raw_count or host_count:
                scan_date = candidate_date
                selected_text = response.text
                save_cached_scan_date(self.context.domain, scan_date)
                break

        if response is None or scan_date is None:
            if not request_failed:
                self.last_error = None
            self.debug("no c99 scan found")
            return []

        text = selected_text
        links = re.findall(r"<a[^>]+class=['\"][^'\"]*\bsd\b[^'\"]*['\"][^>]*>(.*?)</a>", text, re.I | re.S)
        if include_hidden:
            links.extend(self.extract_hosts(text))
        self.debug(f"scan_date={scan_date} raw_entries={len(links)} include_hidden={include_hidden}")

        results = []
        seen = set()
        for link in links:
            host = re.sub(r"<.*?>", "", link).strip().lower()
            result = self.result(host)
            if result and result.host not in seen:
                seen.add(result.host)
                results.append(result)
        return results

    def recent_scan_dates(self) -> list[str]:
        lookback_days = min(90, max(1, int(os.environ.get("C99_LOOKBACK_DAYS", 14))))
        today = date.today()
        return [(today - timedelta(days=offset)).isoformat() for offset in range(lookback_days)]


def unique_dates(values) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def c99_date_cache_path(domain: str):
    domain_hash = hashlib.sha256(domain.encode("utf-8")).hexdigest()
    return cache_directory() / "c99" / f"{domain_hash}.json"


def load_cached_scan_date(domain: str) -> str | None:
    path = c99_date_cache_path(domain)
    ttl = max(0.0, float(os.environ.get("C99_DATE_CACHE_TTL", 86400)))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("domain") != domain or time.time() - float(payload["stored_at"]) > ttl:
            return None
        return str(payload["scan_date"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_cached_scan_date(domain: str, scan_date: str) -> None:
    path = c99_date_cache_path(domain)
    payload = {"domain": domain, "scan_date": scan_date, "stored_at": time.time()}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    except OSError:
        return
